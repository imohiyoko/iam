package wsfed

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// XML 署名（ADR 0110）。realm の ES256 の鍵で、ECDSA-SHA256・SHA-256・Exclusive C14N・enveloped-signature。
// goxmldsig は ECDSA の署名の値を DER で書くので、crypto.Signer を包んで XML 署名の形（r||s の固定長。RFC 4050、
// XML Signature 1.1 の 6.4.3）にする。

// rawECDSA は署名の値を r||s で返す crypto.Signer。
type rawECDSA struct{ key *ecdsa.PrivateKey }

func (s rawECDSA) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s rawECDSA) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	x, y, err := ecdsa.Sign(r, s.key, digest)
	if err != nil {
		return nil, err
	}
	n := (s.key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*n)
	x.FillBytes(out[:n])
	y.FillBytes(out[n:])
	return out, nil
}

// signingContext は el に署名する goxmldsig の設定。idAttr は署名する要素の ID の属性。
func signingContext(key *ecdsa.PrivateKey, cert []byte, idAttr string) (*dsig.SigningContext, error) {
	ctx, err := dsig.NewSigningContext(rawECDSA{key}, [][]byte{cert})
	if err != nil {
		return nil, err
	}
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.IdAttribute = idAttr
	if ctx.GetSignatureMethodIdentifier() != dsig.ECDSASHA256SignatureMethod {
		return nil, errors.New("wsfed: unexpected signature method")
	}
	return ctx, nil
}

// signAt は el に enveloped の署名を作り、子の at 番目に入れる（SAML 2.0 の Assertion とメタデータは Issuer の後か先頭、
// SAML 1.1 の Assertion は最後）。at が負なら最後に足す。
func signAt(el *etree.Element, key *ecdsa.PrivateKey, cert []byte, idAttr string, at int) error {
	ctx, err := signingContext(key, cert, idAttr)
	if err != nil {
		return err
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return err
	}
	if at < 0 || at >= len(el.ChildElements()) {
		el.AddChild(sig)
		return nil
	}
	el.InsertChildAt(el.ChildElements()[at].Index(), sig)
	return nil
}

// certLifetime は署名の証明書の有効期間（RP が証明書の期限で確かめることがある）。
const certLifetime = 10 * 365 * 24 * time.Hour

// newCertificate は署名鍵の自己署名の証明書（DER）を作る。
func newCertificate(key *ecdsa.PrivateKey, issuer, kid string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	cn := "iam ws-federation " + kid
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	if issuer != "" {
		tmpl.Subject.Organization = []string{truncate(issuer, 64)}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// signer は署名に使う鍵（realm の ES256 の使っている鍵。無ければ作る）と、その証明書（無ければ作って置く）を返す。
func (s *Service) signer(ctx context.Context, tx port.Tx, realmID string) (*ecdsa.PrivateKey, []byte, error) {
	key, sk, err := s.Keys.ECSigner(ctx, tx, realmID)
	if err != nil {
		return nil, nil, err
	}
	cs, err := tx.WSFed().ListCertificates(ctx, realmID)
	if err != nil {
		return nil, nil, err
	}
	if i := slices.IndexFunc(cs, func(c port.WSFedCertificate) bool { return c.KeyID == key.ID }); i >= 0 {
		if err := matches(cs[i].DER, &sk.PublicKey); err != nil {
			return nil, nil, err
		}
		return sk, cs[i].DER, nil
	}
	der, err := newCertificate(sk, s.Issuer, key.ID, s.Clock.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := tx.WSFed().CreateCertificate(ctx, port.WSFedCertificate{RealmID: realmID, KeyID: key.ID, DER: der, CreatedAt: s.Clock.Now()}); err != nil {
		return nil, nil, err
	}
	return sk, der, nil
}

// matches は証明書の公開鍵が pub と同じかを確かめる（置いた証明書と鍵の取り違えを防ぐ）。
func matches(der []byte, pub *ecdsa.PublicKey) error {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if p, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || !p.Equal(pub) {
		return errs.New(errs.KindInternal, "wsfed certificate does not match the signing key")
	}
	return nil
}

// certificates はメタデータに載せる証明書（公開している ES256 の鍵のもの）。使っている鍵の証明書が無ければ作り、
// JWKS から消えた鍵の証明書は消す。
func (s *Service) certificates(ctx context.Context, tx port.Tx, realmID string) (*ecdsa.PrivateKey, [][]byte, []byte, error) {
	sk, active, err := s.signer(ctx, tx, realmID)
	if err != nil {
		return nil, nil, nil, err
	}
	keys, err := s.Keys.Published(ctx, tx, realmID)
	if err != nil {
		return nil, nil, nil, err
	}
	cs, err := tx.WSFed().ListCertificates(ctx, realmID)
	if err != nil {
		return nil, nil, nil, err
	}
	var out [][]byte
	for _, c := range cs {
		if !slices.ContainsFunc(keys, func(k port.SigningKey) bool { return k.ID == c.KeyID && k.Alg == port.AlgES256 }) {
			if err := tx.WSFed().DeleteCertificate(ctx, realmID, c.KeyID); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		out = append(out, c.DER)
	}
	return sk, out, active, nil
}
