package samlxml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/imohiyoko/iam/shared/errs"
)

// XML 署名（ADR 0110、0115）。realm の ES256 の鍵で、ECDSA-SHA256・SHA-256・Exclusive C14N・enveloped-signature。
// goxmldsig は ECDSA の署名の値を DER で書くので、crypto.Signer を包んで XML 署名の形（r||s の固定長。RFC 4050、
// XML Signature 1.1 の 6.4.3）にする。

// RawECDSA は署名の値を r||s で返す crypto.Signer。
type RawECDSA struct{ Key *ecdsa.PrivateKey }

// Public は公開鍵。
func (s RawECDSA) Public() crypto.PublicKey { return &s.Key.PublicKey }

// Sign は digest に署名し、r||s（曲線の大きさの固定長）で返す。
func (s RawECDSA) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	x, y, err := ecdsa.Sign(r, s.Key, digest)
	if err != nil {
		return nil, err
	}
	n := (s.Key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*n)
	x.FillBytes(out[:n])
	y.FillBytes(out[n:])
	return out, nil
}

// signingContext は goxmldsig の設定。idAttr は署名する要素の ID の属性。
func signingContext(key *ecdsa.PrivateKey, cert []byte, idAttr string) (*dsig.SigningContext, error) {
	ctx, err := dsig.NewSigningContext(RawECDSA{key}, [][]byte{cert})
	if err != nil {
		return nil, err
	}
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.IdAttribute = idAttr
	if ctx.GetSignatureMethodIdentifier() != dsig.ECDSASHA256SignatureMethod {
		return nil, errors.New("samlxml: unexpected signature method")
	}
	return ctx, nil
}

// SignAt は el に enveloped の署名を作り、子の at 番目に入れる（SAML 2.0 の Assertion・Response・メタデータは Issuer の後か先頭、
// SAML 1.1 の Assertion は最後）。at が負なら最後に足す。
func SignAt(el *etree.Element, key *ecdsa.PrivateKey, cert []byte, idAttr string, at int) error {
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

// CertLifetime は署名の証明書の有効期間（連携先が証明書の期限で確かめることがある）。
const CertLifetime = 10 * 365 * 24 * time.Hour

// NewCertificate は署名鍵の自己署名の証明書（DER）を作る。cn と org は 64 バイトまでに切る。
func NewCertificate(key *ecdsa.PrivateKey, cn, org string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: truncate(cn, 64)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(CertLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	if org != "" {
		tmpl.Subject.Organization = []string{truncate(org, 64)}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// CertificateMatches は証明書の公開鍵が pub と同じかを確かめる（置いた証明書と鍵の取り違えを防ぐ）。
func CertificateMatches(der []byte, pub *ecdsa.PublicKey) error {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if p, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || !p.Equal(pub) {
		return errs.New(errs.KindInternal, "the certificate does not match the signing key")
	}
	return nil
}
