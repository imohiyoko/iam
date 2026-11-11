package wsfed

import (
	"context"
	"crypto"
	"slices"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/port"
)

// XML 署名（ADR 0110）。realm の ES256 の鍵で、ECDSA-SHA256・SHA-256・Exclusive C14N・enveloped-signature（authn/samlxml）。
// RP の signing_alg が RS256 なら realm の RS256 の鍵で RSA-SHA256 の署名をする（フィーチャー rs256。ADR 0125）。

// signAt は el に enveloped の署名を作り、子の at 番目に入れる（samlxml.SignAt）。
func signAt(el *etree.Element, key crypto.Signer, cert []byte, idAttr string, at int) error {
	return samlxml.SignAt(el, key, cert, idAttr, at)
}

// newCertificate は署名鍵の自己署名の証明書（DER）を作る。
func newCertificate(key crypto.Signer, issuer, kid string, now time.Time) ([]byte, error) {
	return samlxml.NewCertificate(key, "iam ws-federation "+kid, issuer, now)
}

// signer は alg（ES256 か RS256）で署名に使う鍵（realm の使っている鍵。無ければ作る）と、その証明書（無ければ作って置く）を返す。
func (s *Service) signer(ctx context.Context, tx port.Tx, realmID, alg string) (crypto.Signer, []byte, error) {
	if alg == "" {
		alg = port.AlgES256
	}
	key, sk, err := s.Keys.XMLSigner(ctx, tx, realmID, alg)
	if err != nil {
		return nil, nil, err
	}
	cs, err := tx.WSFed().ListCertificates(ctx, realmID)
	if err != nil {
		return nil, nil, err
	}
	if i := slices.IndexFunc(cs, func(c port.WSFedCertificate) bool { return c.KeyID == key.ID }); i >= 0 {
		if err := matches(cs[i].DER, sk.Public()); err != nil {
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
func matches(der []byte, pub crypto.PublicKey) error { return samlxml.CertificateMatches(der, pub) }

// certificates はメタデータに載せる証明書（公開している ES256 と RS256 の鍵のもの）。使っている鍵の証明書が無ければ作り、
// JWKS から消えた鍵の証明書は消す。メタデータ自体は ES256 で署名する。
func (s *Service) certificates(ctx context.Context, tx port.Tx, realmID string) (crypto.Signer, [][]byte, []byte, error) {
	sk, active, err := s.signer(ctx, tx, realmID, port.AlgES256)
	if err != nil {
		return nil, nil, nil, err
	}
	// RS256 の RP がメタデータから証明書を取れるように、使っている RS256 の鍵があればその証明書も用意する。鍵はここでは作らない
	// （起動のときに Ensure が作る。フィーチャー rs256 を止める片付けが鍵を退役させた後に、止める前から動いているインスタンスが
	// メタデータの取得で鍵を作り直さないように）。止めた後でも片付けの前なら、まだ RS256 で署名するので証明書を載せる。
	if ok, err := s.Keys.HasActive(ctx, tx, realmID, port.AlgRS256); err != nil {
		return nil, nil, nil, err
	} else if ok {
		if _, _, err := s.signer(ctx, tx, realmID, port.AlgRS256); err != nil {
			return nil, nil, nil, err
		}
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
		if !slices.ContainsFunc(keys, func(k port.SigningKey) bool {
			return k.ID == c.KeyID && (k.Alg == port.AlgES256 || k.Alg == port.AlgRS256)
		}) {
			if err := tx.WSFed().DeleteCertificate(ctx, realmID, c.KeyID); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		out = append(out, c.DER)
	}
	return sk, out, active, nil
}
