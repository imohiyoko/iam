package samlidp

import (
	"context"
	"crypto"
	"errors"
	"slices"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 署名の鍵と証明書（ADR 0115。0110 と同じ形）。realm の ES256 の使っている鍵で署名し、鍵ごとの自己署名の証明書を
// authn_saml_idp_certificates に置いて同じものを返す（SP が証明書・指紋で登録するため）。SP の signing_alg が RS256 なら
// realm の RS256 の鍵で RSA-SHA256 の署名をする（フィーチャー rs256。ADR 0125）。

// signer は alg（ES256 か RS256）で署名に使う鍵（無ければ作る）と、その証明書（無ければ作って置く）を返す。
func (s *Service) signer(ctx context.Context, tx port.Tx, realmID, alg string) (crypto.Signer, []byte, error) {
	if alg == "" {
		alg = port.AlgES256
	}
	key, sk, err := s.Keys.XMLSigner(ctx, tx, realmID, alg)
	if err != nil {
		return nil, nil, err
	}
	cs, err := tx.SAMLIdP().ListCertificates(ctx, realmID)
	if err != nil {
		return nil, nil, err
	}
	if i := slices.IndexFunc(cs, func(c port.SAMLIdPCertificate) bool { return c.KeyID == key.ID }); i >= 0 {
		if err := samlxml.CertificateMatches(cs[i].DER, sk.Public()); err != nil {
			return nil, nil, err
		}
		return sk, cs[i].DER, nil
	}
	der, err := samlxml.NewCertificate(sk, "iam saml idp "+key.ID, s.Issuer, s.Clock.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := tx.SAMLIdP().CreateCertificate(ctx, port.SAMLIdPCertificate{RealmID: realmID, KeyID: key.ID, DER: der, CreatedAt: s.Clock.Now()}); err != nil {
		return nil, nil, err
	}
	return sk, der, nil
}

// spSigningAlg は SP の登録の signing_alg（SP が無くなっていれば ES256）。
func (s *Service) spSigningAlg(ctx context.Context, tx port.Tx, realmID, spID string) (string, error) {
	sp, err := tx.SAMLIdP().GetServiceProvider(ctx, realmID, spID)
	if errors.Is(err, errs.NotFound) {
		return port.AlgES256, nil
	}
	if err != nil {
		return "", err
	}
	c, err := ConfigOf(sp)
	if err != nil {
		return "", err
	}
	return c.SigningAlg, nil
}

// certificates はメタデータに載せる証明書（公開している ES256 と RS256 の鍵のもの）。使っている鍵の証明書が無ければ作り、
// JWKS から消えた鍵の証明書は消す。メタデータ自体は ES256 で署名する。
func (s *Service) certificates(ctx context.Context, tx port.Tx, realmID string) (crypto.Signer, [][]byte, []byte, error) {
	sk, active, err := s.signer(ctx, tx, realmID, port.AlgES256)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.Keys.RS256 {
		// RS256 の SP がメタデータから証明書を取れるように、使っている RS256 の鍵の証明書も用意する。
		if _, _, err := s.signer(ctx, tx, realmID, port.AlgRS256); err != nil {
			return nil, nil, nil, err
		}
	}
	keys, err := s.Keys.Published(ctx, tx, realmID)
	if err != nil {
		return nil, nil, nil, err
	}
	cs, err := tx.SAMLIdP().ListCertificates(ctx, realmID)
	if err != nil {
		return nil, nil, nil, err
	}
	var out [][]byte
	for _, c := range cs {
		if !slices.ContainsFunc(keys, func(k port.SigningKey) bool {
			return k.ID == c.KeyID && (k.Alg == port.AlgES256 || k.Alg == port.AlgRS256)
		}) {
			if err := tx.SAMLIdP().DeleteCertificate(ctx, realmID, c.KeyID); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		out = append(out, c.DER)
	}
	return sk, out, active, nil
}
