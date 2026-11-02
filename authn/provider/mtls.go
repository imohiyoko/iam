package provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// OAuth の mTLS（RFC 8705。ADR 0113）。連携先は token・introspect・revoke・device_authorization のエンドポイントで、クライアント
// 証明書で認証できる（tls_client_auth・self_signed_tls_client_auth）。証明書の受け取りは ADR 0103 のコアの経路（mTLS の専用の
// 待ち受けか、信じたプロキシのヘッダー）で、秘密鍵の所持は TLS のハンドシェイクで確かめてある。

// MTLSFeature は mTLS の連携先の認証と証明書に結び付けたトークンのフィーチャー（既定オフ）。
var MTLSFeature = feature.Feature{Name: feature.MTLSClientAuth, DataVersion: 1}

// maxTLSAuthValue は tls_client_auth の照合の値の長さの上限。
const maxTLSAuthValue = 1000

// TLSAuthFields は tls_client_auth で照合できる証明書の項目。
var TLSAuthFields = []string{port.TLSAuthSubjectDN, port.TLSAuthSANDNS, port.TLSAuthSANURI, port.TLSAuthSANIP, port.TLSAuthSANEmail}

// MTLS は tls_client_auth の証明書を確かめる設定。Roots が nil なら tls_client_auth の連携先は認証できない（fail-closed）。
type MTLS struct {
	Clock clock.Clock
	// Roots は連携先の証明書を発行する CA、Intermediates は設定の中間 CA（クライアントが送ったものにも足す）。
	Roots, Intermediates *x509.CertPool
}

// AuthenticateTLS はクライアント証明書（chain の先頭が本人）で連携先を認証する。連携先の方式が tls_client_auth なら設定の CA
// までの連鎖（clientAuth の用途、期限）と登録の項目の一致を、self_signed_tls_client_auth なら登録の JWKS の鍵と証明書の鍵の一致を
// 確かめる（自己署名の証明書の期限は見ない。RFC 8705 2.2）。無い連携先・方式の違い・証明書の誤りは区別しない（ErrClientAuth）。
func AuthenticateTLS(ctx context.Context, tx port.Tx, m *MTLS, realmID, clientID string, chain [][]byte) (port.Client, error) {
	cl, err := tx.Clients().GetByPublicID(ctx, realmID, clientID)
	if errors.Is(err, errs.NotFound) {
		return port.Client{}, ErrClientAuth
	}
	if err != nil {
		return port.Client{}, err
	}
	if len(chain) == 0 || m == nil {
		return port.Client{}, ErrClientAuth
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return port.Client{}, ErrClientAuth
	}
	switch cl.AuthMethod {
	case port.ClientAuthTLS:
		if m.Roots == nil || !m.verifyChain(leaf, chain[1:]) || !MatchTLSAuth(leaf, cl.TLSAuthField, cl.TLSAuthValue) {
			return port.Client{}, ErrClientAuth
		}
	case port.ClientAuthSelfSignedTLS:
		if !keyInJWKS(leaf.PublicKey, cl.JWKS) {
			return port.Client{}, ErrClientAuth
		}
	default:
		return port.Client{}, ErrClientAuth
	}
	return cl, nil
}

func (m *MTLS) verifyChain(leaf *x509.Certificate, rest [][]byte) bool {
	inter := x509.NewCertPool()
	if m.Intermediates != nil {
		inter = m.Intermediates.Clone()
	}
	for _, der := range rest {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: m.Roots, Intermediates: inter, CurrentTime: m.Clock.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err == nil
}

// MatchTLSAuth は証明書が登録の項目（RFC 8705 2.1.2）と一致するかを返す。subject_dn は RFC 4514 の文字列（Go の
// pkix.Name.String() の形）をそのまま比べる。SAN は1つでも一致すればよい（DNS とメールは大文字小文字を区別しない）。
func MatchTLSAuth(c *x509.Certificate, field, value string) bool {
	if value == "" {
		return false
	}
	switch field {
	case port.TLSAuthSubjectDN:
		return c.Subject.String() == value
	case port.TLSAuthSANDNS:
		return slices.ContainsFunc(c.DNSNames, func(s string) bool { return strings.EqualFold(s, value) })
	case port.TLSAuthSANURI:
		return slices.ContainsFunc(c.URIs, func(u *url.URL) bool { return u.String() == value })
	case port.TLSAuthSANIP:
		want, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		for _, ip := range c.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == want.Unmap() {
				return true
			}
		}
		return false
	case port.TLSAuthSANEmail:
		return slices.ContainsFunc(c.EmailAddresses, func(s string) bool { return strings.EqualFold(s, value) })
	}
	return false
}

// keyInJWKS は公開鍵が JWKS のどれかの鍵と同じかを返す。
func keyInJWKS(pub crypto.PublicKey, raw []byte) bool {
	set, err := jwk.Parse(raw)
	if err != nil {
		return false
	}
	eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	for i := range set.Len() {
		k, _ := set.Key(i)
		pk, err := jwk.PublicRawKeyOf(k)
		if err == nil && eq.Equal(pk) {
			return true
		}
	}
	return false
}

// validTLSAuth は登録の tls_client_auth の項目と値を確かめる。
func validTLSAuth(field, value string) bool {
	if !slices.Contains(TLSAuthFields, field) || value == "" || len(value) > maxTLSAuthValue || strings.TrimSpace(value) != value {
		return false
	}
	if field == port.TLSAuthSANIP {
		_, err := netip.ParseAddr(value)
		return err == nil
	}
	return true
}
