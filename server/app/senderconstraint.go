package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 送信者制約トークン（ADR 0113）。
//
//   - DPoP（RFC 9449。フィーチャー dpop）：token エンドポイントで DPoP の証明を確かめ、鍵（jkt）をアクセストークンに結び付ける。
//     公開クライアントではリフレッシュトークンも。iam の資源（UserInfo、管理 API のサービスアカウントのトークン）は、結び付けた
//     トークンに `Authorization: DPoP` と同じ鍵・ath の証明を求める
//   - OAuth の mTLS（RFC 8705。フィーチャー mtls_client_auth）：tls_client_auth・self_signed_tls_client_auth の連携先の認証と、
//     tls_client_certificate_bound_access_tokens の連携先のトークンを証明書（x5t#S256）に結び付ける。証明書は ADR 0103 の経路で受ける
//
// フィーチャーが止まっていると、結び付けたトークンは確かめられないので通さない（fail-closed）。

// setupSenderConstraint は DPoP の確かめと mTLS の CA を用意する（フィーチャーが動いていなければ nil）。
func (a *App) setupSenderConstraint() error {
	cfg, plan := a.cfg, a.plan
	a.dpop, a.oauthMTLS = nil, nil
	if plan.IsActive(feature.DPoP) {
		d := cfg.OIDC.DPoP
		a.dpop = &dpop.Verifier{Clock: a.deps.Clock, Store: a.deps.Ephemeral, RequireNonce: d.RequireNonce, MaxAge: d.ProofMaxAge.D(),
			NonceTTL: d.NonceTTL.D()}
	}
	if plan.IsActive(feature.MTLSClientAuth) {
		m, err := loadOAuthMTLS(cfg.OIDC.MTLS, a.deps.Clock)
		if err != nil {
			return fmt.Errorf("app: oidc.mtls: %w", err)
		}
		a.oauthMTLS = m
	}
	return nil
}

func loadOAuthMTLS(c config.OAuthMTLS, clk clock.Clock) (*provider.MTLS, error) {
	m := &provider.MTLS{Clock: clk}
	var err error
	if len(c.TrustAnchors) > 0 {
		if m.Roots, err = loadPool(c.TrustAnchors); err != nil {
			return nil, err
		}
	}
	if len(c.Intermediates) > 0 {
		if m.Intermediates, err = loadPool(c.Intermediates); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// loadPool は PEM のファイルの証明書を集める。CERTIFICATE 以外のブロックや、証明書の無いファイルは誤り。
func loadPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- 運営者が設定したファイル
		if err != nil {
			return nil, err
		}
		n := 0
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("%s: unexpected PEM block %q", f, blk.Type)
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			pool.AddCert(c)
			n++
		}
		if n == 0 {
			return nil, fmt.Errorf("%s: no certificates", f)
		}
	}
	return pool, nil
}

// ---------------------------------------------------------------------------
// token エンドポイント

// errInvalidDPoPProof・errUseDPoPNonce は token エンドポイントの DPoP のエラー（RFC 9449 5、8）。
func errInvalidDPoPProof() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_dpop_proof", Description: "the DPoP proof is missing or invalid"}
}

func errUseDPoPNonce() *oidc.Error {
	return &oidc.Error{ErrorType: "use_dpop_nonce", Description: "the authorization server requires a DPoP nonce"}
}

// endpointURLs は path の、連携先から見た URL（DPoP の htu で受けるもの）。mTLS の別名（RFC 8705 5）があればそれも。
func (s *oidcServer) endpointURLs(path string) []string {
	out := []string{s.endpoint(path)}
	if alias := s.mtlsAlias(path); alias != "" {
		out = append(out, alias)
	}
	return out
}

// mtlsAlias は mTLS の専用の待ち受けの path の URL（oidc.mtls.endpoint_url。フィーチャー mtls_client_auth）。ホスト名で決める
// realm（専用の待ち受けではホスト名で引けない）と、設定が無いときは空。
func (s *oidcServer) mtlsAlias(path string) string {
	base := s.a.cfg.OIDC.MTLS.EndpointURL
	if s.a.oauthMTLS == nil || base == "" || len(s.a.realm.Hosts) > 0 {
		return ""
	}
	u, err := url.Parse(s.a.issuer)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(base, "/") + strings.TrimSuffix(u.Path, "/") + path
}

// tokenBinding は token エンドポイントの要求の、トークンに結び付けるもの。
//   - DPoP の証明があれば確かめて鍵を結び付ける（フィーチャー dpop が止まっていれば証明を見ない。RFC 9449 では Bearer を返してよい）。
//     dpop_bound_access_tokens の連携先は証明が要る
//   - tls_client_certificate_bound_access_tokens の連携先は、クライアント証明書が要り、それを結び付ける
func (s *oidcServer) tokenBinding(ctx context.Context, method, path string, h http.Header, cl port.Client) (provider.Binding, error) {
	var b provider.Binding
	proofs := h.Values(dpop.Header)
	switch {
	case s.a.dpop != nil && len(proofs) > 0:
		p, err := s.a.dpop.Verify(ctx, proofs, dpop.Expect{Method: method, URLs: s.endpointURLs(path)})
		switch {
		case errors.Is(err, dpop.ErrUseNonce):
			return b, errUseDPoPNonce()
		case errors.Is(err, dpop.ErrInvalidProof):
			return b, errInvalidDPoPProof()
		case err != nil:
			return b, s.fail(ctx, err)
		}
		if s.fapi2(cl) && !fapi2DPoPAlg(p.Alg) {
			// FAPI 2.0 の連携先の証明は PS256・ES256・EdDSA だけ（ADR 0117）。
			return b, errInvalidDPoPProof()
		}
		b.JKT = p.JKT
	case cl.DPoPBoundAccessTokens:
		// フィーチャーが止まっていても、DPoP を求める連携先に Bearer は出さない。
		return b, errInvalidDPoPProof()
	}
	if cl.TLSBoundAccessTokens {
		chain := credential.ClientCertificates(ctx)
		if s.a.oauthMTLS == nil || len(chain) == 0 {
			return b, oidc.ErrInvalidRequest().WithDescription("a client certificate is required")
		}
		b.X5T = provider.CertThumbprint(chain[0])
	}
	if s.fapi2(cl) && b.JKT == "" && b.X5T == "" {
		// FAPI 2.0 の連携先には送信者制約の無いトークンを出さない（ADR 0117）。
		return b, errSenderConstraintRequired()
	}
	return b, nil
}

// tokenType は token エンドポイントの応答の token_type（DPoP に結び付けたら DPoP。RFC 9449 5）。
func tokenType(b provider.Binding) string {
	if b.JKT != "" {
		return dpop.TokenType
	}
	return oidc.BearerToken
}

// withDPoPNonce は、nonce を求める設定のとき、DPoP の証明を付けた要求の応答に今の nonce を付ける（RFC 9449 8、9）。
// エラーの応答（use_dpop_nonce）にも付くよう、処理の前に置く。nonce を用意できなければ付けない（証明の確かめが 503 にする）。
func (a *App) withDPoPNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.dpop != nil && a.dpop.RequireNonce && len(r.Header.Values(dpop.Header)) > 0 {
			if n, err := a.dpop.Nonce(r.Context()); err != nil {
				a.deps.Logger.WarnContext(r.Context(), "dpop: nonce unavailable", "error", err)
			} else {
				w.Header().Set(dpop.NonceHeader, n)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// adminURLs は管理 API の path の、外から見た URL（oidc.dpop.admin_url と realm のパスの接頭辞。DPoP の htu）。設定が無い・
// フィーチャー dpop が止まっていれば nil（管理 API では DPoP を受けない）。
func (a *App) adminURLs(path string) []string {
	base := a.cfg.OIDC.DPoP.AdminURL
	if a.dpop == nil || base == "" {
		return nil
	}
	prefix := ""
	if u, err := url.Parse(a.issuer); err == nil {
		prefix = strings.TrimSuffix(u.Path, "/")
	}
	return []string{strings.TrimSuffix(base, "/") + prefix + path}
}

// serviceAccountJKT は管理 API の client credentials の要求の DPoP の証明を確かめ、トークンに結び付ける鍵を返す（ADR 0113）。
// 管理 API で DPoP を受けない構成（adminURLs が nil）なら証明を見ない（Bearer を出す）。
func (a *App) serviceAccountJKT(ctx context.Context, proof *string) (string, error) {
	urls := a.adminURLs(adminTokenPath)
	if proof == nil || urls == nil {
		return "", nil
	}
	p, err := a.dpop.Verify(ctx, []string{*proof}, dpop.Expect{Method: http.MethodPost, URLs: urls})
	if err != nil {
		return "", err
	}
	return p.JKT, nil
}

// adminTokenPath は管理 API の client credentials のパス。
const adminTokenPath = "/v1/admin/token" // #nosec G101 -- パス

// ---------------------------------------------------------------------------
// 資源（UserInfo、管理 API）

// authorization は Authorization ヘッダーの方式（Bearer か DPoP。大文字小文字を区別しない）とトークン。ほかの方式は空。
func authorization(h string) (scheme, token string) {
	s, t, ok := strings.Cut(h, " ")
	if !ok {
		return "", ""
	}
	t = strings.TrimSpace(t)
	switch {
	case strings.EqualFold(s, "Bearer"):
		return "Bearer", t
	case strings.EqualFold(s, dpop.Scheme):
		return dpop.Scheme, t
	}
	return "", ""
}

// errBinding は資源での提示の失敗。Code は WWW-Authenticate の error（invalid_token・invalid_dpop_proof・use_dpop_nonce）。
type errBinding struct{ Code string }

func (e *errBinding) Error() string { return "sender constraint: " + e.Code }

// checkResourceBinding は、資源に提示したトークンが結び付け（bound）を満たすかを確かめる。
//   - DPoP に結び付けたトークンは `DPoP` の方式と、同じ鍵・ath・htm・htu の証明が要る（Bearer では通さない。RFC 9449 7.1）
//   - 結び付けの無いトークンを `DPoP` の方式で示すのは誤り
//   - 証明書に結び付けたトークンは、同じクライアント証明書の要求でだけ通す（RFC 8705 3）
//
// フィーチャーが止まっていれば、結び付けたトークンは通さない。
func (a *App) checkResourceBinding(ctx context.Context, r *http.Request, scheme, token string, bound provider.Binding, urls []string) error {
	if bound.JKT == "" && scheme == dpop.Scheme {
		return &errBinding{Code: "invalid_token"}
	}
	if bound.JKT != "" {
		if a.dpop == nil || scheme != dpop.Scheme {
			return &errBinding{Code: "invalid_token"}
		}
		_, err := a.dpop.Verify(ctx, r.Header.Values(dpop.Header), dpop.Expect{Method: r.Method, URLs: urls, AccessToken: token, JKT: bound.JKT})
		switch {
		case errors.Is(err, dpop.ErrUseNonce):
			return &errBinding{Code: "use_dpop_nonce"}
		case errors.Is(err, dpop.ErrInvalidProof):
			return &errBinding{Code: "invalid_dpop_proof"}
		case err != nil:
			return err
		}
	}
	if bound.X5T != "" {
		chain := credential.ClientCertificates(ctx)
		if a.oauthMTLS == nil || len(chain) == 0 || !(provider.Binding{X5T: bound.X5T}).Satisfies(provider.Binding{X5T: provider.CertThumbprint(chain[0])}) {
			return &errBinding{Code: "invalid_token"}
		}
	}
	return nil
}

// challenge は資源の 401 の WWW-Authenticate。DPoP が動いていれば DPoP の方式と受ける alg も示す（RFC 9449 7.1）。
// metadata は資源のメタデータの URL（RFC 9728 5.1。UserInfo だけ。空なら付けない）。
func (a *App) challenge(w http.ResponseWriter, code, metadata string) {
	extra := ""
	if metadata != "" {
		extra = fmt.Sprintf(`, resource_metadata=%q`, metadata)
	}
	if a.dpop != nil {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf(`DPoP error=%q, algs=%q`, code, strings.Join(dpop.Algs, " "))+extra)
	}
	if code == "invalid_token" {
		w.Header().Add("WWW-Authenticate", `Bearer error="invalid_token"`+extra)
	}
}

// senderConstraintDiscovery は Discovery に DPoP と mTLS の項目を足す（フィーチャーが止まっていれば出さない）。
func (s *oidcServer) senderConstraintDiscovery(d *discovery) {
	if s.a.dpop != nil {
		d.DPoPSigningAlgValuesSupported = dpop.Algs
	}
	if s.a.oauthMTLS == nil {
		return
	}
	tls := []oidc.AuthMethod{port.ClientAuthTLS, port.ClientAuthSelfSignedTLS}
	d.TokenEndpointAuthMethodsSupported = append(slices.Clone(d.TokenEndpointAuthMethodsSupported), tls...)
	d.IntrospectionEndpointAuthMethodsSupported = append(slices.Clone(d.IntrospectionEndpointAuthMethodsSupported), tls...)
	d.RevocationEndpointAuthMethodsSupported = append(slices.Clone(d.RevocationEndpointAuthMethodsSupported), tls...)
	d.TLSClientCertificateBoundAccessTokens = true
	if s.mtlsAlias(oidcToken) == "" {
		return
	}
	d.MTLSEndpointAliases = map[string]string{"token_endpoint": s.mtlsAlias(oidcToken), "introspection_endpoint": s.mtlsAlias(oidcIntrospect),
		"revocation_endpoint": s.mtlsAlias(oidcRevoke), "userinfo_endpoint": s.mtlsAlias(oidcUserinfo)}
	if s.a.device != nil {
		d.MTLSEndpointAliases["device_authorization_endpoint"] = s.mtlsAlias(oidcDeviceAuth)
	}
	if s.a.ciba != nil {
		d.MTLSEndpointAliases["backchannel_authentication_endpoint"] = s.mtlsAlias(oidcBackchannel)
	}
	if s.a.par {
		d.MTLSEndpointAliases["pushed_authorization_request_endpoint"] = s.mtlsAlias(oidcPAR)
	}
}

// ---------------------------------------------------------------------------
// フィーチャーの無効化（11.12）

// dpopCleaner は連携先の dpop_bound_access_tokens を外し、DPoP に結び付けたトークン（OIDC のアクセストークン・リフレッシュトークン、
// サービスアカウントのアクセストークン）を消す。消したトークンを持つ連携先は、ログインかリフレッシュし直す。
var dpopCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.DPoPBoundAccessTokens, nil })
		if err != nil {
			return 0, err
		}
		t, err := tx.OIDCTokens().CountBound(ctx, port.BindingDPoP)
		if err != nil {
			return 0, err
		}
		sa, err := tx.ServiceAccounts().CountBoundTokens(ctx)
		return n + t + sa, err
	},
	Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !c.DPoPBoundAccessTokens {
				return false, nil
			}
			c.DPoPBoundAccessTokens, c.UpdatedAt = false, now
			return true, tx.Clients().Update(ctx, c)
		})
		if err != nil || n >= limit {
			return n, err
		}
		t, err := tx.OIDCTokens().PurgeBound(ctx, port.BindingDPoP, limit-n)
		n += t
		if err != nil || n >= limit {
			return n, err
		}
		sa, err := tx.ServiceAccounts().PurgeBoundTokens(ctx, limit-n)
		return n + sa, err
	},
}

// mtlsCleaner は連携先の tls_client_certificate_bound_access_tokens と tls_client_auth の照合の項目を外し、証明書に結び付けた
// トークンを消す。tls_client_auth の連携先は照合の項目が無くなるので、認証方式を変えるまで認証できない（fail-closed）。
// self_signed_tls_client_auth の連携先の JWKS は private_key_jwt と同じ連携先の鍵なので残す（フィーチャーが止まれば認証できない）。
var mtlsCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return hasMTLSSettings(c), nil })
		if err != nil {
			return 0, err
		}
		t, err := tx.OIDCTokens().CountBound(ctx, port.BindingMTLS)
		return n + t, err
	},
	Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !hasMTLSSettings(c) {
				return false, nil
			}
			c.TLSBoundAccessTokens, c.TLSAuthField, c.TLSAuthValue, c.UpdatedAt = false, "", "", now
			return true, tx.Clients().Update(ctx, c)
		})
		if err != nil || n >= limit {
			return n, err
		}
		t, err := tx.OIDCTokens().PurgeBound(ctx, port.BindingMTLS, limit-n)
		return n + t, err
	},
}

func hasMTLSSettings(c port.Client) bool {
	return c.TLSBoundAccessTokens || c.TLSAuthField != "" || c.TLSAuthValue != ""
}
