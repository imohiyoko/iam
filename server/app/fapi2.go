package app

import (
	"context"
	"net/http"
	"slices"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/port"
)

// FAPI 2.0 Security Profile（ADR 0117）と、認可応答の iss（RFC 9207）。
//
// 連携先の設定か realm の設定で有効にした連携先に、PAR（par.go の parRequired）、機密の連携先の認証と PS256・ES256・EdDSA の
// client assertion（authenticate）、送信者制約トークンと DPoP の証明のアルゴリズム（tokenBinding・pushedDPoP）、60 秒以下の
// 認可コード（authRequest）、ローテーションしないリフレッシュトークン（RefreshToken）を強いる。

// fapi2 は連携先に FAPI 2.0 Security Profile を強いるか。連携先の設定は、無効化で外れるまでフィーチャーの状態に依らず強いる
// （fail-closed）。realm の設定はフィーチャーが動いているときだけ見る。
func (s *oidcServer) fapi2(cl port.Client) bool { return cl.FAPI2 || s.a.realmFAPI2() }

// realmFAPI2 は realm の設定で全部の連携先に FAPI 2.0 Security Profile を強いるか（フィーチャー fapi2 が動いているときだけ）。
func (a *App) realmFAPI2() bool { return a.fapi2 && a.settings.FAPI2SecurityProfile }

// checkFAPI2Client は認証した連携先が FAPI 2.0 の条件を満たすかを確かめる（realm の設定で後から有効にしたときと、送信者制約の
// 無効化で設定が外れたとき）。assertion は private_key_jwt の client_assertion（無ければ空）で、alg を確かめる。
// 満たさなければ invalid_client（理由はログにだけ出す）。
func (s *oidcServer) checkFAPI2Client(ctx context.Context, cl port.Client, assertion string) error {
	if !s.fapi2(cl) {
		return nil
	}
	err := provider.CheckFAPI2(cl)
	if err == nil && assertion != "" && !provider.FAPI2Assertion(assertion) {
		err = provider.ErrClientAuth
	}
	if err == nil {
		return nil
	}
	s.a.deps.Logger.WarnContext(ctx, "oidc: client rejected by the FAPI 2.0 security profile", "client_id", cl.PublicID, "error", err)
	return op.NewStatusError(oidc.ErrInvalidClient().WithDescription("client authentication failed"), http.StatusUnauthorized)
}

// fapi2DPoPAlg は FAPI 2.0 の連携先の DPoP の証明の alg が使えるかを返す。
func fapi2DPoPAlg(alg string) bool { return slices.Contains(provider.FAPI2Algs, alg) }

// errSenderConstraintRequired は FAPI 2.0 の連携先が DPoP の証明もクライアント証明書も示さなかったときのエラー。
func errSenderConstraintRequired() *oidc.Error {
	return oidc.ErrInvalidRequest().WithDescription("a sender-constrained access token (DPoP or mTLS) is required")
}

// fapi2Discovery は realm の設定で FAPI 2.0 を強いるとき、Discovery を強いるものだけにする（ADR 0117）。
func (s *oidcServer) fapi2Discovery(d *discovery) {
	if !s.a.realmFAPI2() {
		return
	}
	methods := []oidc.AuthMethod{oidc.AuthMethodPrivateKeyJWT}
	if s.a.oauthMTLS != nil {
		methods = append(methods, port.ClientAuthTLS, port.ClientAuthSelfSignedTLS)
	}
	d.TokenEndpointAuthMethodsSupported = methods
	d.IntrospectionEndpointAuthMethodsSupported = methods
	d.RevocationEndpointAuthMethodsSupported = methods
	d.TokenEndpointAuthSigningAlgValuesSupported = provider.FAPI2Algs
	d.IntrospectionEndpointAuthSigningAlgValuesSupported = provider.FAPI2Algs
	d.RevocationEndpointAuthSigningAlgValuesSupported = provider.FAPI2Algs
	d.IDTokenSigningAlgValuesSupported = []string{port.AlgES256}
	if d.DPoPSigningAlgValuesSupported != nil {
		d.DPoPSigningAlgValuesSupported = provider.FAPI2Algs
	}
	d.RequirePushedAuthorizationRequests = true
}

// issEncoder は認可応答（成功とエラー）に iss を足す（RFC 9207）。op の転送（op.WithEncoder）と iam が作る転送の両方で使う。
type issEncoder struct {
	inner  httphelper.Encoder
	issuer string
}

func (e issEncoder) Encode(src any, dst map[string][]string) error {
	if err := e.inner.Encode(src, dst); err != nil {
		return err
	}
	dst["iss"] = []string{e.issuer}
	return nil
}

// responseEncoder は認可応答のエンコーダー。
func (s *oidcServer) responseEncoder() httphelper.Encoder {
	return issEncoder{inner: oidc.NewEncoder(), issuer: s.a.issuer}
}
