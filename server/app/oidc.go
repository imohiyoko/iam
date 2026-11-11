package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// OIDC Provider（design.md 5.1、5.5、9.3、ADR 0066）。要求の解析と検証は zitadel/oidc の op.Server に任せ、状態（認可要求・
// 認可コード・認可・トークン）と ID トークンの署名は authn/provider で行う。
//
//	GET  /.well-known/openid-configuration  Discovery
//	GET  /oauth2/keys                       JWKS（ML-DSA-65 と ES256）
//	GET  /oauth2/authorize                  認可要求。ログインしていなければログイン画面へ
//	GET  /oauth2/authorize/resume           ログイン画面から戻って認可コードを発行する
//	POST /oauth2/token                      認可コードの交換、リフレッシュ、Token Exchange（RFC 8693。フィーチャー token_exchange）
//	POST /oauth2/introspect                 イントロスペクション（RFC 7662。機密の連携先だけ）
//	POST /oauth2/revoke                     失効（RFC 7009）
//	GET  /oauth2/userinfo                   UserInfo（POST も可）
//	POST /oauth2/device_authorization       Device Authorization Grant の開始（RFC 8628。フィーチャー device_flow）
//	GET  /oauth2/device                     user_code の入力と承認の画面（POST で承認・拒否）
//	GET  /oauth2/end_session                RP-Initiated Logout（POST も可。フィーチャー oidc_logout。endsession.go）
//	POST /oauth2/bc-authorize               CIBA の開始（フィーチャー ciba。ciba.go）
//	POST /oauth2/par                        Pushed Authorization Requests（RFC 9126。フィーチャー par。par.go）
//	GET  /.well-known/oauth-authorization-server  OAuth 2.0 Authorization Server Metadata（RFC 8414。Discovery と同じ内容）
//	GET  /.well-known/oauth-protected-resource    Protected Resource Metadata（RFC 9728。IAM 自身の API）

const (
	oidcAuthorize  = "/oauth2/authorize"
	oidcResume     = "/oauth2/authorize/resume"
	oidcToken      = "/oauth2/token" // #nosec G101 -- パス
	oidcUserinfo   = "/oauth2/userinfo"
	oidcKeys       = "/oauth2/keys"
	oidcIntrospect = "/oauth2/introspect"
	oidcRevoke     = "/oauth2/revoke"
	oidcDeviceAuth = "/oauth2/device_authorization"
	oidcDevice     = "/oauth2/device"
	oidcPAR        = "/oauth2/par"
	// wellKnownAS と wellKnownResource は RFC 8414・9728 の既知の場所（ADR 0112）。
	wellKnownAS       = "/.well-known/oauth-authorization-server"
	wellKnownResource = "/.well-known/oauth-protected-resource"
)

// isOIDC は OIDC Provider のパスかを返す。
func isOIDC(path string) bool {
	return path == oidc.DiscoveryEndpoint || path == wellKnownAS || path == wellKnownResource || strings.HasPrefix(path, "/oauth2/") ||
		path == wellKnownCredentialIssuer || path == wellKnownJWTVCIssuer
}

// newOIDCHandler は OIDC Provider のハンドラを返す。issuer（server.public_url）が無ければ nil。
func newOIDCHandler(a *App) http.Handler {
	if a.issuer == "" {
		return nil
	}
	srv := &oidcServer{a: a}
	endpoints := op.Endpoints{
		Authorization: op.NewEndpoint(oidcAuthorize),
		Token:         op.NewEndpoint(oidcToken),
		JwksURI:       op.NewEndpoint(oidcKeys),
		Introspection: op.NewEndpoint(oidcIntrospect),
		Revocation:    op.NewEndpoint(oidcRevoke),
	}
	if a.device != nil {
		endpoints.DeviceAuthorization = op.NewEndpoint(oidcDeviceAuth)
	}
	// 認可応答には iss を付ける（RFC 9207。fapi2.go）。
	ops := op.RegisterServer(srv, endpoints, op.WithServerCORSOptions(nil), op.WithEncoder(srv.responseEncoder()))
	mux := http.NewServeMux()
	mux.Handle(oidc.DiscoveryEndpoint, ops)
	mux.Handle(oidcKeys, ops)
	// DPoP の nonce（ADR 0113）は token エンドポイントと UserInfo の応答に付ける。
	token := http.Handler(ops)
	if a.ciba != nil {
		// CIBA の grant は op.Server の前で受ける（ADR 0114）。
		token = srv.withCIBAToken(token)
		mux.HandleFunc(oidcBackchannel, srv.backchannelAuthorize)
	}
	if a.vci != nil {
		// OpenID4VCI の Pre-Authorized Code の grant も op.Server の前で受ける（ADR 0119）。
		token = srv.withPreAuthorizedToken(token)
		srv.registerVCI(mux)
	}
	mux.Handle(oidcToken, a.withDPoPNonce(token))
	mux.Handle(oidcIntrospect, ops)
	mux.Handle(oidcRevoke, ops)
	// 認可要求とその続きはブラウザのセッションを見る。
	authorize := http.Handler(ops)
	if a.formPost {
		authorize = srv.withFormPostErrors(authorize)
	}
	mux.Handle(oidcAuthorize, a.withSession(authorize))
	mux.Handle(oidcResume, a.withSession(http.HandlerFunc(srv.resume)))
	if a.formPost {
		mux.Handle(oidcFormPost, a.withSession(http.HandlerFunc(srv.formPost)))
	}
	mux.Handle(oidcUserinfo, a.withDPoPNonce(http.HandlerFunc(srv.userinfo)))
	mux.HandleFunc(wellKnownAS, srv.authorizationServerMetadata)
	mux.HandleFunc(wellKnownResource, srv.protectedResourceMetadata)
	if a.par {
		mux.Handle(oidcPAR, a.withDPoPNonce(http.HandlerFunc(srv.pushAuthorization)))
	}
	if a.device != nil {
		mux.Handle(oidcDeviceAuth, ops)
		// 承認の画面はブラウザのセッションを見る。書き込み（POST）は別オリジンから受けない（CSRF。Cookie も SameSite=Lax）。
		mux.Handle(oidcDevice, a.withSession(http.NewCrossOriginProtection().Handler(http.HandlerFunc(srv.deviceVerify))))
	}
	if a.logoutTmpl != nil {
		// ログアウトの要求はトップレベルの遷移（別のオリジンの連携先から）。確認の答えは自分の画面のフォームからだけ受ける。
		mux.Handle(oidcEndSession, a.withSession(http.HandlerFunc(srv.endSession)))
		mux.Handle(oidcEndSessionConfirm, http.NewCrossOriginProtection().Handler(a.withSession(http.HandlerFunc(srv.confirmEndSession))))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if srv.cors(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// cors はブラウザの連携先（SPA）から呼ぶエンドポイントの CORS（ADR 0066）。Discovery と JWKS は公開の情報なのでどのオリジンにも
// 許す。token・userinfo・revoke は公開クライアント（none）の戻り先のオリジンだけに許す（機密の連携先はサーバーから呼ぶ）。
// Cookie は送らせない（Allow-Credentials を付けない）。authorize はトップレベルの遷移、introspect はリソースサーバーから呼ぶので
// CORS を付けない。プリフライトに答えたら true。
func (s *oidcServer) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	public := r.URL.Path == oidc.DiscoveryEndpoint || r.URL.Path == oidcKeys || r.URL.Path == wellKnownAS || r.URL.Path == wellKnownResource ||
		(s.a.vci != nil && isVCIPath(r.URL.Path))
	browser := r.URL.Path == oidcToken || r.URL.Path == oidcUserinfo || r.URL.Path == oidcRevoke || r.URL.Path == oidcPAR
	if origin == "" || !public && !browser {
		return false
	}
	h := w.Header()
	h.Add("Vary", "Origin")
	preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
	switch {
	case public:
		h.Set("Access-Control-Allow-Origin", "*")
	case s.browserOrigin(r.Context(), origin):
		h.Set("Access-Control-Allow-Origin", origin)
	default:
		if preflight {
			w.WriteHeader(http.StatusNoContent)
		}
		return preflight
	}
	if !preflight {
		h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, DPoP-Nonce")
		return false
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP")
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
	return true
}

// browserOrigin は origin が公開クライアントの戻り先のオリジンかを返す。
func (s *oidcServer) browserOrigin(ctx context.Context, origin string) bool {
	var ok bool
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Clients().List(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.AuthMethod != port.ClientAuthNone {
				continue
			}
			for _, uri := range c.RedirectURIs {
				if u, err := url.Parse(uri); err == nil && u.Scheme+"://"+u.Host == origin {
					ok = true
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		s.a.deps.Logger.WarnContext(ctx, "oidc: cors origin lookup failed", "error", err)
	}
	return ok
}

type oidcServer struct {
	op.UnimplementedServer
	a *App
}

func (s *oidcServer) endpoint(path string) string { return s.a.issuer + path }

// fail はエラーを OIDC のエラーにする。内部の説明は返さず、ログにだけ出す。
func (s *oidcServer) fail(ctx context.Context, err error) error {
	if _, ok := errors.AsType[*oidc.Error](err); ok {
		return err
	}
	if _, ok := errors.AsType[op.StatusError](err); ok {
		return err
	}
	s.a.deps.Logger.ErrorContext(ctx, "oidc request failed", "error", err)
	if errs.KindOf(err) == errs.KindUnavailable {
		return op.NewStatusError(oidc.ErrServerError().WithDescription("temporarily unavailable"), http.StatusServiceUnavailable)
	}
	return oidc.ErrServerError()
}

var (
	grantTypes              = []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	confidentialAuthMethods = []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT}
	authMethods             = append(slices.Clone(confidentialAuthMethods), oidc.AuthMethodNone)
	assertionAlgs           = []string{"ES256", "ES384", "EdDSA", "PS256", "RS256"}
)

// grantTypes は対応する grant_type。Token Exchange（ADR 0099）が動いていればそれも。
func (s *oidcServer) grantTypes() []oidc.GrantType {
	if s.a.tokens.TokenExchange {
		return exchangeGrantTypes()
	}
	return grantTypes
}

// scopes は対応するスコープ。カスタム属性が動いていれば attributes も、offline_access が動いていればそれも。
func (s *oidcServer) scopes() []string {
	out := provider.Scopes
	if s.a.attributes != nil {
		out = append(slices.Clone(out), provider.ScopeAttributes)
	}
	if s.a.tokens.Offline {
		out = append(slices.Clone(out), provider.ScopeOfflineAccess) // ADR 0126
	}
	if s.a.attributes != nil && s.a.attributes.StandardClaims {
		out = append(slices.Clone(out), attribute.ClaimScopes...) // ADR 0127
	}
	return out
}

// responseModes は Discovery の response_modes_supported。フィーチャー form_post なら form_post も（ADR 0124）。
func (s *oidcServer) responseModes() []string {
	if s.a.formPost {
		return []string{string(oidc.ResponseModeQuery), string(responseModeFormPost)}
	}
	return []string{string(oidc.ResponseModeQuery)}
}

func (s *oidcServer) claims() []string {
	out := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "azp", "org_id", "email", "email_verified"}
	if s.a.attributes != nil {
		out = append(out, "attributes")
		if s.a.attributes.StandardClaims {
			out = append(out, attribute.SupportedClaims()...)
		}
	}
	if s.a.acrActive() {
		out = append(out, "acr")
	}
	return out
}

// acrValues は Discovery の acr_values_supported。フィーチャー acr が動いていなければ載せない。
func (s *oidcServer) acrValues() []string {
	if !s.a.acrActive() {
		return nil
	}
	return acr.Supported(s.a.hardwareAAL())
}

// hardwareAAL は、AAL3 を宣言する認証方式（鍵がハードウェアにあると確かめるもの。ADR 0103）が動いているか。
func (a *App) hardwareAAL() bool { return a.methods.MaxAAL() >= 3 }

// acrActive はフィーチャー acr（ADR 0093）が動いているか。
func (a *App) acrActive() bool { return a.plan.IsActive(feature.ACR) }

// discovery は Discovery の応答。zitadel/oidc の型に無い Front-Channel Logout、CIBA と PAR（RFC 9126 5）の項目を足す。
// OAuth 2.0 Authorization Server Metadata（RFC 8414）も同じ内容を返す。
type discovery struct {
	*oidc.DiscoveryConfiguration
	FrontChannelLogoutSupported        bool `json:"frontchannel_logout_supported,omitempty"`
	FrontChannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`
	// DPoP（RFC 9449 5.1）と OAuth の mTLS（RFC 8705 3.3、5）。ADR 0113。
	DPoPSigningAlgValuesSupported         []string          `json:"dpop_signing_alg_values_supported,omitempty"`
	TLSClientCertificateBoundAccessTokens bool              `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	MTLSEndpointAliases                   map[string]string `json:"mtls_endpoint_aliases,omitempty"`
	// CIBA（CIBA Core 4。フィーチャー ciba）。
	BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelUserCodeParameterSupported  *bool    `json:"backchannel_user_code_parameter_supported,omitempty"`
	// PAR（RFC 9126 5。フィーチャー par）。
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`
	// 認可応答の iss（RFC 9207 3。ADR 0117）。
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	// OpenID4VCI の Pre-Authorized Code（OpenID4VCI 12.3。フィーチャー openid4vci）。
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported,omitempty"`
}

func (s *oidcServer) Discovery(ctx context.Context, _ *op.Request[struct{}]) (*op.Response, error) {
	d, err := s.metadata(ctx)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewResponse(d), nil
}

// metadata は Discovery と Authorization Server Metadata（RFC 8414）の中身。
func (s *oidcServer) metadata(ctx context.Context) (discovery, error) {
	var algs []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		algs, err = s.a.keys.Advertised(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		return discovery{}, err
	}
	d := discovery{DiscoveryConfiguration: &oidc.DiscoveryConfiguration{
		Issuer:                            s.a.issuer,
		AuthorizationEndpoint:             s.endpoint(oidcAuthorize),
		TokenEndpoint:                     s.endpoint(oidcToken),
		UserinfoEndpoint:                  s.endpoint(oidcUserinfo),
		JwksURI:                           s.endpoint(oidcKeys),
		ScopesSupported:                   s.scopes(),
		ResponseTypesSupported:            []string{string(oidc.ResponseTypeCode)},
		ResponseModesSupported:            s.responseModes(),
		GrantTypesSupported:               s.grantTypes(),
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  algs,
		TokenEndpointAuthMethodsSupported: authMethods,
		TokenEndpointAuthSigningAlgValuesSupported: assertionAlgs,
		ClaimsSupported:                                    s.claims(),
		CodeChallengeMethodsSupported:                      []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		ClaimTypesSupported:                                []string{"normal"},
		IntrospectionEndpoint:                              s.endpoint(oidcIntrospect),
		IntrospectionEndpointAuthMethodsSupported:          confidentialAuthMethods,
		IntrospectionEndpointAuthSigningAlgValuesSupported: assertionAlgs,
		RevocationEndpoint:                                 s.endpoint(oidcRevoke),
		RevocationEndpointAuthMethodsSupported:             authMethods,
		RevocationEndpointAuthSigningAlgValuesSupported:    assertionAlgs,
		BackChannelLogoutSupported:                         true,
		BackChannelLogoutSessionSupported:                  true,
	}}
	d.ACRValuesSupported = s.acrValues()
	if s.a.logoutTmpl != nil {
		// RP-Initiated Logout と Front-Channel Logout（フィーチャー oidc_logout。ADR 0094）。
		d.EndSessionEndpoint = s.endpoint(oidcEndSession)
		d.FrontChannelLogoutSupported, d.FrontChannelLogoutSessionSupported = true, true
		d.UILocalesSupported = []language.Tag{language.English, language.Japanese}
	}
	// Device Authorization Grant（フィーチャー device_flow。オフなら出さない）。
	if s.a.device != nil {
		d.DeviceAuthorizationEndpoint = s.endpoint(oidcDeviceAuth)
		d.GrantTypesSupported = append(slices.Clone(d.GrantTypesSupported), oidc.GrantTypeDeviceCode)
	}
	// CIBA（フィーチャー ciba。オフなら出さない。ADR 0114）。署名した要求と user_code は扱わない。
	if s.a.ciba != nil {
		no := false
		d.BackchannelAuthenticationEndpoint = s.endpoint(oidcBackchannel)
		d.BackchannelTokenDeliveryModesSupported = []string{port.CIBAPoll, port.CIBAPing}
		d.BackchannelUserCodeParameterSupported = &no
		d.GrantTypesSupported = append(slices.Clone(d.GrantTypesSupported), oidc.GrantType(provider.GrantTypeCIBA))
	}
	// PAR（フィーチャー par。ADR 0112）。
	if s.a.par {
		d.PushedAuthorizationRequestEndpoint = s.endpoint(oidcPAR)
		d.RequirePushedAuthorizationRequests = s.a.settings.RequirePushedAuthorizationRequests
	}
	s.senderConstraintDiscovery(&d)
	d.AuthorizationResponseIssParameterSupported = true
	s.fapi2Discovery(&d)
	if s.a.vci != nil {
		d.GrantTypesSupported = append(slices.Clone(d.GrantTypesSupported), oidc.GrantType(vci.GrantTypePreAuthorized))
		d.PreAuthorizedGrantAnonymousAccessSupported = true
	}
	return d, nil
}

func (s *oidcServer) Keys(ctx context.Context, _ *op.Request[struct{}]) (*op.Response, error) {
	var b []byte
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		b, err = s.a.keys.JWKS(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	resp := op.NewResponse(json.RawMessage(b))
	resp.Header.Set("Cache-Control", "public, max-age=300")
	return resp, nil
}

// opClient は連携先を op.Client にする。device は Device Authorization Grant を許すか（フィーチャーが動いていて、
// 連携先で許したとき）。exchange は Token Exchange を許した連携先か（フィーチャーが動いているときだけ真）。
type opClient struct {
	c        port.Client
	device   bool
	exchange bool
	// resource は認可要求の resource（RFC 8707）で、この連携先に許したリソース。resourceErr は resource が使えないときの
	// invalid_target（Authorize が戻り先に返す。ADR 0112）。
	resource    *port.OAuthResource
	resourceErr error
	// credentialScopes は OpenID4VCI の定義のスコープ（ADR 0119。フィーチャー openid4vci）。
	credentialScopes []string
}

func (s *oidcServer) opClient(c port.Client) opClient {
	_, exchange := provider.ParseExchangePolicy(c.TokenExchange)
	return opClient{c: c, device: s.a.device != nil && c.DeviceGrant,
		exchange: exchange && s.a.tokens.TokenExchange && c.AuthMethod != port.ClientAuthNone}
}

func (c opClient) GetID() string                    { return c.c.PublicID }
func (c opClient) RedirectURIs() []string           { return c.c.RedirectURIs }
func (c opClient) PostLogoutRedirectURIs() []string { return c.c.PostLogoutRedirectURIs }

// ApplicationType は、公開クライアントをネイティブアプリとして扱う（loopback の戻り先はポートを問わない。RFC 8252 7.3）。
func (c opClient) ApplicationType() op.ApplicationType {
	if c.c.AuthMethod == port.ClientAuthNone {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c opClient) AuthMethod() oidc.AuthMethod {
	switch c.c.AuthMethod {
	case port.ClientAuthSecret:
		return oidc.AuthMethodBasic
	case port.ClientAuthPrivateKeyJWT:
		return oidc.AuthMethodPrivateKeyJWT
	case port.ClientAuthTLS, port.ClientAuthSelfSignedTLS:
		return oidc.AuthMethod(c.c.AuthMethod)
	}
	return oidc.AuthMethodNone
}

func (opClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c opClient) GrantTypes() []oidc.GrantType {
	gt := grantTypes
	if c.exchange {
		gt = exchangeGrantTypes()
	}
	if c.device {
		gt = append(slices.Clone(gt), oidc.GrantTypeDeviceCode)
	}
	return gt
}
func (opClient) LoginURL(string) string { return "" }
func (opClient) AccessTokenType() op.AccessTokenType { // 不透明なトークン。DPoP の token_type は応答で決める（ADR 0113）
	return op.AccessTokenTypeBearer
}
func (opClient) IDTokenLifetime() time.Duration { return 0 }
func (opClient) DevMode() bool                  { return false }
func (opClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (opClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// IsScopeAllowed は op に、標準でないスコープ（attributes と、resource のリソースのスコープ）を残させる。使えるかは
// authorize が決める。
func (c opClient) IsScopeAllowed(sc string) bool {
	return sc == provider.ScopeAttributes || (c.resource != nil && slices.Contains(c.resource.Scopes, sc)) || slices.Contains(c.credentialScopes, sc)
}
func (opClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (opClient) ClockSkew() time.Duration             { return 0 }

func (s *oidcServer) client(ctx context.Context, clientID string) (port.Client, error) {
	var cl port.Client
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		cl, err = tx.Clients().GetByPublicID(ctx, s.a.realm.ID, clientID)
		return err
	})
	return cl, err
}

// VerifyAuthRequest は認可要求の連携先を確かめる。request_uri（PAR。RFC 9126 4）なら、預かったパラメーターだけを認可要求として
// 読み替える。ここで返すエラーは戻り先に転送しない（画面に出す）。
func (s *oidcServer) VerifyAuthRequest(ctx context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
	pushed := false
	if uri := r.Form.Get("request_uri"); uri != "" {
		var err error
		if r, err = s.pushedRequest(ctx, r, uri); err != nil {
			return nil, err
		}
		pushed = true
	}
	if r.Data.RequestParam != "" {
		return nil, oidc.ErrRequestNotSupported()
	}
	if r.Data.ClientID == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id is required")
	}
	cl, err := s.client(ctx, r.Data.ClientID)
	if errors.Is(err, errs.NotFound) {
		return nil, oidc.ErrInvalidRequest().WithDescription("unknown client_id")
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	if !pushed && s.parRequired(cl) {
		return nil, oidc.ErrInvalidRequest().WithDescription("pushed authorization request required")
	}
	cr, err := s.clientRequest(ctx, r, cl)
	if err == nil {
		noteFormPost(ctx, cr.Data)
	}
	return cr, err
}

// clientRequest は認可要求に連携先を結び付ける。resource（RFC 8707）があれば、この連携先に許したリソースを引いておく
// （フィーチャー resource_indicators がオフなら resource は見ない）。
func (s *oidcServer) clientRequest(ctx context.Context, r *op.Request[oidc.AuthRequest], cl port.Client) (*op.ClientRequest[oidc.AuthRequest], error) {
	oc := s.opClient(cl)
	scopes, err := s.credentialScopes(ctx)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	oc.credentialScopes = scopes
	if res := r.Form["resource"]; s.a.resources != nil && len(res) > 0 {
		x, err := s.resource(ctx, res, cl.PublicID)
		switch {
		case errors.Is(err, provider.ErrInvalidTarget):
			oc.resourceErr = errInvalidTarget()
		case err != nil:
			return nil, s.fail(ctx, err)
		default:
			oc.resource = &x
		}
	}
	return &op.ClientRequest[oidc.AuthRequest]{Request: r, Client: oc}, nil
}

// resource は連携先 clientID が resource に指定したリソースを返す。1 つだけ受ける。使えなければ provider.ErrInvalidTarget。
func (s *oidcServer) resource(ctx context.Context, res []string, clientID string) (port.OAuthResource, error) {
	if len(res) != 1 {
		return port.OAuthResource{}, provider.ErrInvalidTarget
	}
	var x port.OAuthResource
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		x, err = provider.ResourceForClient(ctx, tx, s.a.realm.ID, res[0], clientID)
		return err
	})
	return x, err
}

// errInvalidTarget は resource が使えないときのエラー（RFC 8707 2）。
func errInvalidTarget() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_target", Description: "the requested resource is not allowed"}
}

// Authorize は検証済みの認可要求（戻り先・スコープ・response_type は op が確かめた）を受け、ログイン済みなら認可コードを、
// そうでなければログイン画面への転送を返す。ここで返すエラーは戻り先に転送される。
func (s *oidcServer) Authorize(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	red, err := s.authorize(ctx, r)
	var oe *oidc.Error
	if err != nil && s.a.formPost && r.Data.ResponseMode == responseModeFormPost && errors.As(err, &oe) {
		// op はエラーをクエリで戻り先に転送するので、form_post の要求のエラーはここで画面に回す（ADR 0124）。
		return s.errorRedirect(ctx, provider.AuthRequest{RedirectURI: r.Data.RedirectURI, State: r.Data.State, ResponseMode: string(responseModeFormPost)}, oe)
	}
	return red, err
}

func (s *oidcServer) authorize(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	req, err := s.authRequest(r)
	if err != nil {
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	if slices.Contains(r.Data.Prompt, oidc.PromptLogin) {
		// op は prompt=login を max_age=0 にする。ログイン画面から戻るまでの時間を許すため、時刻で比べる。
		req.MaxAge, req.LoginAfter = nil, &now
	}
	au, ok := authFrom(ctx)
	if ok && req.Fresh(au.AuthenticatedAt, now) && acrMet(req, au.AuthMethods) {
		return s.complete(ctx, req, au)
	}
	if slices.Contains(r.Data.Prompt, oidc.PromptNone) {
		return nil, oidc.ErrLoginRequired()
	}
	if len(req.ACR) > 0 && req.LoginAfter == nil {
		// acr を求めるなら、ここから後のログインを求める（step-up。今のセッションで足りるなら上で済んでいる）。戻ったときに
		// 満たさなければ、ログインし直しても届かないので unmet_authentication_requirements にする（ADR 0093）。
		req.LoginAfter = &now
	}
	rid, err := s.a.flow.Hold(ctx, req)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewRedirect(s.a.loginURL(rid)), nil
}

// authRequest は op が確かめた認可要求を、IAM の規則（openid、response_mode、PKCE、スコープ、acr、resource）で確かめて
// provider.AuthRequest にする。ログインの状態は見ない（PAR の受け付けでも使う）。
func (s *oidcServer) authRequest(r *op.ClientRequest[oidc.AuthRequest]) (provider.AuthRequest, error) {
	d := r.Data
	oc, _ := r.Client.(opClient)
	// OpenID4VCI のウォレットは openid を送らない。定義のスコープを含む認可要求は openid 無しでも受ける（ADR 0119）。
	credential := slices.ContainsFunc(d.Scopes, func(sc string) bool { return slices.Contains(oc.credentialScopes, sc) })
	if !slices.Contains(d.Scopes, provider.ScopeOpenID) && !credential {
		return provider.AuthRequest{}, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	if d.ResponseMode != "" && d.ResponseMode != oidc.ResponseModeQuery && (!s.a.formPost || d.ResponseMode != responseModeFormPost) {
		return provider.AuthRequest{}, oidc.ErrInvalidRequest().WithDescription("response_mode is not supported")
	}
	// PKCE は S256 だけで、どの連携先にも求める（OAuth 2.0 Security BCP）。
	if d.CodeChallengeMethod != oidc.CodeChallengeMethodS256 || !provider.ValidPKCEValue(d.CodeChallenge) {
		return provider.AuthRequest{}, oidc.ErrInvalidRequest().WithDescription("code_challenge with S256 is required")
	}
	if oc.resourceErr != nil {
		return provider.AuthRequest{}, oc.resourceErr
	}
	req := provider.AuthRequest{RealmID: s.a.realm.ID, ClientID: d.ClientID, RedirectURI: d.RedirectURI, State: d.State, Nonce: d.Nonce,
		CodeChallenge: d.CodeChallenge, ResponseMode: string(d.ResponseMode), MaxAge: d.MaxAge, FAPI2: s.fapi2(oc.c)}
	allowed := s.scopes()
	if oc.resource != nil {
		// 自前の API に向けた認可（RFC 8707、ADR 0112）。リソースのスコープも選べ、アクセストークンの aud はリソースの URI。
		req.Resource, allowed = oc.resource.URI, append(slices.Clone(allowed), oc.resource.Scopes...)
	}
	allowed = append(slices.Clone(allowed), oc.credentialScopes...)
	for _, sc := range d.Scopes {
		if slices.Contains(allowed, sc) && !slices.Contains(req.Scopes, sc) {
			req.Scopes = append(req.Scopes, sc)
		}
	}
	if s.a.acrActive() {
		values, err := requestedACR(d.ACRValues, r.Form.Get("claims"))
		if err != nil {
			return provider.AuthRequest{}, err
		}
		req.ACR = acr.Requested(values, s.a.hardwareAAL())
	}
	if jkt := r.Form.Get("dpop_jkt"); jkt != "" && s.a.dpop != nil {
		// 認可コードを DPoP の鍵に結び付ける（RFC 9449 10）。PAR で預けたものも同じ（10.1）。フィーチャーが止まっていれば見ない。
		if !dpop.ValidJKT(jkt) {
			return provider.AuthRequest{}, oidc.ErrInvalidRequest().WithDescription("dpop_jkt is malformed")
		}
		req.DPoPJKT = jkt
	}
	return req, nil
}

// loginURL はログイン画面の URL。ログインの後で oidcResume に戻る。realm をパスで指すときは接頭辞を付ける。
func (a *App) loginURL(rid string) string {
	return a.base + "/login?" + url.Values{"return_to": {a.base + oidcResume + "?" + url.Values{"request": {rid}}.Encode()}}.Encode()
}

// complete はセッションで認可コードを発行し、連携先の戻り先への転送を返す。
func (s *oidcServer) complete(ctx context.Context, req provider.AuthRequest, au auth) (*op.Redirect, error) {
	// ログインの間にフィーチャー form_post が止まったら、預かった form_post の要求にはコードを出さない（ADR 0124）。
	if req.ResponseMode == string(responseModeFormPost) && !s.a.formPost {
		return s.errorRedirect(ctx, req, oidc.ErrInvalidRequest().WithDescription("response_mode is not supported"))
	}
	// active な Org が使えない（停止・有効期間の外など）セッションでは連携先に入れない（4.7）。
	if len(au.OrgUnavailable) > 0 {
		return s.errorRedirect(ctx, req, oidc.ErrAccessDenied())
	}
	c := provider.Code{AuthRequest: req, UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID, AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods}
	if s.a.acrActive() {
		v, ok := acr.Select(req.ACR, au.AuthMethods)
		if !ok {
			return s.errorRedirect(ctx, req, errUnmetAuthentication())
		}
		c.SelectedACR = v
	}
	code, err := s.a.flow.IssueCode(ctx, c)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	red, err := s.authResponse(ctx, req, &op.CodeResponseType{Code: code, State: req.State}, au.SID)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return red, nil
}

// requestedACR は要求された acr の値（ADR 0093）。claims パラメーター（OpenID Connect Core 5.5）の id_token.acr に
// value・values があればそれを、無ければ acr_values を使う。essential かどうかは区別しない（どちらも満たせなければ
// unmet_authentication_requirements にする）。claims のほかの項目は見ない。claims が JSON でなければ invalid_request。
func requestedACR(acrValues []string, claims string) ([]string, error) {
	if claims == "" {
		return acrValues, nil
	}
	var c struct {
		IDToken map[string]*struct {
			Value  *string  `json:"value"`
			Values []string `json:"values"`
		} `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(claims), &c); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("claims must be a JSON object")
	}
	r := c.IDToken["acr"]
	if r == nil || (r.Value == nil && len(r.Values) == 0) {
		return acrValues, nil
	}
	var out []string
	if r.Value != nil {
		out = append(out, *r.Value)
	}
	return append(out, r.Values...), nil
}

// acrMet は amr の認証が要求の acr を満たすか（要求が無ければ真）。
func acrMet(req provider.AuthRequest, amr []string) bool {
	_, ok := acr.Select(req.ACR, amr)
	return ok
}

// errUnmetAuthentication はログインし直しても要求の acr に届かないときのエラー
// （OpenID Connect Core Error Code unmet_authentication_requirements）。
func errUnmetAuthentication() *oidc.Error {
	return &oidc.Error{ErrorType: "unmet_authentication_requirements", Description: "the requested authentication context class could not be met"}
}

func (s *oidcServer) errorRedirect(ctx context.Context, req provider.AuthRequest, e *oidc.Error) (*op.Redirect, error) {
	e.State = req.State
	sid := ""
	if au, ok := authFrom(ctx); ok {
		sid = au.SID
	}
	red, err := s.authResponse(ctx, req, e, sid)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return red, nil
}

// resume はログイン画面から戻ったブラウザに、預かった認可要求の認可コードを発行する。
func (s *oidcServer) resume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	rid := r.URL.Query().Get("request")
	req, err := s.a.flow.Resume(ctx, s.a.realm.ID, rid)
	if errors.Is(err, provider.ErrRequestExpired) {
		http.Error(w, "The sign-in request has expired. Please return to the application and try again.", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	au, ok := authFrom(ctx)
	if !ok || !req.Fresh(au.AuthenticatedAt, s.a.deps.Clock.Now()) {
		http.Redirect(w, r, s.a.loginURL(rid), http.StatusFound)
		return
	}
	// 待つ間に連携先の登録が変わっていないかを確かめ直す。
	cl, err := s.client(ctx, req.ClientID)
	if errors.Is(err, errs.NotFound) {
		http.Error(w, "The application is no longer registered.", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	if op.ValidateAuthReqRedirectURI(s.opClient(cl), req.RedirectURI, oidc.ResponseTypeCode) != nil {
		http.Error(w, "The application's redirect URI is no longer registered.", http.StatusBadRequest)
		return
	}
	red, err := s.complete(ctx, req, au)
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	if err := s.a.flow.Drop(ctx, rid); err != nil {
		s.a.deps.Logger.WarnContext(ctx, "oidc: drop authorization request", "error", err)
	}
	http.Redirect(w, r, red.URL, http.StatusFound)
}

// VerifyClient は token・revoke・device_authorization エンドポイントでの連携先の認証（client_secret_basic / post、
// private_key_jwt、none）。
func (s *oidcServer) VerifyClient(ctx context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	aud := []string{s.endpoint(oidcToken), s.a.issuer}
	if r.URL != nil && (r.URL.Path == oidcRevoke || r.URL.Path == oidcDeviceAuth) {
		aud = []string{s.endpoint(r.URL.Path), s.a.issuer}
	}
	cl, err := s.authenticate(ctx, r.Data, aud, false)
	if err != nil {
		return nil, err
	}
	return s.opClient(cl), nil
}

// authenticate は連携先を認証する。confidential なら client_secret か private_key_jwt を求める。
func (s *oidcServer) authenticate(ctx context.Context, cc *op.ClientCredentials, audiences []string, confidential bool) (port.Client, error) {
	var cl port.Client
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		switch {
		case cc.ClientAssertion != "":
			cl, err = provider.AuthenticateAssertion(ctx, tx, s.a.deps.Ephemeral, s.a.deps.Clock, s.a.realm.ID, cc.ClientID, cc.ClientAssertion, audiences)
		case cc.ClientSecret != "":
			cl, err = provider.AuthenticateSecret(ctx, tx, s.a.realm.ID, cc.ClientID, cc.ClientSecret)
		default:
			cl, err = tx.Clients().GetByPublicID(ctx, s.a.realm.ID, cc.ClientID)
			switch {
			case errors.Is(err, errs.NotFound):
				err = provider.ErrClientAuth
			case err != nil:
			case cl.AuthMethod == port.ClientAuthTLS || cl.AuthMethod == port.ClientAuthSelfSignedTLS:
				// mTLS の認証（RFC 8705 2。ADR 0113）。証明書は ADR 0103 の経路で受けたもの。フィーチャーが止まっていれば通さない。
				if s.a.oauthMTLS == nil {
					err = provider.ErrClientAuth
					break
				}
				cl, err = provider.AuthenticateTLS(ctx, tx, s.a.oauthMTLS, s.a.realm.ID, cc.ClientID, credential.ClientCertificates(ctx))
			case confidential || cl.AuthMethod != port.ClientAuthNone:
				err = provider.ErrClientAuth
			}
		}
		return err
	})
	if errors.Is(err, provider.ErrClientAuth) {
		return port.Client{}, op.NewStatusError(oidc.ErrInvalidClient().WithDescription("client authentication failed"), http.StatusUnauthorized)
	}
	if err != nil {
		return port.Client{}, s.fail(ctx, err)
	}
	// FAPI 2.0 の連携先は、認証方式・送信者制約・client assertion の alg も確かめる（ADR 0117）。
	if err := s.checkFAPI2Client(ctx, cl, cc.ClientAssertion); err != nil {
		return port.Client{}, err
	}
	return cl, nil
}

func (s *oidcServer) CodeExchange(ctx context.Context, r *op.ClientRequest[oidc.AccessTokenRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	b, err := s.tokenBinding(ctx, r.Method, r.URL.Path, r.Header, cl)
	if err != nil {
		return nil, err
	}
	c, err := s.a.flow.Redeem(ctx, s.a.realm.ID, cl.PublicID, r.Data.Code, r.Data.RedirectURI, r.Data.CodeVerifier)
	if errors.Is(err, provider.ErrInvalidGrant) {
		return nil, oidc.ErrInvalidGrant()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	// token エンドポイントの resource（RFC 8707 2.2）は、認可要求で指定したものと同じ 1 つに限る（ADR 0112）。
	if res := s.tokenResources(r.Form); len(res) > 0 && (len(res) != 1 || res[0] != c.Resource || c.Resource == "") {
		return nil, errInvalidTarget()
	}
	var out provider.Issued
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Exchange(ctx, tx, cl, c, b, requestID(ctx))
		return err
	})
	if errors.Is(err, provider.ErrInvalidGrant) {
		return nil, oidc.ErrInvalidGrant()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return tokenResponse(out), nil
}

// tokenResources は token エンドポイントの resource（RFC 8707）。フィーチャー resource_indicators がオフなら見ない。
func (s *oidcServer) tokenResources(form url.Values) []string {
	if s.a.resources == nil {
		return nil
	}
	return form["resource"]
}

func tokenResponse(out provider.Issued) *op.Response {
	// #nosec G115 -- ExpiresIn は設定の正の寿命
	resp := op.NewResponse(&oidc.AccessTokenResponse{AccessToken: out.AccessToken, TokenType: tokenType(out.Binding), RefreshToken: out.RefreshToken,
		ExpiresIn: uint64(out.ExpiresIn / time.Second), IDToken: out.IDToken, Scope: out.Scopes})
	resp.Header.Set("Pragma", "no-cache")
	return resp
}

// RefreshToken はリフレッシュトークンで新しいトークンを発行する。使用済みのトークンが再び来たら、認可ごと失効させたことを
// 確定してから invalid_grant を返す。
func (s *oidcServer) RefreshToken(ctx context.Context, r *op.ClientRequest[oidc.RefreshTokenRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	b, err := s.tokenBinding(ctx, r.Method, r.URL.Path, r.Header, cl)
	if err != nil {
		return nil, err
	}
	var out provider.Refreshed
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		// FAPI 2.0 の連携先のリフレッシュトークンはローテーションしない（ADR 0117）。
		out, err = s.a.tokens.Refresh(ctx, tx, cl, r.Data.RefreshToken, b, s.tokenResources(r.Form), !s.fapi2(cl), requestID(ctx))
		return err
	})
	if errors.Is(err, provider.ErrInvalidGrant) || (err == nil && out.Reused) {
		return nil, oidc.ErrInvalidGrant()
	}
	if errors.Is(err, provider.ErrInvalidTarget) {
		return nil, errInvalidTarget()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return tokenResponse(out.Issued), nil
}

// Introspect はイントロスペクション（RFC 7662）。呼べるのは client_secret か private_key_jwt で認証した連携先（リソースサーバー）だけ。
// aud のリソースがイントロスペクションしてよい連携先を限っていれば、それ以外の連携先には active: false を返す（ADR 0120）。
func (s *oidcServer) Introspect(ctx context.Context, r *op.Request[op.IntrospectionRequest]) (*op.Response, error) {
	caller, err := s.authenticate(ctx, r.Data.ClientCredentials, []string{s.endpoint(oidcIntrospect), s.a.issuer}, true)
	if err != nil {
		return nil, err
	}
	var out provider.Introspection
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		switch {
		case serviceaccount.IsAccessToken(r.Data.Token):
			// サービスアカウントの、自前の API に向けたトークン（RFC 8707、ADR 0112）。管理 API 向けのものは active: false。
			out, err = s.a.resourceTokenIntrospection(ctx, tx, r.Data.Token)
		case serviceaccount.LooksLikeAPIKey(r.Data.Token):
			// サービスアカウントの API キー（ADR 0120）。フィーチャー api_key_introspection が動いていなければ active: false。
			out, err = s.a.apiKeyIntrospection(ctx, tx, r.Data.Token)
		case pat.Looks(r.Data.Token):
			// 本人の Personal Access Token（ADR 0109）。フィーチャーが動いていなければ active: false。
			out, err = s.a.patIntrospection(ctx, tx, r.Data.Token)
		default:
			out, err = s.a.tokens.Introspect(ctx, tx, s.a.realm.ID, r.Data.Token)
		}
		if err != nil || !out.Active {
			return err
		}
		ok, err := s.a.introspectionCallerAllowed(ctx, tx, out.Aud, caller.PublicID)
		if err == nil && !ok {
			out = provider.Introspection{}
		}
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewResponse(out), nil
}

// Revocation は失効（RFC 7009）。知らないトークンでも 200 を返す。
func (s *oidcServer) Revocation(ctx context.Context, r *op.ClientRequest[oidc.RevocationRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.a.tokens.Revoke(ctx, tx, cl, r.Data.Token, requestID(ctx))
	})
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewResponse(struct{}{}), nil
}

// userinfo は UserInfo（OIDC Core 5.3）。アクセストークンは Authorization ヘッダーか、POST の本文の access_token で受ける。
func (s *oidcServer) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scheme, token := authorization(r.Header.Get("Authorization"))
	if scheme == "" && r.Method == http.MethodPost {
		scheme, token = "Bearer", r.PostFormValue("access_token")
	}
	ctx := r.Context()
	var claims map[string]any
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		a, err := s.a.tokens.Validate(ctx, tx, s.a.realm.ID, strings.TrimSpace(token))
		if err != nil {
			return err
		}
		if provider.ResourceBound(a.Grant) {
			// aud が自前の API のトークンは、IAM 自身の UserInfo では使えない（RFC 8707。ADR 0112）。
			return provider.ErrInvalidToken
		}
		// 結び付けたトークン（DPoP・mTLS。ADR 0113）は、同じ鍵・証明書の要求でだけ通す。
		if err := s.a.checkResourceBinding(ctx, r, scheme, strings.TrimSpace(token), provider.TokenBinding(a.Token), s.endpointURLs(oidcUserinfo)); err != nil {
			return err
		}
		claims, err = s.a.tokens.UserInfo(ctx, tx, a)
		return err
	})
	if eb, ok := errors.AsType[*errBinding](err); ok {
		s.a.challenge(w, eb.Code, s.endpoint(wellKnownResource))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": eb.Code})
		return
	}
	if errors.Is(err, provider.ErrInvalidToken) {
		s.a.challenge(w, "invalid_token", s.endpoint(wellKnownResource))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}
