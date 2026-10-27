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

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OIDC Provider（design.md 5.1、5.5、9.3、ADR 0066）。要求の解析と検証は zitadel/oidc の op.Server に任せ、状態（認可要求・
// 認可コード・認可・トークン）と ID トークンの署名は authn/provider で行う。
//
//	GET  /.well-known/openid-configuration  Discovery
//	GET  /oauth2/keys                       JWKS（ML-DSA-65 と ES256）
//	GET  /oauth2/authorize                  認可要求。ログインしていなければログイン画面へ
//	GET  /oauth2/authorize/resume           ログイン画面から戻って認可コードを発行する
//	POST /oauth2/token                      認可コードの交換とリフレッシュ
//	POST /oauth2/introspect                 イントロスペクション（RFC 7662。機密の連携先だけ）
//	POST /oauth2/revoke                     失効（RFC 7009）
//	GET  /oauth2/userinfo                   UserInfo（POST も可）

const (
	oidcAuthorize  = "/oauth2/authorize"
	oidcResume     = "/oauth2/authorize/resume"
	oidcToken      = "/oauth2/token" // #nosec G101 -- パス
	oidcUserinfo   = "/oauth2/userinfo"
	oidcKeys       = "/oauth2/keys"
	oidcIntrospect = "/oauth2/introspect"
	oidcRevoke     = "/oauth2/revoke"
)

// isOIDC は OIDC Provider のパスかを返す。
func isOIDC(path string) bool {
	return path == oidc.DiscoveryEndpoint || strings.HasPrefix(path, "/oauth2/")
}

// newOIDCHandler は OIDC Provider のハンドラを返す。issuer（server.public_url）が無ければ nil。
func newOIDCHandler(a *App) http.Handler {
	if a.issuer == "" {
		return nil
	}
	srv := &oidcServer{a: a}
	ops := op.RegisterServer(srv, op.Endpoints{
		Authorization: op.NewEndpoint(oidcAuthorize),
		Token:         op.NewEndpoint(oidcToken),
		JwksURI:       op.NewEndpoint(oidcKeys),
		Introspection: op.NewEndpoint(oidcIntrospect),
		Revocation:    op.NewEndpoint(oidcRevoke),
	}, op.WithServerCORSOptions(nil))
	mux := http.NewServeMux()
	mux.Handle(oidc.DiscoveryEndpoint, ops)
	mux.Handle(oidcKeys, ops)
	mux.Handle(oidcToken, ops)
	mux.Handle(oidcIntrospect, ops)
	mux.Handle(oidcRevoke, ops)
	// 認可要求とその続きはブラウザのセッションを見る。
	mux.Handle(oidcAuthorize, a.withSession(ops))
	mux.Handle(oidcResume, a.withSession(http.HandlerFunc(srv.resume)))
	mux.HandleFunc(oidcUserinfo, srv.userinfo)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
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

func (s *oidcServer) Discovery(context.Context, *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(&oidc.DiscoveryConfiguration{
		Issuer:                                     s.a.issuer,
		AuthorizationEndpoint:                      s.endpoint(oidcAuthorize),
		TokenEndpoint:                              s.endpoint(oidcToken),
		UserinfoEndpoint:                           s.endpoint(oidcUserinfo),
		JwksURI:                                    s.endpoint(oidcKeys),
		ScopesSupported:                            provider.Scopes,
		ResponseTypesSupported:                     []string{string(oidc.ResponseTypeCode)},
		ResponseModesSupported:                     []string{string(oidc.ResponseModeQuery)},
		GrantTypesSupported:                        grantTypes,
		SubjectTypesSupported:                      []string{"public"},
		IDTokenSigningAlgValuesSupported:           provider.Algs,
		TokenEndpointAuthMethodsSupported:          authMethods,
		TokenEndpointAuthSigningAlgValuesSupported: assertionAlgs,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "azp", "org_id", "email",
			"email_verified"},
		CodeChallengeMethodsSupported:                      []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		ClaimTypesSupported:                                []string{"normal"},
		IntrospectionEndpoint:                              s.endpoint(oidcIntrospect),
		IntrospectionEndpointAuthMethodsSupported:          confidentialAuthMethods,
		IntrospectionEndpointAuthSigningAlgValuesSupported: assertionAlgs,
		RevocationEndpoint:                                 s.endpoint(oidcRevoke),
		RevocationEndpointAuthMethodsSupported:             authMethods,
		RevocationEndpointAuthSigningAlgValuesSupported:    assertionAlgs,
	}), nil
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

// opClient は連携先を op.Client にする。
type opClient struct{ c port.Client }

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
	}
	return oidc.AuthMethodNone
}

func (opClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (opClient) GrantTypes() []oidc.GrantType { return grantTypes }
func (opClient) LoginURL(string) string       { return "" }
func (opClient) AccessTokenType() op.AccessTokenType {
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
func (opClient) IsScopeAllowed(string) bool           { return false }
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

func (s *oidcServer) VerifyAuthRequest(ctx context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
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
	return &op.ClientRequest[oidc.AuthRequest]{Request: r, Client: opClient{cl}}, nil
}

// Authorize は検証済みの認可要求（戻り先・スコープ・response_type は op が確かめた）を受け、ログイン済みなら認可コードを、
// そうでなければログイン画面への転送を返す。ここで返すエラーは戻り先に転送される。
func (s *oidcServer) Authorize(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	d := r.Data
	if !slices.Contains(d.Scopes, provider.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	if d.ResponseMode != "" && d.ResponseMode != oidc.ResponseModeQuery {
		return nil, oidc.ErrInvalidRequest().WithDescription("response_mode is not supported")
	}
	// PKCE は S256 だけで、どの連携先にも求める（OAuth 2.0 Security BCP）。
	if d.CodeChallengeMethod != oidc.CodeChallengeMethodS256 || !provider.ValidPKCEValue(d.CodeChallenge) {
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge with S256 is required")
	}
	now := s.a.deps.Clock.Now()
	req := provider.AuthRequest{RealmID: s.a.realm.ID, ClientID: d.ClientID, RedirectURI: d.RedirectURI, State: d.State, Nonce: d.Nonce,
		CodeChallenge: d.CodeChallenge, ResponseMode: string(d.ResponseMode), MaxAge: d.MaxAge}
	for _, sc := range d.Scopes {
		if slices.Contains(provider.Scopes, sc) && !slices.Contains(req.Scopes, sc) {
			req.Scopes = append(req.Scopes, sc)
		}
	}
	if slices.Contains(d.Prompt, oidc.PromptLogin) {
		// op は prompt=login を max_age=0 にする。ログイン画面から戻るまでの時間を許すため、時刻で比べる。
		req.MaxAge, req.LoginAfter = nil, &now
	}
	au, ok := authFrom(ctx)
	if ok && req.Fresh(au.AuthenticatedAt, now) {
		return s.complete(ctx, req, au)
	}
	if slices.Contains(d.Prompt, oidc.PromptNone) {
		return nil, oidc.ErrLoginRequired()
	}
	rid, err := s.a.flow.Hold(ctx, req)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewRedirect(loginURL(rid)), nil
}

// loginURL はログイン画面の URL。ログインの後で oidcResume に戻る。
func loginURL(rid string) string {
	return "/login?" + url.Values{"return_to": {oidcResume + "?" + url.Values{"request": {rid}}.Encode()}}.Encode()
}

// complete はセッションで認可コードを発行し、連携先の戻り先への転送を返す。
func (s *oidcServer) complete(ctx context.Context, req provider.AuthRequest, au auth) (*op.Redirect, error) {
	// active な Org が使えない（停止・有効期間の外など）セッションでは連携先に入れない（4.7）。
	if len(au.OrgUnavailable) > 0 {
		return s.errorRedirect(ctx, req, oidc.ErrAccessDenied())
	}
	code, err := s.a.flow.IssueCode(ctx, provider.Code{AuthRequest: req, UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID,
		AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods})
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	u, err := op.AuthResponseURL(req.RedirectURI, oidc.ResponseTypeCode, oidc.ResponseMode(req.ResponseMode),
		&op.CodeResponseType{Code: code, State: req.State}, oidc.NewEncoder())
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewRedirect(u), nil
}

func (s *oidcServer) errorRedirect(ctx context.Context, req provider.AuthRequest, e *oidc.Error) (*op.Redirect, error) {
	e.State = req.State
	u, err := op.AuthResponseURL(req.RedirectURI, oidc.ResponseTypeCode, oidc.ResponseMode(req.ResponseMode), e, oidc.NewEncoder())
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return op.NewRedirect(u), nil
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
		http.Redirect(w, r, loginURL(rid), http.StatusFound)
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
	if op.ValidateAuthReqRedirectURI(opClient{cl}, req.RedirectURI, oidc.ResponseTypeCode) != nil {
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

// VerifyClient は token エンドポイントと revoke エンドポイントでの連携先の認証（client_secret_basic / post、
// private_key_jwt、none）。
func (s *oidcServer) VerifyClient(ctx context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	aud := []string{s.endpoint(oidcToken), s.a.issuer}
	if r.URL != nil && r.URL.Path == oidcRevoke {
		aud = []string{s.endpoint(oidcRevoke), s.a.issuer}
	}
	cl, err := s.authenticate(ctx, r.Data, aud, false)
	if err != nil {
		return nil, err
	}
	return opClient{cl}, nil
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
		case confidential:
			err = provider.ErrClientAuth
		default:
			cl, err = tx.Clients().GetByPublicID(ctx, s.a.realm.ID, cc.ClientID)
			if errors.Is(err, errs.NotFound) || (err == nil && cl.AuthMethod != port.ClientAuthNone) {
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
	return cl, nil
}

func (s *oidcServer) CodeExchange(ctx context.Context, r *op.ClientRequest[oidc.AccessTokenRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	c, err := s.a.flow.Redeem(ctx, s.a.realm.ID, cl.PublicID, r.Data.Code, r.Data.RedirectURI, r.Data.CodeVerifier)
	if errors.Is(err, provider.ErrInvalidGrant) {
		return nil, oidc.ErrInvalidGrant()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	var out provider.Issued
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Exchange(ctx, tx, cl, c, requestID(ctx))
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

func tokenResponse(out provider.Issued) *op.Response {
	// #nosec G115 -- ExpiresIn は設定の正の寿命
	resp := op.NewResponse(&oidc.AccessTokenResponse{AccessToken: out.AccessToken, TokenType: oidc.BearerToken, RefreshToken: out.RefreshToken,
		ExpiresIn: uint64(out.ExpiresIn / time.Second), IDToken: out.IDToken, Scope: out.Scopes})
	resp.Header.Set("Pragma", "no-cache")
	return resp
}

// RefreshToken はリフレッシュトークンで新しいトークンを発行する。使用済みのトークンが再び来たら、認可ごと失効させたことを
// 確定してから invalid_grant を返す。
func (s *oidcServer) RefreshToken(ctx context.Context, r *op.ClientRequest[oidc.RefreshTokenRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	var out provider.Refreshed
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Refresh(ctx, tx, cl, r.Data.RefreshToken, requestID(ctx))
		return err
	})
	if errors.Is(err, provider.ErrInvalidGrant) || (err == nil && out.Reused) {
		return nil, oidc.ErrInvalidGrant()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	return tokenResponse(out.Issued), nil
}

// Introspect はイントロスペクション（RFC 7662）。呼べるのは client_secret か private_key_jwt で認証した連携先（リソースサーバー）だけ。
func (s *oidcServer) Introspect(ctx context.Context, r *op.Request[op.IntrospectionRequest]) (*op.Response, error) {
	if _, err := s.authenticate(ctx, r.Data.ClientCredentials, []string{s.endpoint(oidcIntrospect), s.a.issuer}, true); err != nil {
		return nil, err
	}
	var out provider.Introspection
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Introspect(ctx, tx, s.a.realm.ID, r.Data.Token)
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
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok && r.Method == http.MethodPost {
		token = r.PostFormValue("access_token")
	}
	ctx := r.Context()
	var claims map[string]any
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		a, err := s.a.tokens.Validate(ctx, tx, s.a.realm.ID, strings.TrimSpace(token))
		if err != nil {
			return err
		}
		claims, err = s.a.tokens.UserInfo(ctx, tx, a)
		return err
	})
	if errors.Is(err, provider.ErrInvalidToken) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}
