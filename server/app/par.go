package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/schema"

	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Pushed Authorization Requests（RFC 9126）、Authorization Server Metadata（RFC 8414）、Protected Resource Metadata（RFC 9728）。
// ADR 0112。

// maxPARBody は PAR の要求の本文の上限。
const maxPARBody = 64 << 10

// authDecoder は預かった認可要求のパラメーターを読む（op と同じ設定。知らない項目は無視する）。
var authDecoder = func() *schema.Decoder {
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)
	return d
}()

// errRequestURI は request_uri が使えないときのエラー（RFC 9126 4、OIDC Core 3.1.2.6 の invalid_request_uri）。
func errRequestURI() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_request_uri", Description: "the request_uri is invalid or expired"}
}

// parRequired は連携先に PAR を求めるか（連携先の登録か realm の設定。フィーチャー par が動いているときだけ）。
func (s *oidcServer) parRequired(cl port.Client) bool {
	// FAPI 2.0 の連携先（ADR 0117）は par が止まっていても求める（request_uri を受けられないので認可要求は通らない。fail-closed）。
	return s.fapi2(cl) || s.a.par && (cl.RequirePAR || s.a.settings.RequirePushedAuthorizationRequests)
}

// pushedRequest は request_uri で預かった認可要求を、1 回だけ取り出して認可要求にする（RFC 9126 4）。パラメーターは
// 預かったものだけを使い、ブラウザから来たほかのパラメーターは見ない。client_id は預けた連携先と同じであること。
func (s *oidcServer) pushedRequest(ctx context.Context, r *op.Request[oidc.AuthRequest], uri string) (*op.Request[oidc.AuthRequest], error) {
	if !s.a.par {
		return nil, &oidc.Error{ErrorType: "request_uri_not_supported", Description: "request_uri is not supported"}
	}
	if r.Data.ClientID == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id is required")
	}
	params, err := s.a.flow.TakePushed(ctx, s.a.realm.ID, r.Data.ClientID, uri)
	if errors.Is(err, provider.ErrRequestURI) {
		return nil, errRequestURI()
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	data := new(oidc.AuthRequest)
	if err := authDecoder.Decode(data, params); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse the pushed authorization request")
	}
	return &op.Request[oidc.AuthRequest]{Method: r.Method, URL: r.URL, Header: r.Header, Form: params, Data: data}, nil
}

// pushAuthorization は PAR エンドポイント（RFC 9126 2）。連携先を token エンドポイントと同じ方法で認証し、認可要求を
// authorize と同じ規則で確かめてから預け、request_uri を返す（201）。誤りは token エンドポイントと同じ形の JSON で返し、
// 戻り先には転送しない。
func (s *oidcServer) pushAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxPARBody)
	if err := r.ParseForm(); err != nil {
		op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("cannot parse the request body"), nil)
		return
	}
	// パラメーターは本文だけから読む（RFC 9126 2.1）。
	params := r.PostForm
	switch {
	case params.Has("request_uri"):
		op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("request_uri must not be pushed"), nil)
		return
	case params.Has("request"):
		op.WriteError(w, r, oidc.ErrRequestNotSupported(), nil)
		return
	}
	cc, err := clientCredentials(r)
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	cl, err := s.authenticate(ctx, cc, []string{s.endpoint(oidcPAR), s.a.issuer, s.endpoint(oidcToken)}, false)
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	if id := params.Get("client_id"); id != "" && id != cl.PublicID {
		op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("client_id does not match the authenticated client"), nil)
		return
	}
	params = cloneValues(params)
	params.Set("client_id", cl.PublicID)
	if err := s.pushedDPoP(ctx, r, params, cl); err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	if err := s.checkPushed(ctx, r, params, cl); err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	uri, ttl, err := s.a.flow.Push(ctx, s.a.realm.ID, cl.PublicID, params)
	if errors.Is(err, provider.ErrPushedTooLarge) {
		op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("the pushed authorization request is too large"), nil)
		return
	}
	if err != nil {
		op.WriteError(w, r, s.fail(ctx, err), nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": uri, "expires_in": int(ttl.Seconds())})
}

// pushedDPoP は PAR の要求の DPoP の証明（RFC 9449 10.1）。証明があれば確かめ、その鍵を dpop_jkt として預ける。本文にも
// dpop_jkt があれば同じ鍵であること。フィーチャー dpop が止まっていれば証明を見ない（dpop_jkt も authRequest が見ない）。
// FAPI 2.0 の連携先（ADR 0117）の証明は PS256・ES256・EdDSA だけ。
func (s *oidcServer) pushedDPoP(ctx context.Context, r *http.Request, params url.Values, cl port.Client) error {
	proofs := r.Header.Values(dpop.Header)
	if s.a.dpop == nil || len(proofs) == 0 {
		return nil
	}
	p, err := s.a.dpop.Verify(ctx, proofs, dpop.Expect{Method: r.Method, URLs: s.endpointURLs(oidcPAR)})
	switch {
	case errors.Is(err, dpop.ErrUseNonce):
		return errUseDPoPNonce()
	case errors.Is(err, dpop.ErrInvalidProof):
		return errInvalidDPoPProof()
	case err != nil:
		return s.fail(ctx, err)
	}
	if s.fapi2(cl) && !fapi2DPoPAlg(p.Alg) {
		return errInvalidDPoPProof()
	}
	if jkt := params.Get("dpop_jkt"); jkt != "" && jkt != p.JKT {
		return errInvalidDPoPProof().WithDescription("dpop_jkt does not match the DPoP proof")
	}
	params.Set("dpop_jkt", p.JKT)
	return nil
}

// checkPushed は預ける認可要求を、authorize と同じ規則（op の確かめと IAM の規則）で確かめる。
func (s *oidcServer) checkPushed(ctx context.Context, r *http.Request, params url.Values, cl port.Client) error {
	data := new(oidc.AuthRequest)
	if err := authDecoder.Decode(data, params); err != nil {
		return oidc.ErrInvalidRequest().WithDescription("cannot parse the authorization request")
	}
	if data.RequestParam != "" {
		return oidc.ErrRequestNotSupported()
	}
	cr, err := s.clientRequest(ctx, &op.Request[oidc.AuthRequest]{Method: r.Method, URL: r.URL, Header: r.Header, Form: params, Data: data}, cl)
	if err != nil {
		return err
	}
	if data.RedirectURI == "" {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("redirect_uri is required")
	}
	if err := op.ValidateAuthReqRedirectURI(cr.Client, data.RedirectURI, data.ResponseType); err != nil {
		return err
	}
	if data.MaxAge, err = op.ValidateAuthReqPrompt(data.Prompt, data.MaxAge); err != nil {
		return err
	}
	if data.Scopes, err = op.ValidateAuthReqScopes(cr.Client, data.Scopes); err != nil {
		return err
	}
	if err := op.ValidateAuthReqResponseType(cr.Client, data.ResponseType); err != nil {
		return err
	}
	if err := op.ValidateAuthReqCodeChallengeMethod(data.CodeChallenge, data.CodeChallengeMethod); err != nil {
		return err
	}
	_, err = s.authRequest(cr)
	return err
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// authorizationServerMetadata は OAuth 2.0 Authorization Server Metadata（RFC 8414）。OIDC Discovery と同じ内容を返す
// （RFC 8414 の項目は Discovery の項目と同じ名前・意味で、issuer も同じ）。
func (s *oidcServer) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.metadata())
}

// resourceMetadata は IAM 自身の API の Protected Resource Metadata（RFC 9728 2）。
type resourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
}

// protectedResourceMetadata は IAM 自身の API（このアクセストークンを受ける UserInfo）のメタデータ（RFC 9728）。resource は
// issuer で、トークンを発行するのも同じ issuer。
func (s *oidcServer) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, resourceMetadata{Resource: s.a.issuer, AuthorizationServers: []string{s.a.issuer}, ScopesSupported: s.scopes(),
		BearerMethodsSupported: []string{"header", "body"}, ResourceName: "iam"})
}

// resourceTokenIntrospection はサービスアカウントの、自前の API に向けたアクセストークン（RFC 8707、ADR 0112）の
// イントロスペクション。管理 API 向けのトークンやフィーチャーが止まっているときは active: false。
func (a *App) resourceTokenIntrospection(ctx context.Context, tx port.Tx, token string) (provider.Introspection, error) {
	t, au, err := a.serviceAccounts.ResourceToken(ctx, tx, a.realm.ID, token, a.deps.Clock.Now())
	if errors.Is(err, serviceaccount.ErrInvalid) {
		return provider.Introspection{}, nil
	}
	if err != nil {
		return provider.Introspection{}, err
	}
	sa := au.Account
	out := provider.Introspection{Active: true, Scope: strings.Join(t.Scopes, " "), ClientID: sa.ID, TokenType: "access_token", Exp: t.ExpiresAt.Unix(),
		Iat: t.CreatedAt.Unix(), Sub: sa.ID, PrincipalType: port.PrincipalServiceAccount, Aud: []string{t.Audience}, Iss: a.issuer,
		AuthTime: au.AuthTime.Unix(), AMR: []string{au.Method}}
	if t.JKT != "" {
		// DPoP に結び付けたトークン（ADR 0113）。リソースサーバーが同じ鍵の証明を求める。
		out.Cnf = &provider.Confirmation{JKT: t.JKT}
	}
	return a.withServiceAccountOrg(ctx, tx, sa, out)
}

// apiKeyIntrospection はサービスアカウントの API キーのイントロスペクション（フィーチャー api_key_introspection。ADR 0120）。
// フィーチャーが止まっているときや使えない API キーは active: false。API キーは向け先を持たないので aud と scope は無い。
func (a *App) apiKeyIntrospection(ctx context.Context, tx port.Tx, key string) (provider.Introspection, error) {
	if !a.plan.IsActive(feature.APIKeyIntrospection) || !a.plan.IsActive(feature.ServiceAccounts) {
		return provider.Introspection{}, nil
	}
	now := a.deps.Clock.Now()
	c, sa, err := a.serviceAccounts.APIKey(ctx, tx, a.realm.ID, key, now)
	if errors.Is(err, serviceaccount.ErrInvalid) {
		return provider.Introspection{}, nil
	}
	if err != nil {
		return provider.Introspection{}, err
	}
	out := provider.Introspection{Active: true, TokenType: serviceaccount.TypeAPIKey, Iat: c.CreatedAt.Unix(), Sub: sa.ID,
		PrincipalType: port.PrincipalServiceAccount, Iss: a.issuer, AuthTime: now.Unix(), AMR: []string{serviceaccount.MethodAPIKey}}
	if c.ExpiresAt != nil {
		out.Exp = c.ExpiresAt.Unix()
	}
	return a.withServiceAccountOrg(ctx, tx, sa, out)
}

// withServiceAccountOrg は、サービスアカウントが Org に属していれば応答に Org の公開 ID を載せる。
func (a *App) withServiceAccountOrg(ctx context.Context, tx port.Tx, sa port.ServiceAccount, out provider.Introspection) (provider.Introspection, error) {
	if sa.OrgID != "" {
		// Org に属するサービスアカウント（ADR 0074）なら、リソースサーバーが Org ごとに扱えるよう Org の公開 ID を載せる（#190）。
		// Org が使えなければ、サービスアカウントの確かめ（ResourceToken・APIKey）がもう拒んでいる。
		o, err := tx.Orgs().Get(ctx, a.realm.ID, sa.OrgID)
		if errors.Is(err, errs.NotFound) {
			return provider.Introspection{}, nil
		}
		if err != nil {
			return provider.Introspection{}, err
		}
		out.OrgID = o.PublicID
	}
	return out, nil
}

// introspectionCallerAllowed は、aud のうち登録したリソース（RFC 8707、ADR 0112）がイントロスペクションしてよい連携先を限っていれば、
// 呼び出した連携先 clientID がそのすべてに載っているかを返す（ADR 0120）。限っていなければ true。
func (a *App) introspectionCallerAllowed(ctx context.Context, tx port.Tx, aud []string, clientID string) (bool, error) {
	if a.resources == nil {
		return true, nil
	}
	for _, uri := range aud {
		if !provider.ValidResourceURI(uri) {
			continue
		}
		x, err := tx.OAuthResources().GetByURI(ctx, a.realm.ID, uri)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		if len(x.IntrospectionClients) > 0 && !slices.Contains(x.IntrospectionClients, clientID) {
			return false, nil
		}
	}
	return true, nil
}
