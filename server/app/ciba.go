package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// OpenID Connect Client-Initiated Backchannel Authentication（CIBA Core 1.0、ADR 0114。フィーチャー ciba）。
//
//	POST /oauth2/bc-authorize                      機密の連携先が本人の手がかりを付けて要求し、auth_req_id を受け取る
//	POST /oauth2/token                             grant_type=urn:openid:params:grant-type:ciba でポーリングする（op.Server の前で受ける）
//	POST /v1/login/methods/push:callback           本人の端末（プッシュの承認）の応答（方式が受け、OnBackchannel で判断を記録する）
//	GET  /v1/me/backchannel-requests               本人宛ての未決の要求（本人の API）
//	POST /v1/me/backchannel-requests/{id}:approve  本人の API での承認・拒否（:deny）

const oidcBackchannel = "/oauth2/bc-authorize"

// cibaChannel は判断の経路（監査ログ）。
const (
	cibaChannelPush = "push"
	cibaChannelSelf = "self_service"
	cibaChannelNone = "none"
)

// cibaNotifyTimeout は ping の通知の打ち切り。
const cibaNotifyTimeout = 5 * time.Second

// writeCIBAError は CIBA のエラーの応答（CIBA Core 11、13、RFC 6749 5.2）。invalid_client は 401、それ以外は op の
// StatusError の状態か 400（token エンドポイントの access_denied も 400）。
func (s *oidcServer) writeCIBAError(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := errors.AsType[*oidc.Error](err); ok && e.ErrorType == oidc.InvalidClient {
		err = op.NewStatusError(e, http.StatusUnauthorized)
	}
	if _, ok := errors.AsType[*oidc.Error](err); !ok {
		if _, ok := errors.AsType[op.StatusError](err); !ok {
			err = s.fail(r.Context(), err)
		}
	}
	op.WriteError(w, r, err, nil)
}

// clientCredentials は要求の連携先の認証の値を読む（op の webServer と同じ規則。Basic が優先し、2つの方式を混ぜない）。
func clientCredentials(r *http.Request) (*op.ClientCredentials, error) {
	f := r.PostForm
	cc := &op.ClientCredentials{ClientID: f.Get("client_id"), ClientSecret: f.Get("client_secret"),
		ClientAssertion: f.Get("client_assertion"), ClientAssertionType: f.Get("client_assertion_type")}
	assertion := cc.ClientAssertion != "" && cc.ClientAssertionType != ""
	secret := cc.ClientSecret != "" && cc.ClientID != ""
	if assertion && secret {
		return nil, oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method")
	}
	if id, sec, ok := r.BasicAuth(); ok {
		if assertion || secret {
			return nil, oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method")
		}
		var err error
		if cc.ClientID, err = url.QueryUnescape(id); err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header")
		}
		if cc.ClientSecret, err = url.QueryUnescape(sec); err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header")
		}
	}
	if cc.ClientID == "" && cc.ClientAssertion == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id or client_assertion must be provided")
	}
	if cc.ClientAssertion != "" && cc.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return nil, oidc.ErrInvalidRequest().WithDescription("invalid client_assertion_type")
	}
	return cc, nil
}

// cibaClient は CIBA の要求の連携先を認証する（機密の連携先だけ。CIBA Core 4）。CIBA の登録が無ければ unauthorized_client。
func (s *oidcServer) cibaClient(r *http.Request, audiences []string) (port.Client, error) {
	cc, err := clientCredentials(r)
	if err != nil {
		return port.Client{}, err
	}
	cl, err := s.authenticate(r.Context(), cc, audiences, true)
	if err != nil {
		return port.Client{}, err
	}
	if cl.CIBAMode != port.CIBAPoll && cl.CIBAMode != port.CIBAPing {
		return port.Client{}, oidc.ErrUnauthorizedClient().WithDescription("backchannel authentication is not allowed for this client")
	}
	return cl, nil
}

// backchannelAuthorize は backchannel authentication エンドポイント（CIBA Core 7）。
func (s *oidcServer) backchannelAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeCIBAError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form"))
		return
	}
	ctx := r.Context()
	// 機密の連携先だけだが、総当たり・本人の有無の照会に使わせないよう、接続元ごとに数える。
	c, _ := ctx.Value(clientKey{}).(client)
	if !s.allowCIBA(w, r, "ciba:ip:"+s.a.realm.ID+":"+ratelimit.Bucket(c.IP), "ip") {
		return
	}
	cl, err := s.cibaClient(r, []string{s.endpoint(oidcBackchannel), s.a.issuer})
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	if !s.allowCIBA(w, r, "ciba:client:"+s.a.realm.ID+":"+cl.ID, "client") {
		return
	}
	req, hint, err := s.backchannelRequest(r.PostForm, cl)
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	u, err := s.backchannelUser(ctx, cl, hint)
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	req.UserID = u.ID
	st, err := s.a.ciba.Start(ctx, req)
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter(ex)))
		s.writeCIBAError(w, r, op.NewStatusError(oidc.ErrInvalidRequest().WithDescription("too many pending requests for the user"), http.StatusTooManyRequests))
		return
	}
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	channel := s.a.startBackchannelChannel(ctx, st, cl)
	s.a.recordCIBA(ctx, "oidc.ciba_requested", audit.ResultSuccess, audit.Actor{Type: "client", ID: cl.PublicID},
		map[string]any{"client_id": cl.PublicID, "user_id": u.PublicID, "scopes": req.Scopes, "mode": cl.CIBAMode, "channel": channel})
	resp := map[string]any{"auth_req_id": st.AuthReqID, "expires_in": int(st.ExpiresIn / time.Second), "interval": int(st.Interval / time.Second)}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

// allowCIBA は要求の回数を数える（security.login.rate_limit.per_ip）。超えたら 429 を書いて false。
func (s *oidcServer) allowCIBA(w http.ResponseWriter, r *http.Request, key, scope string) bool {
	err := s.a.perIP.Allow(r.Context(), key)
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		if ex.First {
			s.a.recordRateLimit(r.Context(), scope, oidcBackchannel)
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter(ex)))
		s.writeCIBAError(w, r, op.NewStatusError(oidc.ErrInvalidRequest().WithDescription("too many requests"), http.StatusTooManyRequests))
		return false
	}
	if err != nil {
		s.writeCIBAError(w, r, err)
		return false
	}
	return true
}

// cibaHint は本人の手がかり。
type cibaHint struct {
	loginHint, idTokenHint string
}

// backchannelRequest は要求の値を確かめる（CIBA Core 7.1）。
func (s *oidcServer) backchannelRequest(f url.Values, cl port.Client) (provider.BackchannelRequest, cibaHint, error) {
	var h cibaHint
	if f.Get("request") != "" || f.Get("request_uri") != "" {
		return provider.BackchannelRequest{}, h, oidc.ErrInvalidRequest().WithDescription("signed authentication requests are not supported")
	}
	scopes := strings.Fields(f.Get("scope"))
	if !slices.Contains(scopes, provider.ScopeOpenID) {
		return provider.BackchannelRequest{}, h, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	req := provider.BackchannelRequest{RealmID: s.a.realm.ID, ClientID: cl.PublicID, Mode: cl.CIBAMode}
	for _, sc := range scopes {
		if slices.Contains(s.scopes(), sc) && !slices.Contains(req.Scopes, sc) {
			req.Scopes = append(req.Scopes, sc)
		}
	}
	// 手がかりはちょうど1つ。
	n := 0
	for _, k := range []string{"login_hint", "id_token_hint", "login_hint_token"} {
		if f.Get(k) != "" {
			n++
		}
	}
	if n != 1 {
		return provider.BackchannelRequest{}, h, oidc.ErrInvalidRequest().WithDescription("exactly one of login_hint, id_token_hint and login_hint_token is required")
	}
	if f.Get("login_hint_token") != "" {
		return provider.BackchannelRequest{}, h, oidc.ErrInvalidRequest().WithDescription("login_hint_token is not supported")
	}
	h = cibaHint{loginHint: f.Get("login_hint"), idTokenHint: f.Get("id_token_hint")}
	if m := f.Get("binding_message"); m != "" {
		if !provider.ValidBindingMessage(m) {
			return provider.BackchannelRequest{}, h, &oidc.Error{ErrorType: "invalid_binding_message", Description: "binding_message must be at most 64 characters without control characters"}
		}
		req.BindingMessage = m
	}
	if cl.CIBAMode == port.CIBAPing {
		t := f.Get("client_notification_token")
		if !provider.ValidNotificationToken(t) {
			return provider.BackchannelRequest{}, h, oidc.ErrInvalidRequest().WithDescription("client_notification_token is required for the ping mode")
		}
		req.NotificationToken = t
	}
	if v := f.Get("requested_expiry"); v != "" {
		sec, err := strconv.Atoi(v)
		if err != nil || sec <= 0 || sec > 86400 {
			return provider.BackchannelRequest{}, h, oidc.ErrInvalidRequest().WithDescription("requested_expiry must be a positive integer")
		}
		req.ExpiresAt = s.a.deps.Clock.Now().Add(time.Duration(sec) * time.Second)
	}
	if s.a.acrActive() {
		req.ACR = acr.Requested(strings.Fields(f.Get("acr_values")), s.a.hardwareAAL())
	}
	return req, h, nil
}

// errUnknownUser は本人が分からない（CIBA Core 13 の unknown_user_id。理由は区別しない）。
func errUnknownUser() *oidc.Error {
	return &oidc.Error{ErrorType: "unknown_user_id", Description: "the user could not be identified"}
}

// backchannelUser は手がかりから本人を決める。login_hint は確認済みのメールアドレスかユーザーの公開 ID、id_token_hint はこの連携先に
// 発行した ID トークン。ログインできる状態のユーザーだけ。
func (s *oidcServer) backchannelUser(ctx context.Context, cl port.Client, h cibaHint) (port.User, error) {
	var u port.User
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		switch {
		case h.idTokenHint != "":
			var sub string
			if sub, err = s.a.tokens.HintSubject(ctx, tx, s.a.realm.ID, cl.PublicID, h.idTokenHint); err != nil {
				return err
			}
			u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, sub)
		case strings.Contains(h.loginHint, "@"):
			email, nerr := account.NormalizeEmail(h.loginHint)
			if nerr != nil {
				return errs.New(errs.KindNotFound, "user")
			}
			e, ferr := s.a.accounts.FindByEmail(ctx, tx, s.a.realm.ID, email)
			if ferr != nil {
				return ferr
			}
			if e.VerifiedAt == nil {
				return errs.New(errs.KindNotFound, "user")
			}
			u, err = tx.Users().Get(ctx, s.a.realm.ID, e.UserID)
		default:
			if len(h.loginHint) > 64 {
				return errs.New(errs.KindNotFound, "user")
			}
			u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, h.loginHint)
		}
		return err
	})
	if errors.Is(err, errs.NotFound) || errors.Is(err, provider.ErrInvalidHint) || (err == nil && u.Status != port.UserActive) {
		return port.User{}, errUnknownUser()
	}
	return u, err
}

// startBackchannelChannel は本人の端末（プッシュの承認）に要求を送る。送れる方式・端末が無い、上限を超えた、送れなかったときも
// 要求はそのまま（本人の API で承認できる）。返すのは経路（監査ログ）。
func (a *App) startBackchannelChannel(ctx context.Context, st provider.BackchannelStart, cl port.Client) string {
	r := st.Request
	name := cl.Name
	if utf8.RuneCountInString(name) > 64 {
		name = string([]rune(name)[:64])
	}
	c, _ := ctx.Value(clientKey{}).(client)
	ch, err := a.credentials.BeginBackchannel(ctx, a.realm.ID, r.UserID, port.BackchannelRequest{ClientName: name, BindingMessage: r.BindingMessage,
		Scopes: r.Scopes, ExpiresAt: r.ExpiresAt}, credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: requestID(ctx)})
	if err != nil {
		if !errors.Is(err, credential.ErrNoBackchannel) {
			a.deps.Logger.WarnContext(ctx, "ciba: could not reach the authentication device", "error", err)
		}
		return cibaChannelNone
	}
	if err := a.ciba.Attach(ctx, st.AuthReqID, provider.BackchannelChannel{Method: ch.Method, Ref: ch.Ref, State: ch.State}); err != nil {
		a.deps.Logger.WarnContext(ctx, "ciba: attach the authentication device", "error", err)
		return cibaChannelNone
	}
	return ch.Method
}

// withCIBAToken は token エンドポイントの CIBA の grant を op.Server の前で受ける（zitadel/oidc は CIBA を持たない）。
func (s *oidcServer) withCIBAToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.ParseForm() == nil && r.PostForm.Get("grant_type") == provider.GrantTypeCIBA {
			s.cibaToken(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cibaToken は CIBA の grant（CIBA Core 10、11）。承認されていれば認可コードの交換と同じトークンを発行する。
func (s *oidcServer) cibaToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cl, err := s.cibaClient(r, []string{s.endpoint(oidcToken), s.a.issuer})
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	id := r.PostForm.Get("auth_req_id")
	if id == "" {
		s.writeCIBAError(w, r, oidc.ErrInvalidRequest().WithDescription("auth_req_id is required"))
		return
	}
	// 送信者制約（ADR 0113）。証明の誤りでポーリングの間隔を数えないよう、Poll の前に確かめる。
	b, err := s.tokenBinding(ctx, r.Method, r.URL.Path, r.Header, cl)
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	c, req, err := s.a.ciba.Poll(ctx, s.a.realm.ID, cl.PublicID, id)
	if errors.Is(err, provider.ErrDevicePending) && req.Channel != nil {
		// 端末の応答が届いていて、記録に失敗していた（届く前に Attach が終わっていなかったなど）ときに拾う。
		s.a.resolveBackchannel(ctx, req)
		c, err = s.a.ciba.Retake(ctx, s.a.realm.ID, cl.PublicID, id)
	}
	switch {
	case errors.Is(err, provider.ErrDevicePending):
		err = oidc.ErrAuthorizationPending()
	case errors.Is(err, provider.ErrDeviceSlowDown):
		err = oidc.ErrSlowDown()
	case errors.Is(err, provider.ErrDeviceDenied):
		err = oidc.ErrAccessDenied()
	case errors.Is(err, provider.ErrDeviceExpired):
		err = oidc.ErrExpiredDeviceCode()
	case errors.Is(err, provider.ErrInvalidGrant):
		err = oidc.ErrInvalidGrant()
	}
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	var out provider.Issued
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Exchange(ctx, tx, cl, c, b, requestID(ctx))
		return err
	})
	if errors.Is(err, provider.ErrInvalidGrant) {
		err = oidc.ErrInvalidGrant()
	}
	if err != nil {
		s.writeCIBAError(w, r, err)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, &oidc.AccessTokenResponse{AccessToken: out.AccessToken, TokenType: tokenType(out.Binding), RefreshToken: out.RefreshToken,
		ExpiresIn: uint64(out.ExpiresIn / time.Second), IDToken: out.IDToken, Scope: out.Scopes}) // #nosec G115 -- ExpiresIn は設定の正の寿命
}

// backchannelAnswered は本人の端末が CIBA のチャレンジに答えたときに呼ばれる（credential.Service.OnBackchannel）。
func (a *App) backchannelAnswered(ctx context.Context, realmID, method, ref string) {
	if a.ciba == nil || realmID != a.realm.ID {
		return
	}
	req, err := a.ciba.ByRef(ctx, realmID, method, ref)
	if err != nil {
		if !errors.Is(err, provider.ErrBackchannelRequest) {
			a.deps.Logger.WarnContext(ctx, "ciba: look up the answered request", "error", err)
		}
		return
	}
	a.resolveBackchannel(ctx, req)
}

// resolveBackchannel は本人の端末の応答を取り出し、要求に判断を記録する。承認なら CIBA 用のセッション（ブラウザに渡さない。
// ログインの系列にするだけ）を発行する。届いていなければ何もしない。取り出した後の失敗は拒否として記録する（fail-closed）。
func (a *App) resolveBackchannel(ctx context.Context, req provider.BackchannelRequest) {
	if req.Channel == nil {
		return
	}
	cred, amr, err := a.credentials.CompleteBackchannel(ctx, a.realm.ID, req.UserID,
		credential.Backchannel{Method: req.Channel.Method, Ref: req.Channel.Ref, State: req.Channel.State})
	if errors.Is(err, port.ErrMethodPending) {
		return
	}
	actor, _ := a.userActor(ctx, req.UserID)
	if err != nil {
		reason := "denied"
		if !errors.Is(err, credential.ErrAuthFailed) {
			a.deps.Logger.ErrorContext(ctx, "ciba: complete the authentication device", "error", err)
			reason = "error"
		}
		a.decideBackchannel(ctx, req, nil, cibaChannelPush, reason, actor, "")
		return
	}
	var selected string
	if a.acrActive() {
		v, ok := acr.Select(req.ACR, amr)
		if !ok {
			a.decideBackchannel(ctx, req, nil, cibaChannelPush, "unmet_authentication_requirements", actor, "")
			return
		}
		selected = v
	}
	var is session.Issued
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		is, err = a.sessions.Issue(ctx, tx, session.Issue{RealmID: a.realm.ID, UserID: req.UserID, AuthMethods: amr, Credentials: []string{cred.ID},
			UserAgent: "ciba " + req.ClientID, RequestID: requestID(ctx), Backchannel: true})
		return err
	})
	if err == nil && is.Session.Restriction != port.RestrictionNone {
		err = errs.New(errs.KindPermissionDenied, "restricted session")
	}
	if err != nil {
		reason := "policy"
		if _, ok := errors.AsType[errs.Denial](err); !ok && !errors.Is(err, errs.PermissionDenied) {
			a.deps.Logger.ErrorContext(ctx, "ciba: issue the backchannel session", "error", err)
			reason = "error"
		}
		a.decideBackchannel(ctx, req, nil, cibaChannelPush, reason, actor, "")
		return
	}
	a.sessions.Committed(ctx, a.realm.ID, is)
	s := is.Session
	code := &provider.Code{UserID: req.UserID, OrgID: s.ActiveOrgID, SID: s.SID, AuthTime: s.AuthenticatedAt, AMR: s.AuthMethods, SelectedACR: selected}
	if !a.decideBackchannel(ctx, req, code, cibaChannelPush, "", actor, s.ID) {
		// 先に本人の API で判断していた。作ったセッションは使わない。
		if err := a.sessions.Revoke(ctx, a.realm.ID, s.ID, req.UserID, session.ReasonLogout, actor, requestID(ctx)); err != nil {
			a.deps.Logger.WarnContext(ctx, "ciba: revoke the unused backchannel session", "error", err)
		}
	}
}

// userActor は本人の監査ログの主体（公開 ID）。
func (a *App) userActor(ctx context.Context, userID string) (audit.Actor, error) {
	var actor audit.Actor
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, a.realm.ID, userID)
		actor = audit.Actor{Type: "user", ID: u.PublicID}
		return err
	})
	return actor, err
}

// decideBackchannel は判断を記録し、監査ログに残し、ping の連携先に通知する。先に判断があれば何もせず false。
func (a *App) decideBackchannel(ctx context.Context, req provider.BackchannelRequest, code *provider.Code, channel, reason string, actor audit.Actor, sessionID string) bool {
	if _, err := a.ciba.Decide(ctx, a.realm.ID, req.ID, code); err != nil {
		if !errors.Is(err, provider.ErrBackchannelRequest) {
			a.deps.Logger.ErrorContext(ctx, "ciba: record the decision", "error", err)
		}
		return false
	}
	typ, result := "oidc.ciba_denied", audit.ResultFailure
	if code != nil {
		typ, result = "oidc.ciba_approved", audit.ResultSuccess
	}
	details := map[string]any{"client_id": req.ClientID, "scopes": req.Scopes, "channel": channel}
	if reason != "" {
		details["reason"] = reason
	}
	a.recordCIBAIn(ctx, typ, result, actor, sessionID, details)
	if req.Mode == port.CIBAPing {
		go a.notifyBackchannel(context.WithoutCancel(ctx), req)
	}
	return true
}

func (a *App) recordCIBA(ctx context.Context, typ string, result audit.Result, actor audit.Actor, details map[string]any) {
	a.recordCIBAIn(ctx, typ, result, actor, "", details)
}

func (a *App) recordCIBAIn(ctx context.Context, typ string, result audit.Result, actor audit.Actor, sessionID string, details map[string]any) {
	c, _ := ctx.Value(clientKey{}).(client)
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{Type: typ, Result: result, RealmID: a.realm.ID, Actor: actor,
			SessionID: sessionID, IP: c.IP, UserAgent: c.UserAgent, RequestID: requestID(ctx), Details: details})
		return err
	})
	if err != nil {
		a.deps.Logger.ErrorContext(ctx, "ciba: record audit event", "type", typ, "error", err)
	}
}

// notifyBackchannel は ping の連携先に、判断が出たことを知らせる（CIBA Core 10.2）。1 回だけ送り、届かなくても連携先は
// ポーリングできる。送り先は今の登録（変わっていれば新しい方、外されていれば送らない）。
func (a *App) notifyBackchannel(ctx context.Context, req provider.BackchannelRequest) {
	var cl port.Client
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		cl, err = tx.Clients().GetByPublicID(ctx, a.realm.ID, req.ClientID)
		return err
	})
	if err != nil || cl.CIBAMode != port.CIBAPing || cl.CIBANotificationEndpoint == "" || req.AuthReqID == "" {
		if err != nil && !errors.Is(err, errs.NotFound) {
			a.deps.Logger.WarnContext(ctx, "ciba: load the client to notify", "error", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, cibaNotifyTimeout)
	defer cancel()
	body, err := json.Marshal(map[string]string{"auth_req_id": req.AuthReqID})
	if err != nil {
		return
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.CIBANotificationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		a.deps.Logger.WarnContext(ctx, "ciba: build the notification", "error", err)
		return
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+req.NotificationToken)
	hc := a.cibaHTTP
	if hc == nil {
		hc = &http.Client{Timeout: cibaNotifyTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(hr) // #nosec G704 -- 送り先は運営者が登録した backchannel_client_notification_endpoint
	if err != nil {
		a.deps.Logger.InfoContext(ctx, "ciba: notification failed", "client_id", req.ClientID, "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		a.deps.Logger.InfoContext(ctx, "ciba: notification rejected", "client_id", req.ClientID, "status", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 本人の API

func (s publicServer) backchannelView(ctx context.Context, rs []provider.BackchannelRequest) ([]publicapi.BackchannelRequest, error) {
	names := map[string]string{}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		for _, r := range rs {
			if _, ok := names[r.ClientID]; ok {
				continue
			}
			cl, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, r.ClientID)
			if errors.Is(err, errs.NotFound) {
				continue
			}
			if err != nil {
				return err
			}
			names[r.ClientID] = cl.Name
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]publicapi.BackchannelRequest, 0, len(rs))
	for _, r := range rs {
		name, ok := names[r.ClientID]
		if !ok {
			continue // 連携先が消えた要求は見せない（承認しても使えない）。
		}
		v := publicapi.BackchannelRequest{Id: r.ID, ClientId: r.ClientID, ClientName: name, Scopes: r.Scopes, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
		if v.Scopes == nil {
			v.Scopes = []string{}
		}
		if r.BindingMessage != "" {
			m := r.BindingMessage
			v.BindingMessage = &m
		}
		out = append(out, v)
	}
	return out, nil
}

func (s publicServer) ListMyBackchannelRequests(ctx context.Context, _ publicapi.ListMyBackchannelRequestsRequestObject) (publicapi.ListMyBackchannelRequestsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyBackchannelRequests401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.ciba == nil {
		return publicapi.ListMyBackchannelRequests404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	rs, err := s.a.ciba.Pending(ctx, s.a.realm.ID, au.PrincipalID)
	if err != nil {
		return nil, err
	}
	out, err := s.backchannelView(ctx, rs)
	if err != nil {
		return nil, err
	}
	return publicapi.ListMyBackchannelRequests200JSONResponse{BackchannelRequests: out}, nil
}

func (s publicServer) ApproveMyBackchannelRequest(ctx context.Context, req publicapi.ApproveMyBackchannelRequestRequestObject) (publicapi.ApproveMyBackchannelRequestResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ApproveMyBackchannelRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.ciba == nil {
		return publicapi.ApproveMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	r, err := s.myBackchannel(ctx, au, req.Id)
	if errors.Is(err, provider.ErrBackchannelRequest) {
		return publicapi.ApproveMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	// active な Org が使えないセッション・要求の acr を満たさないセッションでは承認にしない（拒否として記録する）。
	var reason, selected string
	if len(au.OrgUnavailable) > 0 {
		reason = "org_unavailable"
	} else if s.a.acrActive() {
		v, ok := acr.Select(r.ACR, au.AuthMethods)
		if !ok {
			reason = "unmet_authentication_requirements"
		}
		selected = v
	}
	var code *provider.Code
	if reason == "" {
		code = &provider.Code{UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID, AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods, SelectedACR: selected}
	}
	if !s.a.decideBackchannel(ctx, r, code, cibaChannelSelf, reason, au.Actor(), au.SID) {
		return publicapi.ApproveMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if reason != "" {
		return publicapi.ApproveMyBackchannelRequest403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse{Error: reason}}, nil
	}
	return publicapi.ApproveMyBackchannelRequest204Response{}, nil
}

func (s publicServer) DenyMyBackchannelRequest(ctx context.Context, req publicapi.DenyMyBackchannelRequestRequestObject) (publicapi.DenyMyBackchannelRequestResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.DenyMyBackchannelRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.ciba == nil {
		return publicapi.DenyMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	r, err := s.myBackchannel(ctx, au, req.Id)
	if errors.Is(err, provider.ErrBackchannelRequest) {
		return publicapi.DenyMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	if !s.a.decideBackchannel(ctx, r, nil, cibaChannelSelf, "denied", au.Actor(), au.SID) {
		return publicapi.DenyMyBackchannelRequest404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	return publicapi.DenyMyBackchannelRequest204Response{}, nil
}

// myBackchannel は本人宛ての未決の要求を返す。連携先が消えたか CIBA の登録を外した要求も ErrBackchannelRequest。
func (s publicServer) myBackchannel(ctx context.Context, au auth, id string) (provider.BackchannelRequest, error) {
	r, err := s.a.ciba.Get(ctx, s.a.realm.ID, au.PrincipalID, id)
	if err != nil {
		return r, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cl, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, r.ClientID)
		if errors.Is(err, errs.NotFound) || (err == nil && cl.CIBAMode == "") {
			return provider.ErrBackchannelRequest
		}
		return err
	})
	return r, err
}
