package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Device Authorization Grant（RFC 8628、ADR 0095。フィーチャー device_flow）。
//
//	POST /oauth2/device_authorization  端末が device_code と user_code を受け取る（連携先の認証は token と同じ。公開クライアントも可）
//	GET  /oauth2/device                本人が user_code を入れる画面。ログインしていなければログイン画面へ。
//	                                   user_code があれば連携先の名前とスコープを見せ、承認か拒否を選ばせる
//	POST /oauth2/device                承認・拒否（user_code は1回だけ使える）
//	POST /oauth2/token                 grant_type=urn:ietf:params:oauth:grant-type:device_code でポーリング

// DeviceAuthorization は端末の要求を受け、device_code と user_code を返す（RFC 8628 3.1、3.2）。
func (s *oidcServer) DeviceAuthorization(ctx context.Context, r *op.ClientRequest[oidc.DeviceAuthorizationRequest]) (*op.Response, error) {
	cl := r.Client.(opClient)
	if !cl.device {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("the device authorization grant is not allowed for this client")
	}
	// 未認証の公開クライアントからも呼べるので、接続元ごとに数える（user_code の空きを使い切らせない）。
	c, _ := ctx.Value(clientKey{}).(client)
	err := s.a.perIP.Allow(ctx, "device:ip:"+s.a.realm.ID+":"+ratelimit.Bucket(c.IP))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		if ex.First {
			s.a.recordRateLimit(ctx, "ip", oidcDeviceAuth)
		}
		return nil, op.NewStatusError(oidc.ErrInvalidRequest().WithDescription("too many requests"), http.StatusTooManyRequests)
	}
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	if !slices.Contains(r.Data.Scopes, provider.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	req := provider.DeviceRequest{RealmID: s.a.realm.ID, ClientID: cl.c.PublicID}
	for _, sc := range r.Data.Scopes {
		if slices.Contains(s.scopes(), sc) && !slices.Contains(req.Scopes, sc) {
			req.Scopes = append(req.Scopes, sc)
		}
	}
	st, err := s.a.device.Start(ctx, req)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	verify := s.endpoint(oidcDevice)
	resp := op.NewResponse(&oidc.DeviceAuthorizationResponse{DeviceCode: st.DeviceCode, UserCode: st.UserCode, VerificationURI: verify,
		VerificationURIComplete: verify + "?" + url.Values{"user_code": {st.UserCode}}.Encode(),
		ExpiresIn:               int(st.ExpiresIn / time.Second), Interval: int(st.Interval / time.Second)})
	resp.Header.Set("Pragma", "no-cache")
	return resp, nil
}

// DeviceToken は端末のポーリングに答える（RFC 8628 3.4、3.5）。承認されていれば、認可コードの交換と同じトークンを発行する。
// grant_type を許していない連携先は、op が unauthorized_client で拒む（opClient.GrantTypes）。
func (s *oidcServer) DeviceToken(ctx context.Context, r *op.ClientRequest[oidc.DeviceAccessTokenRequest]) (*op.Response, error) {
	cl := r.Client.(opClient)
	if s.a.device == nil {
		return nil, oidc.ErrUnsupportedGrantType()
	}
	if !cl.device {
		return nil, oidc.ErrUnauthorizedClient()
	}
	// 証明は Poll の前に確かめる。Poll は承認済みの結果を1回で消費するため、後で use_dpop_nonce を返すと nonce 付きの再試行が通らない。
	b, err := s.tokenBinding(ctx, r.Method, r.URL.Path, r.Header, cl.c)
	if err != nil {
		return nil, err
	}
	c, err := s.a.device.Poll(ctx, s.a.realm.ID, cl.c.PublicID, r.Data.DeviceCode)
	switch {
	case errors.Is(err, provider.ErrDevicePending):
		return nil, oidc.ErrAuthorizationPending()
	case errors.Is(err, provider.ErrDeviceSlowDown):
		return nil, oidc.ErrSlowDown()
	case errors.Is(err, provider.ErrDeviceDenied):
		return nil, oidc.ErrAccessDenied()
	case errors.Is(err, provider.ErrDeviceExpired):
		return nil, oidc.ErrExpiredDeviceCode()
	case errors.Is(err, provider.ErrInvalidGrant):
		return nil, oidc.ErrInvalidGrant()
	case err != nil:
		return nil, s.fail(ctx, err)
	}
	var out provider.Issued
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.Exchange(ctx, tx, cl.c, c, b, requestID(ctx))
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

// 承認の画面。

// deviceTexts は承認の画面の文言。
type deviceTexts struct {
	Title, Enter, Code, Continue, Confirm, Requests, Scopes, Warning, Approve, Deny, Approved, Denied, Invalid, RateLimited, OrgUnavailable string
}

var deviceCatalog = map[string]deviceTexts{
	"en": {
		Title: "Connect a device", Enter: "Enter the code shown on your device.", Code: "Code", Continue: "Continue",
		Confirm: "Confirm the code below matches the one shown on your device.", Requests: "wants to sign in to your account.",
		Scopes: "Requested access", Warning: "Only continue if you started this sign-in on your own device. Never enter a code someone else gave you.",
		Approve: "Allow", Deny: "Deny", Approved: "Your device is now signed in. You can close this window.",
		Denied: "The request was denied. You can close this window.", Invalid: "The code is invalid or has expired. Check the code on your device.",
		RateLimited: "Too many attempts. Please wait and try again.", OrgUnavailable: "Your current organization cannot be used. The request was denied.",
	},
	"ja": {
		Title: "端末の接続", Enter: "端末に表示されたコードを入力してください。", Code: "コード", Continue: "次へ",
		Confirm: "下のコードが端末に表示されたものと同じかを確かめてください。", Requests: "があなたのアカウントでのログインを求めています。",
		Scopes: "求められている権限", Warning: "このログインを自分の端末で始めたときだけ続けてください。他の人から伝えられたコードは入力しないでください。",
		Approve: "許可する", Deny: "拒否する", Approved: "端末でログインしました。この画面は閉じてかまいません。",
		Denied: "拒否しました。この画面は閉じてかまいません。", Invalid: "コードが正しくないか、期限が切れています。端末のコードを確かめてください。",
		RateLimited: "試行が多すぎます。しばらく待ってからお試しください。", OrgUnavailable: "今の Org は使えません。要求を拒否しました。",
	},
}

type devicePage struct {
	Lang, Base, Action string
	// Step は enter（コードの入力）・confirm（承認の確認）・approved・denied のどれか。
	Step, Error      string
	UserCode, Client string
	Scopes           []string
	T                deviceTexts
}

// deviceTemplate は承認の画面のテンプレートを読む。dir（server.login_templates）に device.html があれば差し替える。
func deviceTemplate(dir string) (*template.Template, error) {
	var (
		src []byte
		err error
	)
	if dir != "" {
		src, err = os.ReadFile(filepath.Join(dir, "device.html")) // #nosec G304 -- テンプレートの場所は運用者が設定する
		if errors.Is(err, fs.ErrNotExist) {
			src, err = nil, nil
		}
	}
	if err == nil && src == nil {
		src, err = fs.ReadFile(webFS, "web/device.html")
	}
	if err != nil {
		return nil, fmt.Errorf("device page: %w", err)
	}
	t, err := template.New("device").Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("device page template: %w", err)
	}
	// 起動時に一度描いて、差し替えたテンプレートの誤りを起動時に見つける。
	if err := t.Execute(&bytes.Buffer{}, devicePage{Lang: "en", Step: "confirm", UserCode: "BCDF-GHJK", Client: "x", Scopes: []string{"openid"},
		T: deviceCatalog["en"]}); err != nil {
		return nil, fmt.Errorf("device page template: %w", err)
	}
	return t, nil
}

func (s *oidcServer) renderDevice(w http.ResponseWriter, r *http.Request, status int, p devicePage) {
	l := lang(r)
	p.Lang, p.T, p.Base, p.Action = l, deviceCatalog[l], s.a.base, s.a.base+oidcDevice
	var buf bytes.Buffer
	if err := s.a.deviceTmpl.Execute(&buf, p); err != nil {
		s.a.deps.Logger.ErrorContext(r.Context(), "device page: render", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", hostedCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// deviceLoginURL はログイン画面の URL。ログインの後で承認の画面（user_code を持ったまま）に戻る。
func (a *App) deviceLoginURL(userCode string) string {
	back := a.base + oidcDevice
	if userCode != "" {
		back += "?" + url.Values{"user_code": {userCode}}.Encode()
	}
	return a.base + "/login?" + url.Values{"return_to": {back}}.Encode()
}

// deviceVerify は承認の画面。ログインしたブラウザでだけ user_code を照合し、連携先の名前とスコープを見せてから、
// 本人の操作（POST）で承認か拒否を記録する（フィッシングの対策。user_code だけでは承認しない）。
func (s *oidcServer) deviceVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userCode := r.FormValue("user_code")
	if code, ok := provider.NormalizeUserCode(userCode); ok {
		userCode = provider.FormatUserCode(code)
	} else if len(userCode) > 32 {
		userCode = ""
	}
	ctx := r.Context()
	au, ok := authFrom(ctx)
	if !ok {
		http.Redirect(w, r, s.a.deviceLoginURL(userCode), http.StatusSeeOther)
		return
	}
	if userCode == "" {
		s.renderDevice(w, r, http.StatusOK, devicePage{Step: "enter"})
		return
	}
	// user_code の総当たりを防ぐため、照合は本人ごと（接続元ごとと合計）と接続元ごとに数える。
	c, _ := ctx.Value(clientKey{}).(client)
	if err := s.a.allowUserCode(ctx, au.PrincipalID, c.IP); err != nil {
		if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			w.Header().Set("Retry-After", fmt.Sprint(retryAfter(ex)))
			s.renderDevice(w, r, http.StatusTooManyRequests, devicePage{Step: "enter", UserCode: userCode, Error: "rate_limited"})
			return
		}
		s.a.unavailable(w, r, err)
		return
	}
	req, cl, err := s.deviceRequest(ctx, userCode)
	if errors.Is(err, provider.ErrUserCode) {
		s.renderDevice(w, r, http.StatusBadRequest, devicePage{Step: "enter", UserCode: userCode, Error: "invalid"})
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	if r.Method == http.MethodGet {
		s.renderDevice(w, r, http.StatusOK, devicePage{Step: "confirm", UserCode: userCode, Client: cl.Name, Scopes: req.Scopes})
		return
	}
	action := r.PostFormValue("action")
	if action != "approve" && action != "deny" {
		s.renderDevice(w, r, http.StatusBadRequest, devicePage{Step: "confirm", UserCode: userCode, Client: cl.Name, Scopes: req.Scopes})
		return
	}
	approve := action == "approve"
	// active な Org が使えない（停止・有効期間の外など）セッションでは連携先に入れない（4.7。認可要求と同じ）。
	orgUnavailable := approve && len(au.OrgUnavailable) > 0
	var code *provider.Code
	if approve && !orgUnavailable {
		code = &provider.Code{UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID, AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods}
	}
	if _, err := s.a.device.Decide(ctx, s.a.realm.ID, userCode, code); errors.Is(err, provider.ErrUserCode) {
		s.renderDevice(w, r, http.StatusBadRequest, devicePage{Step: "enter", Error: "invalid"})
		return
	} else if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	typ, step := "oidc.device_denied", "denied"
	if code != nil {
		typ, step = "oidc.device_approved", "approved"
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
			Actor: au.Actor(), SessionID: au.SID, IP: c.IP, UserAgent: c.UserAgent, RequestID: requestID(ctx),
			Details: map[string]any{"client_id": cl.PublicID, "scopes": req.Scopes}})
		return err
	})
	if err != nil {
		s.a.deps.Logger.ErrorContext(ctx, "device: record decision", "error", err)
	}
	p := devicePage{Step: step}
	if orgUnavailable {
		p.Error = "org_unavailable"
	}
	s.renderDevice(w, r, http.StatusOK, p)
}

// deviceRequest は user_code の端末の要求と、その連携先を返す。連携先が消えた・許可を外した要求は ErrUserCode。
func (s *oidcServer) deviceRequest(ctx context.Context, userCode string) (provider.DeviceRequest, port.Client, error) {
	req, err := s.a.device.Lookup(ctx, s.a.realm.ID, userCode)
	if err != nil {
		return req, port.Client{}, err
	}
	cl, err := s.client(ctx, req.ClientID)
	if errors.Is(err, errs.NotFound) || (err == nil && !cl.DeviceGrant) {
		return req, port.Client{}, provider.ErrUserCode
	}
	return req, cl, err
}

// allowUserCode は user_code の照合の回数を数える（本人と接続元ごとに per_account、本人ごとに per_account_total、
// 接続元ごとに per_ip）。最初に超えたときは監査ログに残す。
func (a *App) allowUserCode(ctx context.Context, userID, ip string) error {
	err := a.accountLimiter().AllowFrom(ctx, "device-user:"+a.realm.ID+":"+userID, ip)
	scope := "account"
	if err == nil {
		err, scope = a.perIP.Allow(ctx, "device-code:ip:"+a.realm.ID+":"+ratelimit.Bucket(ip)), "ip"
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok && ex.First {
		a.recordRateLimit(ctx, scope, oidcDevice)
	}
	return err
}
