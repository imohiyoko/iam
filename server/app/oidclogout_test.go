package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/port"
)

// bclReceiver は Back-Channel Logout を受ける試験用の連携先。
type bclReceiver struct {
	mu     sync.Mutex
	tokens []string
	status int
}

func (b *bclReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if b.status != 0 {
		w.WriteHeader(b.status)
		return
	}
	b.tokens = append(b.tokens, r.PostFormValue("logout_token"))
	w.WriteHeader(http.StatusOK)
}

func (b *bclReceiver) take() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.tokens
	b.tokens = nil
	return out
}

func (l *loginEnv) flushLogout(t *testing.T) {
	t.Helper()
	if _, err := l.a.logout.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCBackchannelLogout(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	recv := &bclReceiver{}
	srv := httptest.NewServer(recv)
	defer srv.Close()
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "backchannel_logout_uri": srv.URL + "/bcl"})
	quiet := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if !strings.Contains(w.Body.String(), `"backchannel_logout_supported":true`) || !strings.Contains(w.Body.String(), `"backchannel_logout_session_supported":true`) {
		t.Fatalf("discovery: %s", w.Body)
	}

	code, cookie := p.login(t, "alice@example.com", nil)
	_, tok := p.exchange(t, code, nil)
	sid := l.idClaims(t, tok["id_token"].(string), port.AlgES256)["sid"]
	// 同じログインの系列で別の連携先にも入る。
	_, qt := quiet.exchange(t, quiet.code(t, l.oidcDo(t, "GET", quiet.authorizeURL(nil), nil, cookie)), nil)

	// ID の入れ替えでは系列は終わらない。
	l.advance(l.a.cfg.Security.Session.RotationInterval.D() + time.Second)
	w = l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			cookie = c.Value
		}
	}
	l.advance(l.a.cfg.Security.Session.RotationGrace.D() + time.Second)
	l.flushLogout(t)
	if got := recv.take(); len(got) != 0 {
		t.Fatalf("logout on rotation: %d", len(got))
	}

	// ログアウトで、その系列に入った連携先のうち送り先を登録したものに Logout Token を送る。
	if code, _ := l.meDo(t, "POST", cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	l.flushLogout(t)
	got := recv.take()
	if len(got) != 1 {
		t.Fatalf("logout tokens: %d", len(got))
	}
	header, _, _ := strings.Cut(got[0], ".")
	if h, _ := base64.RawURLEncoding.DecodeString(header); !strings.Contains(string(h), `"typ":"logout+jwt"`) {
		t.Fatalf("header: %s", h)
	}
	claims := l.idClaims(t, got[0], port.AlgES256)
	alice := l.userID(t, "alice@example.com")
	events, _ := claims["events"].(map[string]any)
	if claims["iss"] != testIssuer || claims["aud"] != p.clientID || claims["sub"] != alice || claims["sid"] != sid || claims["jti"] == nil ||
		claims["nonce"] != nil || events == nil || events["http://schemas.openid.net/event/backchannel-logout"] == nil {
		t.Fatalf("logout token: %v", claims)
	}
	// 系列の認可は失効する（どちらの連携先も）。2度は送らない。
	if in := quiet.introspect(t, qt["refresh_token"].(string)); in["active"] != false {
		t.Fatalf("grant after logout: %v", in)
	}
	l.flushLogout(t)
	if got := recv.take(); len(got) != 0 {
		t.Fatalf("sent twice: %d", len(got))
	}

	// 今から効くユーザーの停止でも送る。停止が解けても認可は戻らない。
	code, _ = p.login(t, "alice@example.com", nil)
	_, tok = p.exchange(t, code, nil)
	// 運営者のセッションは直近の認証を求めるので、入り直す。
	_, owner = l.operator(t, "root2@example.com", role.RealmOwner)
	status, sp := l.admin(t, "/v1/admin/users/"+alice+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "x"})
	if status != 201 {
		t.Fatalf("suspend: %d %v", status, sp)
	}
	l.flushLogout(t)
	if got := recv.take(); len(got) != 1 {
		t.Fatalf("logout on suspension: %d", len(got))
	}
	if status, _ := l.admin(t, "/v1/admin/suspensions/"+sp["id"].(string)+":lift", owner, map[string]string{"reason": "x"}); status != 200 {
		t.Fatalf("lift: %d", status)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["active"] != false {
		t.Fatalf("grant after lift: %v", in)
	}

	// 予約した停止は始まりの時刻に送る。
	code, _ = p.login(t, "alice@example.com", nil)
	_, _ = p.exchange(t, code, nil)
	if status, _ := l.admin(t, "/v1/admin/users/"+alice+"/suspensions", owner,
		map[string]any{"category": "tos_violation", "reason": "x", "starts_at": l.a.deps.Clock.Now().Add(time.Hour)}); status != 201 {
		t.Fatalf("schedule suspension: %d", status)
	}
	l.flushLogout(t)
	if got := recv.take(); len(got) != 0 {
		t.Fatalf("sent before start: %d", len(got))
	}
	l.advance(time.Hour)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	l.flushLogout(t)
	if got := recv.take(); len(got) != 1 {
		t.Fatalf("logout at suspension start: %d", len(got))
	}

	// 送れなければ次の送出でまた送り、GiveUp を過ぎたらあきらめる。
	code, cookie = p.login(t, "bob@example.com", nil)
	_, _ = p.exchange(t, code, nil)
	recv.mu.Lock()
	recv.status = http.StatusInternalServerError
	recv.mu.Unlock()
	if code, _ := l.meDo(t, "POST", cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	for range 2 {
		l.flushLogout(t)
		if n := l.pendingLogout(t); n != 1 {
			t.Fatalf("pending after failure: %d", n)
		}
	}
	l.advance(provider.DefaultLogoutGiveUp)
	l.flushLogout(t)
	if n := l.pendingLogout(t); n != 0 {
		t.Fatalf("pending after give up: %d", n)
	}

	if strings.Contains(l.out.String(), l.internalUserID(t, alice)) {
		t.Fatal("internal user id leaked")
	}
}

func (l *loginEnv) pendingLogout(t *testing.T) int {
	t.Helper()
	var n int
	err := l.a.deps.Storage.Tx(t.Context(), func(ctx context.Context, tx port.Tx) error {
		ms, err := tx.Outbox().Pending(ctx, provider.LogoutTopic, 100)
		n = len(ms)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOIDCCORSAndCSRF(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	spa := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []string{"https://spa.example.com/cb"}})
	l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://web.example.com/cb"}})
	preflight := func(path, origin string) *httptest.ResponseRecorder {
		return l.oidcDo(t, "OPTIONS", path, nil, "", "Origin", origin, "Access-Control-Request-Method", "POST")
	}

	// 公開クライアントの戻り先のオリジンには token・userinfo・revoke を許す。Cookie は送らせない。
	for _, path := range []string{oidcToken, oidcUserinfo, oidcRevoke} {
		w := preflight(path, "https://spa.example.com")
		if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://spa.example.com" ||
			w.Header().Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
			t.Fatalf("%s preflight: %d %v", path, w.Code, w.Header())
		}
	}
	// 機密の連携先・知らないオリジン・introspect・authorize には付けない。
	for _, c := range []struct{ path, origin string }{
		{oidcToken, "https://web.example.com"}, {oidcToken, "https://evil.example.com"},
		{oidcIntrospect, "https://spa.example.com"}, {oidcAuthorize, "https://spa.example.com"},
	} {
		if w := preflight(c.path, c.origin); w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s from %s: %v", c.path, c.origin, w.Header())
		}
	}
	// Discovery と JWKS はどのオリジンにも。
	if w := l.oidcDo(t, "GET", oidcKeys, nil, "", "Origin", "https://any.example.com"); w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("jwks: %d %v", w.Code, w.Header())
	}

	// SPA はブラウザから別オリジンで token を呼べる（CrossOriginProtection の外）。
	code, cookie := spa.login(t, "alice@example.com", nil)
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {spa.redirect}, "code_verifier": {spa.verifier},
		"client_id": {spa.clientID}}
	w := l.oidcDo(t, "POST", oidcToken, f, "", "Origin", "https://spa.example.com", "Sec-Fetch-Site", "cross-site")
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "https://spa.example.com" {
		t.Fatalf("cross-origin token: %d %v %s", w.Code, w.Header(), w.Body)
	}
	// Cookie のセッションで書き込む公開 API は、別オリジンからは拒む。
	if w := l.oidcDo(t, "POST", "/v1/logout", nil, cookie, "Origin", "https://spa.example.com", "Sec-Fetch-Site", "cross-site"); w.Code != 403 {
		t.Fatalf("cross-origin logout: %d", w.Code)
	}
	if w := l.oidcDo(t, "POST", "/v1/logout", nil, cookie, "Sec-Fetch-Site", "same-origin"); w.Code != 204 {
		t.Fatalf("same-origin logout: %d", w.Code)
	}
}

// 認可が期限切れでも、系列が終われば連携先に送る（連携先のログインは認可の期限とは別に残りうる）。
func TestOIDCBackchannelLogoutAfterGrantExpiry(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		c.OIDC.RefreshTokenTTL = config.Duration(time.Hour)
	}, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	recv := &bclReceiver{}
	srv := httptest.NewServer(recv)
	defer srv.Close()
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "backchannel_logout_uri": srv.URL + "/bcl"})
	code, cookie := p.login(t, "alice@example.com", nil)
	_, _ = p.exchange(t, code, nil)
	l.advance(2 * time.Hour)
	if code, _ := l.meDo(t, "POST", cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	l.flushLogout(t)
	if got := recv.take(); len(got) != 1 {
		t.Fatalf("logout tokens after grant expiry: %d", len(got))
	}
}
