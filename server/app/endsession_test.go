package app

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// RP-Initiated Logout と Front-Channel Logout（ADR 0094）を HTTP で確かめる。

// withOIDCLogout は issuer を設定し、既定のフィーチャーに oidc_logout を足す。
func withOIDCLogout(c *config.Config) {
	withIssuer(c)
	var names []string
	for _, f := range feature.Registered() {
		if f.DefaultEnabled {
			names = append(names, f.Name)
		}
	}
	names = append(names, feature.OIDCLogout)
	c.Features = &names
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// logoutRequestID は確認の画面からフォームの request を取り出す。
func logoutRequestID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 200 || !strings.Contains(w.Body.String(), `data-page="confirm"`) {
		t.Fatalf("want confirm page, got %d %s", w.Code, w.Body)
	}
	m := requestField.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no request id: %s", w.Body)
	}
	return m[1]
}

// confirmLogout は確認の画面のフォームを送る（同じオリジンのブラウザから）。
func (l *loginEnv) confirmLogout(t *testing.T, rid, action, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	return l.oidcDo(t, "POST", oidcEndSessionConfirm, url.Values{"request": {rid}, "action": {action}}, cookie, "Sec-Fetch-Site", "same-origin")
}

// sessionAlive はセッションの Cookie がまだ使えるかを返す。
func (l *loginEnv) sessionAlive(t *testing.T, cookie string) bool {
	t.Helper()
	code, _ := l.meDo(t, "GET", cookie, "/v1/me/sessions", nil)
	return code == 200
}

func clearsCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestOIDCRPInitiatedLogout(t *testing.T) {
	l := newLoginEnvWith(t, withOIDCLogout, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	recv := &bclReceiver{}
	srv := httptest.NewServer(recv)
	defer srv.Close()
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "backchannel_logout_uri": srv.URL + "/bcl",
		"post_logout_redirect_uris": []string{"https://rp.example.com/bye"}, "frontchannel_logout_uri": "https://rp.example.com/fcl",
		"frontchannel_logout_session_required": true})
	q := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://q.example.com/cb"},
		"frontchannel_logout_uri": "https://q.example.com/fcl?x=1"})
	// 登録の応答に出る。戻り先と違うオリジンは登録できない。
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients", nil); code != 200 || !strings.Contains(mustJSON(out), `"frontchannel_logout_session_required":true`) {
		t.Fatalf("list clients: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "X", "redirect_uris": []string{"https://x.example.com/cb"},
		"token_endpoint_auth_method": "none", "frontchannel_logout_uri": "https://evil.example.com/fcl"}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("other origin: %d %v", code, out)
	}

	var disc map[string]any
	if w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, ""); json.Unmarshal(w.Body.Bytes(), &disc) != nil ||
		disc["end_session_endpoint"] != testIssuer+oidcEndSession || disc["frontchannel_logout_supported"] != true ||
		disc["frontchannel_logout_session_supported"] != true {
		t.Fatalf("discovery: %v", disc)
	}

	code, cookie := p.login(t, "alice@example.com", nil)
	_, tok := p.exchange(t, code, nil)
	hint := tok["id_token"].(string)
	sid := l.idClaims(t, hint, port.AlgES256)["sid"].(string)
	_, _ = q.exchange(t, q.code(t, l.oidcDo(t, "GET", q.authorizeURL(nil), nil, cookie)), nil)

	// 正しくない要求は、連携先に戻さずに画面で止め、ログアウトしない。
	for name, v := range map[string]url.Values{
		"unregistered redirect":   {"client_id": {p.clientID}, "post_logout_redirect_uri": {"https://rp.example.com/bye/x"}},
		"open redirect":           {"client_id": {p.clientID}, "post_logout_redirect_uri": {"https://evil.example.com/"}},
		"redirect without client": {"post_logout_redirect_uri": {"https://rp.example.com/bye"}},
		"other client's redirect": {"client_id": {q.clientID}, "post_logout_redirect_uri": {"https://rp.example.com/bye"}},
		"tampered hint":           {"id_token_hint": {hint[:len(hint)-4] + "AAAA"}},
		"client mismatch":         {"id_token_hint": {hint}, "client_id": {q.clientID}},
	} {
		w := l.oidcDo(t, "GET", oidcEndSession+"?"+v.Encode(), nil, cookie)
		if w.Code != 400 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), `data-page="error"`) {
			t.Fatalf("%s: %d %v %s", name, w.Code, w.Header(), w.Body)
		}
	}
	if !l.sessionAlive(t, cookie) {
		t.Fatal("logged out by an invalid request")
	}

	// id_token_hint が無ければ確かめる。ui_locales で言語を選ぶ。CSP は戻り先のオリジンだけをフォームの後の転送に許す。
	w := l.oidcDo(t, "GET", oidcEndSession+"?"+url.Values{"client_id": {p.clientID}, "post_logout_redirect_uri": {"https://rp.example.com/bye"},
		"state": {"st1"}, "ui_locales": {"fr ja-JP"}}.Encode(), nil, cookie)
	rid := logoutRequestID(t, w)
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://rp.example.com;") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(w.Body.String(), `lang="ja"`) || !strings.Contains(w.Body.String(), "RP") {
		t.Fatalf("confirm page: %s\n%s", csp, w.Body)
	}
	// 別のオリジンからの答えは受けない（CSRF）。
	if w := l.oidcDo(t, "POST", oidcEndSessionConfirm, url.Values{"request": {rid}, "action": {"logout"}}, cookie, "Sec-Fetch-Site", "cross-site"); w.Code != 403 {
		t.Fatalf("cross-site confirm: %d", w.Code)
	}
	// 断ればログインしたまま。要求は1回だけ使える。
	if w := l.oidcDo(t, "POST", oidcEndSessionConfirm, url.Values{"request": {rid}, "action": {"cancel"}, "ui_locales": {"ja"}}, cookie,
		"Sec-Fetch-Site", "same-origin"); w.Code != 200 || !strings.Contains(w.Body.String(), `data-page="cancelled"`) || !strings.Contains(w.Body.String(), `lang="ja"`) || clearsCookie(w) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	if w := l.confirmLogout(t, rid, "logout", cookie); w.Code != 400 || !l.sessionAlive(t, cookie) {
		t.Fatalf("reuse: %d %s", w.Code, w.Body)
	}
	// 別のセッションでは確認を通さない。
	w = l.oidcDo(t, "GET", oidcEndSession, nil, cookie)
	rid = logoutRequestID(t, w)
	_, bob := l.login(t, "bob@example.com")
	if w := l.confirmLogout(t, rid, "logout", bob); w.Code != 400 || !l.sessionAlive(t, bob) || !l.sessionAlive(t, cookie) {
		t.Fatalf("other session: %d %s", w.Code, w.Body)
	}

	// id_token_hint がセッションと合えば確かめずにログアウトする（期限切れの ID トークンでも）。完了の画面で、系列の連携先の
	// frontchannel_logout_uri を開き（session_required なら iss と sid）、JS で戻り先に移る。
	l.advance(2 * time.Hour)
	// ID の入れ替え（Cookie の差し替え）を済ませておく（入れ替え前の ID の猶予は POST /v1/logout と同じ扱い）。
	for _, c := range l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie).Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			cookie = c.Value
		}
	}
	l.advance(l.a.cfg.Security.Session.RotationGrace.D() + time.Second)
	w = l.oidcDo(t, "GET", oidcEndSession+"?"+url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://rp.example.com/bye"},
		"state": {"st2"}}.Encode(), nil, cookie)
	body := html.UnescapeString(w.Body.String())
	fcl := "https://rp.example.com/fcl?" + url.Values{"iss": {testIssuer}, "sid": {sid}}.Encode()
	if w.Code != 200 || !strings.Contains(body, `data-page="done"`) || !strings.Contains(body, `<iframe src="`+fcl+`"`) ||
		!strings.Contains(body, `<iframe src="https://q.example.com/fcl?x=1"`) || !strings.Contains(body, `data-redirect="https://rp.example.com/bye?state=st2"`) ||
		!strings.Contains(body, "/login/assets/logout.js") || !clearsCookie(w) {
		t.Fatalf("done page: %d %s", w.Code, body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src https://rp.example.com https://q.example.com;") ||
		!strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("done csp: %s", csp)
	}
	if l.sessionAlive(t, cookie) {
		t.Fatal("session alive after logout")
	}
	// Back-Channel Logout も送る（ADR 0066 の系列の終わり）。
	l.flushLogout(t)
	if got := recv.take(); len(got) != 1 || l.idClaims(t, got[0], port.AlgES256)["sid"] != sid {
		t.Fatalf("backchannel: %v", got)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["active"] != false {
		t.Fatalf("grant after logout: %v", in)
	}
	if w := l.oidcDo(t, "GET", "/login/assets/logout.js", nil, ""); w.Code != 200 {
		t.Fatalf("logout.js: %d", w.Code)
	}

	// ログインし直した新しい系列に古い id_token_hint は合わないので確かめる。開くものが無ければ、戻り先にすぐ転送する。
	_, cookie = l.login(t, "alice@example.com")
	w = l.oidcDo(t, "GET", oidcEndSession+"?"+url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://rp.example.com/bye"},
		"state": {"st3"}}.Encode(), nil, cookie)
	w = l.confirmLogout(t, logoutRequestID(t, w), "logout", cookie)
	if u := location(t, w); u.String() != "https://rp.example.com/bye?state=st3" || !clearsCookie(w) || l.sessionAlive(t, cookie) {
		t.Fatalf("confirmed logout: %s", u)
	}

	// ログインしていなければ、確かめずに戻す（終えた系列が無いので、連携先の iframe は開かない）。
	w = l.oidcDo(t, "POST", oidcEndSession, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://rp.example.com/bye"}}, "")
	if u := location(t, w); u.String() != "https://rp.example.com/bye" {
		t.Fatalf("logged out with hint: %s", u)
	}
	if u := location(t, l.oidcDo(t, "GET", oidcEndSession+"?"+url.Values{"client_id": {p.clientID}, "post_logout_redirect_uri": {"https://rp.example.com/bye"}}.Encode(), nil, "")); u.String() != "https://rp.example.com/bye" {
		t.Fatalf("logged out: %s", u)
	}
	if w := l.oidcDo(t, "GET", oidcEndSession, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `data-page="done"`) {
		t.Fatalf("no params: %d %s", w.Code, w.Body)
	}
	if w := l.oidcDo(t, "PUT", oidcEndSession, nil, ""); w.Code != 405 {
		t.Fatalf("PUT: %d", w.Code)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// 制限つきのセッション（2要素目の確認待ちなど）も、確かめてログアウトできる（POST /v1/logout と同じ）。
func TestOIDCRPInitiatedLogoutRestricted(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withOIDCLogout(c)
		c.Security.SecondFactor.Required = true
	}, feature.Registered())
	res, cookie := l.login(t, "alice@example.com")
	if res["next"] == nil {
		t.Fatalf("not restricted: %v", res)
	}
	w := l.oidcDo(t, "GET", oidcEndSession, nil, cookie)
	w = l.confirmLogout(t, logoutRequestID(t, w), "logout", cookie)
	if w.Code != 200 || !clearsCookie(w) {
		t.Fatalf("logout: %d %s", w.Code, w.Body)
	}
	if code, _ := l.meDo(t, "POST", cookie, "/v1/login/second-factor:verify", map[string]string{"totp_code": "000000"}); code != 401 {
		t.Fatalf("restricted session alive: %d", code)
	}
}

// フィーチャーが無ければ、エンドポイントも Discovery の項目も無く、Front-Channel Logout を登録できない。
func TestOIDCRPInitiatedLogoutOff(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if strings.Contains(w.Body.String(), "end_session_endpoint") || strings.Contains(w.Body.String(), "frontchannel") {
		t.Fatalf("discovery: %s", w.Body)
	}
	if w := l.oidcDo(t, "GET", oidcEndSession, nil, ""); w.Code != 404 {
		t.Fatalf("end_session: %d", w.Code)
	}
	if w := l.oidcDo(t, "GET", "/login/assets/logout.js", nil, ""); w.Code != 200 {
		t.Fatalf("asset: %d", w.Code)
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "X", "redirect_uris": []string{"https://x.example.com/cb"},
		"token_endpoint_auth_method": "none", "frontchannel_logout_uri": "https://x.example.com/fcl"}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("register: %d %v", code, out)
	}
}

// 無効化では連携先の Front-Channel Logout の登録を外す（post_logout_redirect_uris は残す）。
func TestDisableOIDCLogoutWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "post_logout_redirect_uris": []string{"https://rp.example.com/bye"},
		"frontchannel_logout_uri": "https://rp.example.com/fcl", "frontchannel_logout_session_required": true})
	l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	disableWithData(t, l, feature.OIDCLogout, 1)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Clients().GetByPublicID(ctx, l.a.realm.ID, p.clientID)
		if err != nil || c.FrontchannelLogoutURI != "" || c.FrontchannelLogoutSessionRequired || len(c.PostLogoutRedirectURIs) != 1 {
			t.Fatalf("client after purge = %+v, %v", c, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// 複数 realm（ADR 0083）：パスで指す realm でも、その realm の issuer・連携先・セッションで動き、別の realm の ID トークンは受けない。
func TestOIDCRPInitiatedLogoutMultiRealm(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = multiRealmURL
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.MultiRealm, feature.OIDCLogout)
		c.Features = &names
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	acme, _ := l.newRealm(t, owner, map[string]any{"slug": "acme", "name": "Acme"})
	ra, err := l.a.RealmApp("acme")
	if err != nil {
		t.Fatal(err)
	}
	var acmeClient string
	err = l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, _, err := ra.clients.Create(ctx, tx, ra.realm.ID, provider.ClientInput{Name: "Acme RP", RedirectURIs: []string{"https://acme-rp.example.com/cb"},
			PostLogoutRedirectURIs: []string{"https://acme-rp.example.com/bye"}, AuthMethod: port.ClientAuthNone}, audit.Actor{Type: "system"}, "")
		acmeClient = c.PublicID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "post_logout_redirect_uris": []string{"https://rp.example.com/bye"}})
	code, _ := p.login(t, "alice@example.com", nil)
	_, tok := p.exchange(t, code, nil)
	hint := tok["id_token"].(string)

	if w := acme.do(t, false, "GET", "/.well-known/openid-configuration", nil); decode(t, w)["end_session_endpoint"] != multiRealmURL+"/realms/acme"+oidcEndSession {
		t.Fatalf("acme discovery: %s", w.Body)
	}
	// 既定の realm の ID トークンと連携先は、acme では知らないもの。
	for _, q := range []url.Values{{"id_token_hint": {hint}}, {"client_id": {p.clientID}}} {
		if w := acme.do(t, false, "GET", oidcEndSession+"?"+q.Encode(), nil); w.Code != 400 {
			t.Fatalf("foreign %v: %d %s", q, w.Code, w.Body)
		}
	}
	if w := l.oidcDo(t, "GET", oidcEndSession+"?"+url.Values{"client_id": {acmeClient}}.Encode(), nil, ""); w.Code != 400 {
		t.Fatalf("acme client in default realm: %d", w.Code)
	}

	_, cookie := acme.login(t, "alice@acme.example")
	q := url.Values{"client_id": {acmeClient}, "post_logout_redirect_uri": {"https://acme-rp.example.com/bye"}, "state": {"s"}}
	w := acme.do(t, false, "GET", oidcEndSession+"?"+q.Encode(), nil, "Cookie", acme.cookieName+"="+cookie)
	rid := logoutRequestID(t, w)
	if !strings.Contains(w.Body.String(), `action="/realms/acme/oauth2/end_session/confirm"`) {
		t.Fatalf("form action: %s", w.Body)
	}
	r := httptest.NewRequest("POST", "/realms/acme"+oidcEndSessionConfirm, strings.NewReader(url.Values{"request": {rid}, "action": {"logout"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Cookie", acme.cookieName+"="+cookie)
	w = httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	if u := location(t, w); u.String() != "https://acme-rp.example.com/bye?state=s" {
		t.Fatalf("acme logout: %s", u)
	}
	if w := acme.do(t, false, "GET", "/v1/me/sessions", nil, "Cookie", acme.cookieName+"="+cookie); w.Code != http.StatusUnauthorized {
		t.Fatalf("acme session after logout: %d", w.Code)
	}
}

// E2E：ふつうの RP（zitadel/oidc の rp）が Discovery の end_session_endpoint に id_token_hint を送り、登録した戻り先に state 付きで
// 戻される（RP のサーバーから送るので、ブラウザのセッションは無い）。
func TestOIDCE2ERPInitiatedLogout(t *testing.T) {
	e := newE2EWith(t, func(c *config.Config) {
		names := []string{}
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.OIDCLogout)
		c.Features = &names
	}, feature.Registered())
	ctx := context.Background()
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	web := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "post_logout_redirect_uris": []string{"https://rp.example.com/bye"}})
	relying, err := oidcrp.NewRelyingPartyOIDC(ctx, e.issuer, web.clientID, web.secret, web.redirect, []string{"openid"}, oidcrp.WithHTTPClient(e.http))
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier, challenge := pkce()
	code := e.browse(t, oidcrp.AuthURL("st", relying, oidcrp.WithCodeChallenge(challenge)), "alice@example.com", web.redirect)
	tokens, err := oidcrp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying, oidcrp.WithCodeVerifier(verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	loc, err := oidcrp.EndSession(ctx, relying, tokens.IDToken, "https://rp.example.com/bye", "bye-state", "", nil)
	if err != nil || loc == nil || loc.String() != "https://rp.example.com/bye?state=bye-state" {
		t.Fatalf("end session: %v %v", loc, err)
	}
	if _, err := oidcrp.EndSession(ctx, relying, tokens.IDToken, "https://evil.example.com/", "", "", nil); err == nil {
		t.Fatal("unregistered post_logout_redirect_uri accepted")
	}
}
