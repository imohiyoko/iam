package app

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
)

// フィーチャー form_post（OAuth 2.0 Form Post Response Mode。ADR 0124）を HTTP で確かめる。

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// formFields は自動で POST する画面の action と hidden の値を返す。
func formFields(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := regexp.MustCompile(`<form id="formpost" method="post" action="([^"]+)">`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form: %s", body)
	}
	out := url.Values{}
	for _, f := range hiddenInput.FindAllStringSubmatch(body, -1) {
		out.Add(f[1], strings.ReplaceAll(f[2], "&#43;", "+"))
	}
	return strings.ReplaceAll(m[1], "&amp;", "&"), out
}

func responseModesOf(t *testing.T, l *loginEnv) []string {
	t.Helper()
	var out []string
	for _, v := range metadataAt(t, l, "/.well-known/openid-configuration")["response_modes_supported"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestFormPostOff(t *testing.T) {
	l := senderEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if modes := responseModesOf(t, l); slices.Contains(modes, "form_post") {
		t.Fatalf("discovery while off: %v", modes)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	_, cookie := l.login(t, "alice@example.com")
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"response_mode": {"form_post"}}), nil, cookie))
	if u.Query().Get("error") != "invalid_request" || u.Query().Get("code") != "" {
		t.Fatalf("form_post while off: %s", u)
	}
	if w := l.oidcDo(t, "GET", oidcFormPost+"?r=x", nil, cookie); w.Code != 404 {
		t.Fatalf("form_post page while off: %d", w.Code)
	}
}

func TestFormPost(t *testing.T) {
	l := senderEnv(t, nil, feature.FormPost)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if modes := responseModesOf(t, l); !slices.Contains(modes, "form_post") || !slices.Contains(modes, "query") {
		t.Fatalf("discovery: %v", modes)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://rp.example.com/cb?tenant=1&state=fixed"}})
	_, cookie := l.login(t, "alice@example.com")

	// ログイン済みのブラウザ：認可エンドポイントは画面へ転送し、画面は戻り先へ code・state・iss を POST する。
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"response_mode": {"form_post"}}), nil, cookie))
	if u.Path != oidcFormPost || u.Query().Get("code") != "" {
		t.Fatalf("redirect = %s", u)
	}
	page := u.Path + "?" + u.RawQuery
	// 別のブラウザ（セッションなし、別のセッション）では開けず、使い切らない。
	if w := l.oidcDo(t, "GET", page, nil, ""); w.Code != 400 {
		t.Fatalf("other browser: %d", w.Code)
	}
	_, bob := l.login(t, "bob@example.com")
	if w := l.oidcDo(t, "GET", page, nil, bob); w.Code != 400 {
		t.Fatalf("other session: %d", w.Code)
	}
	w := l.oidcDo(t, "GET", page, nil, cookie)
	if w.Code != 200 {
		t.Fatalf("form page: %d %s", w.Code, w.Body)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action https://rp.example.com;") || !strings.Contains(csp, "frame-ancestors 'none'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", w.Header())
	}
	action, fields := formFields(t, w.Body.String())
	// 戻り先が元から持つクエリ（state=fixed も）は action に残り、応答の値には混ざらない。
	if action != "https://rp.example.com/cb?tenant=1&state=fixed" || !slices.Equal(fields["state"], []string{p.state}) || fields.Get("iss") != testIssuer ||
		fields.Get("code") == "" || fields.Get("tenant") != "" {
		t.Fatalf("form: %s %v", action, fields)
	}
	// 1 回限り。
	if w := l.oidcDo(t, "GET", page, nil, cookie); w.Code != 400 {
		t.Fatalf("second open: %d", w.Code)
	}
	if code, out := p.exchange(t, fields.Get("code"), nil); code != 200 || out["id_token"] == nil {
		t.Fatalf("exchange: %d %v", code, out)
	}

	// エラーの応答も POST で返す（セッションなし、prompt=none）。
	u = location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"response_mode": {"form_post"}, "prompt": {"none"}}), nil, ""))
	if u.Path != oidcFormPost {
		t.Fatalf("error redirect = %s", u)
	}
	w = l.oidcDo(t, "GET", u.Path+"?"+u.RawQuery, nil, "")
	if w.Code != 200 {
		t.Fatalf("error page: %d %s", w.Code, w.Body)
	}
	if _, fields := formFields(t, w.Body.String()); fields.Get("error") != "login_required" || fields.Get("state") != p.state || fields.Get("code") != "" {
		t.Fatalf("error form: %v", fields)
	}
	// op が自分で返すエラー（prompt の検証）も POST で返す。
	u = location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"response_mode": {"form_post"}, "prompt": {"none login"}}), nil, cookie))
	if u.Path != oidcFormPost {
		t.Fatalf("op error redirect = %s", u)
	}
	w = l.oidcDo(t, "GET", u.Path+"?"+u.RawQuery, nil, cookie)
	if w.Code != 200 || len(w.Body.String()) == 0 {
		t.Fatalf("op error page: %d %s", w.Code, w.Body)
	}
	if action, fields := formFields(t, w.Body.String()); action != "https://rp.example.com/cb?tenant=1&state=fixed" || fields.Get("error") != "invalid_request" ||
		!slices.Equal(fields["state"], []string{p.state}) || fields.Get("tenant") != "" || fields.Get("code") != "" {
		t.Fatalf("op error form: %s %v", action, fields)
	}
	// 既定（query）は今までどおり戻り先へ転送する。
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie)); u.Host != "rp.example.com" || u.Query().Get("code") == "" {
		t.Fatalf("query mode: %s", u)
	}
}

// TestFormPostDisabledDuringLogin は、ログインの間にフィーチャーを止めて起動し直したら（Storage と EphemeralStore はそのまま）、
// 預かった form_post の要求にコードを出さないことを確かめる。
func TestFormPostDisabledDuringLogin(t *testing.T) {
	l := senderEnv(t, nil, feature.FormPost)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"response_mode": {"form_post"}}), nil, ""))
	back := u.Query().Get("return_to")
	if u.Path != "/login" || !strings.HasPrefix(back, oidcResume+"?request=") {
		t.Fatalf("not sent to login: %s", u)
	}
	enabled := slices.DeleteFunc(slices.Clone(*l.e.cfg.Features), func(n string) bool { return n == feature.FormPost })
	if _, err := l.restart(t, enabled, feature.Registered()); err != nil || l.a.formPost {
		t.Fatalf("restart without form_post: %v", err)
	}
	_, cookie := l.login(t, "alice@example.com")
	u = location(t, l.oidcDo(t, "GET", back, nil, cookie))
	if u.Host != "rp.example.com" || u.Query().Get("error") != "invalid_request" || u.Query().Get("code") != "" || u.Query().Get("state") != p.state {
		t.Fatalf("resume after disable: %s", u)
	}
}
