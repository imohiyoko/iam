package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Pushed Authorization Requests（RFC 9126）、Authorization Server Metadata（RFC 8414）、Protected Resource Metadata
// （RFC 9728）を HTTP で確かめる（ADR 0112）。

// featureEnv は既定のフィーチャーに extra を足した環境。edit で設定も変えられる。
func featureEnv(t *testing.T, edit func(*config.Config), extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

// push は PAR エンドポイントに認可要求を送る。authorizeURL と同じパラメーター（PKCE・state・nonce は新しく作る）に extra を重ねる。
func (p *rp) push(t *testing.T, extra url.Values) (int, map[string]any) {
	t.Helper()
	u, _ := url.Parse(p.authorizeURL(nil))
	q := u.Query()
	q.Del("client_id")
	for k, v := range extra {
		q[k] = v
	}
	return p.post(t, oidcPAR, q)
}

// followLogin は認可要求の URL から、ログイン画面を経て戻り先への転送まで進める。
func (p *rp) followLogin(t *testing.T, authorize, email string) string {
	t.Helper()
	u := location(t, p.l.oidcDo(t, "GET", authorize, nil, ""))
	if u.Path != "/login" {
		t.Fatalf("not sent to login: %s", u)
	}
	_, cookie := p.l.login(t, email)
	return p.code(t, p.l.oidcDo(t, "GET", u.Query().Get("return_to"), nil, cookie))
}

func discoveryOf(t *testing.T, l *loginEnv, path string) map[string]any {
	t.Helper()
	w := l.oidcDo(t, "GET", path, nil, "")
	var out map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	return out
}

func TestPAROff(t *testing.T) {
	l := featureEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if d := discoveryOf(t, l, "/.well-known/openid-configuration"); d["pushed_authorization_request_endpoint"] != nil ||
		d["require_pushed_authorization_requests"] != nil {
		t.Fatalf("discovery shows PAR: %v", d)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if status, _ := p.push(t, nil); status != http.StatusNotFound {
		t.Fatalf("par while off: %d", status)
	}
	// request_uri は受けない（戻り先には転送しない）。
	w := l.oidcDo(t, "GET", oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {provider.RequestURIPrefix + "x"}}.Encode(), nil, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "request_uri_not_supported") {
		t.Fatalf("request_uri while off: %d %s", w.Code, w.Body)
	}
	// 連携先に PAR の必須を置けない。
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "X", "redirect_uris": []string{"https://x.example.com/cb"},
		"token_endpoint_auth_method": "none", "require_pushed_authorization_requests": true}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("require par while off: %d %v", code, out)
	}
}

func TestPAR(t *testing.T) {
	l := featureEnv(t, nil, feature.PAR)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	// Discovery と RFC 8414 のメタデータは同じ内容で、PAR のエンドポイントを載せる。
	disc := discoveryOf(t, l, "/.well-known/openid-configuration")
	if disc["pushed_authorization_request_endpoint"] != testIssuer+oidcPAR || disc["require_pushed_authorization_requests"] != nil {
		t.Fatalf("discovery: %v", disc)
	}
	if as := discoveryOf(t, l, wellKnownAS); !reflect.DeepEqual(as, disc) {
		t.Fatalf("authorization server metadata differs: %v", as)
	}

	status, out := p.push(t, nil)
	uri, _ := out["request_uri"].(string)
	if status != http.StatusCreated || !strings.HasPrefix(uri, provider.RequestURIPrefix) || out["expires_in"] != float64(60) {
		t.Fatalf("push: %d %v", status, out)
	}
	// ブラウザのほかのパラメーターは見ない（預かったものだけ）。
	authorize := oidcAuthorize + "?" + url.Values{"client_id": {p.clientID}, "request_uri": {uri}, "state": {"evil"},
		"redirect_uri": {"https://evil.example.com/cb"}}.Encode()
	code := p.followLogin(t, authorize, "alice@example.com")
	if st, tok := p.exchange(t, code, nil); st != 200 || tok["scope"] != "openid email" {
		t.Fatalf("token: %d %v", st, tok)
	}
	// request_uri は 1 回だけ。
	if w := l.oidcDo(t, "GET", authorize, nil, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_request_uri") {
		t.Fatalf("reuse: %d %s", w.Code, w.Body)
	}
	// 別の連携先では使えず、使おうとした request_uri はもう使えない。
	other := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	_, out = p.push(t, nil)
	uri = out["request_uri"].(string)
	if w := l.oidcDo(t, "GET", oidcAuthorize+"?"+url.Values{"client_id": {other.clientID}, "request_uri": {uri}}.Encode(), nil, ""); w.Code != 400 {
		t.Fatalf("other client: %d", w.Code)
	}
	if w := l.oidcDo(t, "GET", oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {uri}}.Encode(), nil, ""); w.Code != 400 {
		t.Fatalf("after misuse: %d", w.Code)
	}
	// 期限切れ。
	_, out = p.push(t, nil)
	l.advance(61 * time.Second)
	if w := l.oidcDo(t, "GET", oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {out["request_uri"].(string)}}.Encode(), nil, ""); w.Code != 400 {
		t.Fatalf("expired: %d", w.Code)
	}

	// 受け付けで authorize と同じ規則を確かめ、誤りは JSON で返す（戻り先に転送しない）。
	for name, c := range map[string]struct {
		extra url.Values
		want  string
	}{
		"unregistered redirect_uri": {url.Values{"redirect_uri": {"https://evil.example.com/cb"}}, "invalid_request"},
		"no pkce":                   {url.Values{"code_challenge": nil, "code_challenge_method": nil}, "invalid_request"},
		"no openid":                 {url.Values{"scope": {"email"}}, "invalid_scope"},
		"request_uri pushed":        {url.Values{"request_uri": {provider.RequestURIPrefix + "x"}}, "invalid_request"},
		"request object":            {url.Values{"request": {"eyJ"}}, "request_not_supported"},
		"other client_id":           {url.Values{"client_id": {other.clientID}}, "invalid_client"},
	} {
		if status, out := p.push(t, c.extra); status != 400 || out["error"] != c.want {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	bad := *p
	bad.secret = p.secret[:len(p.secret)-2] + "AA"
	if status, out := bad.push(t, nil); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", status, out)
	}
	if w := l.oidcDo(t, "GET", oidcPAR, nil, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET par: %d", w.Code)
	}

	// 公開クライアントも client_id だけで送れる。
	_, out = other.push(t, nil)
	if _, ok := out["request_uri"].(string); !ok {
		t.Fatalf("public client push: %v", out)
	}
	other.followLogin(t, oidcAuthorize+"?"+url.Values{"client_id": {other.clientID}, "request_uri": {out["request_uri"].(string)}}.Encode(), "bob@example.com")

	// 連携先に PAR を求めると、ふつうの認可要求は戻り先に転送せずに拒む。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+p.clientID, map[string]any{"name": "RP", "redirect_uris": []string{p.redirect},
		"token_endpoint_auth_method": "client_secret", "require_pushed_authorization_requests": true}); code != 200 || out["require_pushed_authorization_requests"] != true {
		t.Fatalf("require par: %d %v", code, out)
	}
	if w := l.oidcDo(t, "GET", p.authorizeURL(nil), nil, ""); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("plain authorize with require par: %d %v", w.Code, w.Header())
	}
	_, out = p.push(t, nil)
	p.followLogin(t, oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {out["request_uri"].(string)}}.Encode(), "alice@example.com")
	// ほかの連携先は今までどおり。
	if u := location(t, l.oidcDo(t, "GET", other.authorizeURL(nil), nil, "")); u.Path != "/login" {
		t.Fatalf("other client: %s", u)
	}
}

func TestPARRequiredByRealm(t *testing.T) {
	l := featureEnv(t, func(c *config.Config) { c.Realm.RequirePushedAuthorizationRequests = true }, feature.PAR)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	if d := discoveryOf(t, l, wellKnownAS); d["require_pushed_authorization_requests"] != true {
		t.Fatalf("metadata: %v", d)
	}
	if w := l.oidcDo(t, "GET", p.authorizeURL(nil), nil, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("plain authorize: %d", w.Code)
	}
	_, out := p.push(t, nil)
	p.followLogin(t, oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {out["request_uri"].(string)}}.Encode(), "alice@example.com")
}

func TestDisablePARWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "require_pushed_authorization_requests": true})
	disableWithData(t, l, feature.PAR, 1)
}

func TestProtectedResourceMetadata(t *testing.T) {
	l := featureEnv(t, nil)
	m := discoveryOf(t, l, wellKnownResource)
	if m["resource"] != testIssuer || !reflect.DeepEqual(m["authorization_servers"], []any{testIssuer}) ||
		!reflect.DeepEqual(m["bearer_methods_supported"], []any{"header", "body"}) {
		t.Fatalf("resource metadata: %v", m)
	}
	// RFC 8414 のメタデータは PAR が無くても出す。
	if d := discoveryOf(t, l, wellKnownAS); d["issuer"] != testIssuer || d["token_endpoint"] != testIssuer+oidcToken {
		t.Fatalf("authorization server metadata: %v", d)
	}
	// どのオリジンからも読める（公開の情報）。
	w := l.oidcDo(t, "GET", wellKnownResource, nil, "", "Origin", "https://app.example.org")
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("cors: %v", w.Header())
	}
}
