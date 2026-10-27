package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// orgIdP は Org の IdP（トークンエンドポイント）を模す。code ごとにクレームを置く。
type orgIdP struct {
	mu     sync.Mutex
	srv    *httptest.Server
	grants map[string]orgIdPGrant
}

type orgIdPGrant struct {
	claims    map[string]any
	challenge string
}

func newOrgIdP(t *testing.T) *orgIdP {
	p := &orgIdP{grants: map[string]orgIdPGrant{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		g, ok := p.grants[r.PostForm.Get("code")]
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || r.PostForm.Get("client_secret") != "acme-secret" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, "invalid_grant", 400)
			return
		}
		b, _ := json.Marshal(g.claims)
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".x"})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// ssoLogin は Org の connection でのログインを通し、応答を返す。
func (l *loginEnv) ssoLogin(t *testing.T, p *orgIdP, conn, sub, email string) *httptest.ResponseRecorder {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth/"+conn+":start", map[string]string{})
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var st struct {
		FlowID string `json:"flow_id"`
		URL    string `json:"authorization_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	u, _ := url.Parse(st.URL)
	q := u.Query()
	if !strings.HasSuffix(q.Get("redirect_uri"), "/login/oauth/callback") {
		t.Fatalf("redirect_uri = %s", q.Get("redirect_uri"))
	}
	now := l.a.deps.Clock.Now()
	code := "code-" + q.Get("state")[:8]
	p.mu.Lock()
	p.grants[code] = orgIdPGrant{challenge: q.Get("code_challenge"), claims: map[string]any{"iss": "https://idp.acme.example", "aud": "acme-client",
		"sub": sub, "email": email, "email_verified": true, "nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}}
	p.mu.Unlock()
	return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth:complete", map[string]string{"state": q.Get("state"), "code": code, "flow_id": st.FlowID})
}

func sessionOf(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func TestOrgSSO(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "sso", "admin", "invitation"}
		c.Server.PublicURL = "https://iam.example"
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.OrgManagedUsers, feature.OrgLoginPolicy)
		c.Features = &names
	}, feature.Registered())
	dns := &fakeDNS{txt: map[string][]string{}}
	l.a.orgs.Resolver = dns
	idp := newOrgIdP(t)
	l.a.oauth.HTTP = idp.srv.Client()

	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	base := "/v1/me/orgs/" + acme + "/connections"
	body := map[string]any{"issuer": "https://idp.acme.example", "authorization_endpoint": "https://idp.acme.example/authorize",
		"token_endpoint": idp.srv.URL + "/token", "client_id": "acme-client", "client_secret": "acme-secret"}

	// 設定の誤り（openid の無い scopes）は 400。
	bad := map[string]any{}
	for k, v := range body {
		bad[k] = v
	}
	bad["scopes"] = []string{"email"}
	if code, out := l.mePost(t, owner, base, bad); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("bad connection: %d %v", code, out)
	}
	code, out := l.mePost(t, owner, base, body)
	if code != 201 || !strings.HasSuffix(out["redirect_uri"].(string), "/login/oauth/callback") || out["client_secret"] != nil {
		t.Fatalf("add connection: %d %v", code, out)
	}
	conn := out["id"].(string)
	if code, out := l.meDo(t, "GET", owner, base, nil); code != 200 || len(out["connections"].([]any)) != 1 {
		t.Fatalf("list connections: %d %v", code, out)
	}
	// 個人 Org には置けない。
	personal := ""
	if code, out := l.meDo(t, "GET", owner, "/v1/me/orgs", nil); code == 200 {
		for _, o := range out["orgs"].([]any) {
			if m := o.(map[string]any); m["kind"] == "personal" {
				personal = m["id"].(string)
			}
		}
	}
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+personal+"/connections", body); code != 409 || out["error"] != "personal_org" {
		t.Fatalf("personal org connection: %d %v", code, out)
	}

	// ドメインから connection を探せる。ホスト型の画面の一覧には出さない。
	discover := func(email string) []any {
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/sso:discover", map[string]string{"email": email})
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != 200 {
			t.Fatalf("discover %s: %d %v", email, w.Code, out)
		}
		return out["connections"].([]any)
	}
	if got := discover("Someone@ACME.example"); len(got) != 1 || got[0] != conn {
		t.Fatalf("discover acme = %v", got)
	}
	if got := discover("someone@other.example"); len(got) != 0 {
		t.Fatalf("discover other = %v", got)
	}

	// 証明済みドメインの人は、Org の IdP で登録すると管理ユーザーになり、その Org に入る。
	w := l.ssoLogin(t, idp, conn, "u-1", "sam@acme.example")
	if w.Code != 200 {
		t.Fatalf("sso signup: %d %s", w.Code, w.Body)
	}
	sam := sessionOf(w)
	if e := l.myOrgEntry(t, sam, acme); e["managed"] != true || e["active"] != true {
		t.Fatalf("sso user not managed or not in the org: %v", e)
	}
	// 2回目は同じユーザーでログインする。
	if w := l.ssoLogin(t, idp, conn, "u-1", "sam@acme.example"); w.Code != 200 {
		t.Fatalf("sso login: %d %s", w.Code, w.Body)
	}
	// 証明していないドメインのアドレスでは登録できない。
	if w := l.ssoLogin(t, idp, conn, "u-2", "eve@other.example"); w.Code != 400 || !strings.Contains(w.Body.String(), "email_domain_not_verified") {
		t.Fatalf("sso signup outside domain: %d %s", w.Code, w.Body)
	}
	// 個人ユーザーのアドレスは自動リンクしない。個人ユーザーは Org の connection を連携できない。
	if w := l.ssoLogin(t, idp, conn, "u-3", "boss@acme.example"); w.Code != 409 {
		t.Fatalf("sso with personal user's email: %d %s", w.Code, w.Body)
	}
	if code, out := l.mePost(t, owner, "/v1/me/identities/"+conn+":start", map[string]string{}); code != 409 || out["error"] != "not_managed_by_org" {
		t.Fatalf("personal user links org connection: %d %v", code, out)
	}

	// require_sso：Org の connection で認証したセッションだけが入れる。
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"require_sso": true}}); code != 200 {
		t.Fatalf("require_sso: %d %v", code, out)
	}
	_, owner2 := l.login(t, "boss@acme.example")
	if code, out, _ := l.post(t, owner2, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(out) != "policy.require_sso" {
		t.Fatalf("switch without sso: %d %v", code, out)
	}
	if w := l.ssoLogin(t, idp, conn, "u-1", "sam@acme.example"); w.Code != 200 {
		t.Fatalf("sso login with require_sso: %d %s", w.Code, w.Body)
	}
	if code, out := l.putSettings(t, owner, acme, map[string]any{}); code != 200 {
		t.Fatalf("clear policy: %d %v", code, out)
	}

	// 管理を手放すと、Org の connection の外部 ID は無効になる（個人ユーザーを Org の IdP でなりすませない）。
	samMember := l.myOrgEntry(t, sam, acme)["membership_id"].(string)
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/members/"+samMember+":release-management", nil); code != 204 {
		t.Fatalf("release: %d %v", code, out)
	}
	if w := l.ssoLogin(t, idp, conn, "u-1", "sam@acme.example"); w.Code != 409 {
		t.Fatalf("sso login after release: %d %s", w.Code, w.Body)
	}

	// connection を消すと、その connection ではログインできない。
	if code, out := l.mePost(t, owner, base+"/"+conn+":delete", nil); code != 204 {
		t.Fatalf("delete connection: %d %v", code, out)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth/"+conn+":start", map[string]string{}); w.Code != 404 {
		t.Fatalf("start deleted connection: %d %s", w.Code, w.Body)
	}
	if got := discover("sam@acme.example"); len(got) != 0 {
		t.Fatalf("discover after delete = %v", got)
	}
}
