package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// M1 の完了条件の E2E（roadmap.md M1）。公開 API と管理 API を HTTP で通し、外部プロバイダだけを偽物にする。

// fakeIdP は OAuth / OIDC のプロバイダの偽物（TLS のトークンエンドポイント）。
type fakeIdP struct {
	srv       *httptest.Server
	claims    map[string]any
	challenge string
}

// newFakeIdP はプロバイダを立て、運営者が管理 API で connection "fake" を登録する。
func newFakeIdP(t *testing.T, l *loginEnv, owner string) *fakeIdP {
	t.Helper()
	p := &fakeIdP{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
			http.Error(w, "invalid_grant", 400)
			return
		}
		b, _ := json.Marshal(p.claims)
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".x"})
	}))
	t.Cleanup(p.srv.Close)
	l.a.oauth.HTTP = p.srv.Client()
	oauth.Presets["fake"] = oauth.Config{Issuers: []string{"https://fake.example"}, AuthURL: "https://fake.example/auth",
		TokenURL: p.srv.URL, Scopes: []string{"openid", "email"}}
	t.Cleanup(func() { delete(oauth.Presets, "fake") })
	status, res := l.admin(t, "/v1/admin/connections", owner, map[string]any{"slug": "fake", "preset": "fake", "client_id": "cid",
		"client_secret": "csecret", "redirect_uris": []string{"https://app.example/cb"}})
	if status != 201 {
		t.Fatalf("create connection: %d %v", status, res)
	}
	return p
}

// login はブラウザでの OAuth のログインを模す。sessionCookieValue は既に持っているセッション（ID の入れ替えの確認用）。
func (p *fakeIdP) login(t *testing.T, l *loginEnv, sub, email string, verified bool, sessionCookieValue string) (int, map[string]any, string) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth/fake:start", map[string]string{"redirect_uri": "https://app.example/cb"})
	if w.Code != 200 {
		t.Fatalf("oauth start: %d %s", w.Code, w.Body)
	}
	var st struct {
		FlowID string `json:"flow_id"`
		URL    string `json:"authorization_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	u, _ := url.Parse(st.URL)
	q := u.Query()
	p.challenge = q.Get("code_challenge")
	now := l.a.deps.Clock.Now()
	p.claims = map[string]any{"iss": "https://fake.example", "aud": "cid", "sub": sub, "email": email,
		"email_verified": verified, "nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	cookies := oauthCookie + "=" + st.FlowID
	if sessionCookieValue != "" {
		cookies += "; " + sessionCookie + "=" + sessionCookieValue
	}
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth:complete", map[string]string{"state": q.Get("state"), "code": "the-code"},
		"Cookie", cookies)
	var res map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return w.Code, res, c.Value
		}
	}
	return w.Code, res, ""
}

func (l *loginEnv) me(t *testing.T, cookie string) (int, []map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/sessions", nil, "Cookie", sessionCookie+"="+cookie)
	var body struct {
		Sessions []map[string]any `json:"sessions"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Sessions
}

// E2E：OAuth で登録 → ログアウト → メールコードで再ログイン（roadmap M1 の完了条件）。
func TestE2EOAuthSignupLogoutEmailRelogin(t *testing.T) {
	e2eOAuthSignupLogoutEmailRelogin(t, newLoginEnvWith(t, nil, feature.Registered()))
}

func e2eOAuthSignupLogoutEmailRelogin(t *testing.T, l *loginEnv) {
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)

	status, signup, cookie := idp.login(t, l, "google-sub-1", "Carol@Example.com", true, "")
	if status != 200 || signup["created"] != true || cookie == "" {
		t.Fatalf("oauth signup: %d %v", status, signup)
	}
	if code, ss := l.me(t, cookie); code != 200 || len(ss) != 1 || ss[0]["auth_methods"].([]any)[0] != "fed" {
		t.Fatalf("me after signup: %d %v", code, ss)
	}

	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/logout", nil, "Cookie", sessionCookie+"="+cookie); w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	if code, _ := l.me(t, cookie); code != 401 {
		t.Fatalf("me after logout: %d", code)
	}

	// プロバイダが確認したメールで、コードでもログインできる（同じユーザー）。
	relogin, cookie2 := l.login(t, "carol@example.com")
	if relogin["created"] != false || relogin["user_id"] != signup["user_id"] {
		t.Fatalf("relogin = %v, signup = %v", relogin, signup)
	}
	if code, ss := l.me(t, cookie2); code != 200 || len(ss) != 1 || ss[0]["auth_methods"].([]any)[0] != "otp" {
		t.Fatalf("me after relogin: %d %v", code, ss)
	}
	// もう一度 OAuth でも同じユーザー（外部 ID で引く）。
	if status, again, _ := idp.login(t, l, "google-sub-1", "carol@example.com", true, ""); status != 200 || again["user_id"] != signup["user_id"] || again["created"] != false {
		t.Fatalf("oauth login again: %d %v", status, again)
	}
}

// E2E：code を無効にした構成（メールを送れない環境）で、OAuth と運営者による登録だけで運用できる（roadmap M1）。
func TestE2ECodeDisabled(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Realm.VerifiedVia = []string{"oauth_provider", "admin"} }, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)

	// メールのフローは同じ応答を返すが、何も送らない。
	sentBefore := l.notes.count()
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": "owner@example.com"}); w.Code != 200 {
		t.Fatalf("email start: %d", w.Code)
	}
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.notes.count() != sentBefore {
		t.Fatal("a notification was sent although code is disabled")
	}

	// OAuth で登録できる。
	if status, res, cookie := idp.login(t, l, "sub-dave", "dave@example.com", true, ""); status != 200 || res["created"] != true || cookie == "" {
		t.Fatalf("oauth signup: %d %v", status, res)
	}
	// 運営者が登録し、ログイン用リンクを渡せる。
	status, res := l.admin(t, "/v1/admin/users", owner, map[string]string{"email": "erin@example.com"})
	if status != 201 {
		t.Fatalf("admin create: %d %v", status, res)
	}
	erin := res["user_id"].(string)
	status, link := l.admin(t, "/v1/admin/users/"+erin+":login_link", owner, nil)
	if status != 200 {
		t.Fatalf("login link: %d %v", status, link)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": link["token"]})
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || got["user_id"] != erin {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
}

// 不変条件：秘密（セッションのトークン、コード、リンクのトークン、クライアントシークレット）が、
// ログ・監査ログの外部出力・API の応答の本文以外のどこにも出ない（13.5）。
func TestSecretsNeverLogged(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)
	_, _, oauthSession := idp.login(t, l, "sub-1", "frank@example.com", true, "")
	_, emailSession := l.login(t, "frank@example.com")
	_, link := l.admin(t, "/v1/admin/users/"+l.userID(t, "frank@example.com")+":login_link", owner, nil)
	l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": link["token"]})
	l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]any{"flow_id": "bogus", "code": "123456"})
	if _, err := l.a.relay.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	secrets := map[string]string{"oauth session": oauthSession, "email session": emailSession, "owner session": owner,
		"login link": link["token"].(string), "client secret": "csecret", "delivery api key": l.apiKey}
	for _, c := range l.codes {
		secrets["code "+c] = c
	}
	for name, s := range secrets {
		if s == "" {
			t.Fatalf("%s is empty; the test would pass vacuously", name)
		}
		// トークンの秘密の部分（公開 ID の後ろ）で探す。
		if _, after, ok := strings.Cut(s, "."); ok && strings.HasPrefix(s, "ses_") {
			s = after
		}
		for where, text := range map[string]string{"logs": l.e.logs.String(), "audit export": l.e.out.String()} {
			// コードは6桁の数字で、時刻やハッシュに偶然含まれうるため、JSON の値として探す。
			if strings.Contains(text, s) && (!strings.HasPrefix(name, "code ") || strings.Contains(text, `"`+s+`"`)) {
				t.Errorf("%s leaked to %s", name, where)
			}
		}
	}
	if l.e.out.String() == "" {
		t.Fatal("nothing was exported; the test would pass vacuously")
	}
}

// 不変条件：ログイン時にセッションの ID が入れ替わる（5.2）。HTTP で、既存の Cookie を持ったままログインする。
func TestLoginReplacesSessionOverHTTP(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)
	_, first, oldCookie := idp.login(t, l, "sub-g", "gina@example.com", true, "")
	if code, _ := l.me(t, oldCookie); code != 200 { // 有効性をキャッシュに載せる（入れ替えでキャッシュも消えることを確かめる）
		t.Fatalf("old session before replacement: %d", code)
	}
	_, second, newCookie := idp.login(t, l, "sub-g", "gina@example.com", true, oldCookie)
	if newCookie == "" || newCookie == oldCookie || first["session_id"] == second["session_id"] {
		t.Fatalf("session not replaced: %v %v", first, second)
	}
	if code, _ := l.me(t, oldCookie); code != 401 {
		t.Fatalf("old session still valid: %d", code)
	}
	if code, ss := l.me(t, newCookie); code != 200 || len(ss) != 1 {
		t.Fatalf("new session: %d %v", code, ss)
	}
}

// 不変条件：運営者による失効が、設定した上限（validity_max_delay）の時間内に検証へ反映される（5.3）。
func TestAdminRevocationReflectedWithinMaxDelay(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	res, cookie := l.login(t, "hank@example.com")
	if code, _ := l.me(t, cookie); code != 200 { // 有効性をキャッシュに載せる
		t.Fatalf("me: %d", code)
	}
	if status, _ := l.admin(t, "/v1/admin/sessions/"+res["session_id"].(string)+":revoke", owner, nil); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.ValidityMaxDelay.D())
	if code, _ := l.me(t, cookie); code != 401 {
		t.Fatalf("revoked session accepted after max delay: %d", code)
	}
}

// userID はメールアドレスのユーザーの公開 ID。
func (l *loginEnv) userID(t *testing.T, email string) string {
	t.Helper()
	var out string
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		e, err := l.a.accounts.FindByEmail(ctx, tx, l.a.realm.ID, email)
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, l.a.realm.ID, e.UserID)
		out = u.PublicID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// 不変条件：OAuth と管理 API の経路でも、内部 ID（ユーザー、外部 ID の紐付け、ロールの付与）は外に出ない（ADR 0045）。
func TestInternalIDsNeverLeaveOAuthAndAdmin(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	ownerID, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)
	_, res, _ := idp.login(t, l, "sub-i", "ivy@example.com", true, "")
	code, jack := l.admin(t, "/v1/admin/users", owner, map[string]string{"email": "jack@example.com"})
	if code != 201 && code != 200 {
		t.Fatalf("create user: %d %v", code, jack)
	}
	ctx := context.Background()
	if _, err := l.a.relay.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var internal []string
	err := l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		for _, pub := range []string{res["user_id"].(string), jack["user_id"].(string), ownerID} {
			u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, pub)
			if err != nil {
				return err
			}
			internal = append(internal, u.ID)
			ids, err := tx.Identities().ListByUser(ctx, l.a.realm.ID, u.ID)
			for _, x := range ids {
				internal = append(internal, x.ID)
			}
			if err != nil {
				return err
			}
			bs, err := tx.RoleBindings().ListByPrincipal(ctx, l.a.realm.ID, port.PrincipalUser, u.ID)
			for _, b := range bs {
				internal = append(internal, b.ID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(internal) < 4 {
		t.Fatalf("internal ids = %v", internal)
	}
	emitted := l.out.String() + l.e.out.String() + l.notes.sent.String()
	for _, v := range internal {
		_, suffix, _ := strings.Cut(v, "_")
		if strings.Contains(emitted, suffix) {
			t.Errorf("internal id %s leaked", v)
		}
	}
}
