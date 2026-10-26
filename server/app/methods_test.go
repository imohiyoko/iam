package app

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// 本人による認証手段の追加・削除（design.md 4.2、4.3）を HTTP で確かめる。

// claimLast は最後の通知の秘密（コード）を、配信用のサービスアカウントで取り出す。
func (l *loginEnv) claimLast(t *testing.T) string {
	t.Helper()
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := l.notes.last(t)
	w := l.do(t, l.a.AdminHandler(), "POST", "/v1/admin/notifications/"+n.ID+":claim", nil, "Authorization", "Bearer "+l.apiKey)
	var sec struct{ Code string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &sec) != nil || sec.Code == "" {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	return sec.Code
}

// me は本人の API を Cookie で呼ぶ。
func (l *loginEnv) mePost(t *testing.T, cookie, path string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", path, body, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

type myMethods struct {
	Emails []struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Identities []struct {
		ID         string `json:"id"`
		Connection string `json:"connection"`
	} `json:"identities"`
}

func (l *loginEnv) methods(t *testing.T, cookie string) myMethods {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+cookie)
	var m myMethods
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("methods: %d %s", w.Code, w.Body)
	}
	return m
}

// addEmail はメールの追加を始めて、届いたコードで完了する。
func (l *loginEnv) addEmail(t *testing.T, cookie, email string) (int, map[string]any) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/me/emails:start", map[string]string{"email": email})
	if status != 200 {
		return status, st
	}
	code := l.claimLast(t)
	return l.mePost(t, cookie, "/v1/me/emails:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code})
}

func TestAddAndRemoveEmail(t *testing.T) {
	l := newLoginEnv(t)
	first, cookie := l.login(t, "dan@example.com")
	if status, res := l.addEmail(t, cookie, "Dan@Work.example"); status != 200 || res["primary"] != false || res["email"] != "dan@work.example" {
		t.Fatalf("add: %d %v", status, res)
	}
	m := l.methods(t, cookie)
	if len(m.Emails) != 2 || !m.Emails[0].Primary || m.Emails[1].Email != "dan@work.example" {
		t.Fatalf("methods: %+v", m)
	}
	// 足したメールでも同じユーザーとしてログインできる。
	if again, _ := l.login(t, "dan@work.example"); again["user_id"] != first["user_id"] || again["created"] != false {
		t.Fatalf("login with added email: %v", again)
	}
	// 本人のメールをもう一度足そうとすると、開始の時点で email_exists。
	if status, res := l.mePost(t, cookie, "/v1/me/emails:start", map[string]string{"email": "dan@work.example"}); status != 409 || res["error"] != "email_exists" {
		t.Fatalf("add own email again: %d %v", status, res)
	}
	primary, work := m.Emails[0].ID, m.Emails[1].ID
	if status, res := l.mePost(t, cookie, "/v1/me/emails/"+primary+":remove", nil); status != 409 || res["error"] != "primary_email" {
		t.Fatalf("remove primary: %d %v", status, res)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/emails/"+work+":make-primary", nil); status != 204 {
		t.Fatalf("make primary: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/emails/"+primary+":remove", nil); status != 204 {
		t.Fatalf("remove old primary: %d", status)
	}
	m = l.methods(t, cookie)
	if len(m.Emails) != 1 || m.Emails[0].ID != work || !m.Emails[0].Primary {
		t.Fatalf("after remove: %+v", m)
	}
	// 最後の確認済みメールは消せない。
	if status, res := l.mePost(t, cookie, "/v1/me/emails/"+work+":remove", nil); status != 409 || res["error"] != "primary_email" {
		t.Fatalf("remove last email: %d %v", status, res)
	}
	// 消したアドレスは別のユーザーが使える。
	if other, _ := l.login(t, "dan@example.com"); other["created"] != true {
		t.Fatalf("removed address not free: %v", other)
	}
	// 未ログインでは何もできない。別のユーザーのメールは見つからない扱い。
	if status, _ := l.mePost(t, "", "/v1/me/emails:start", map[string]string{"email": "x@example.com"}); status != 401 {
		t.Fatalf("anonymous start: %d", status)
	}
	_, eve := l.login(t, "eve@example.com")
	if status, _ := l.mePost(t, eve, "/v1/me/emails/"+work+":remove", nil); status != 404 {
		t.Fatalf("remove another user's email: %d", status)
	}
}

// 別のユーザーで使われているアドレスは、所有を確かめるまで同じ応答を返し、確かめた後で email_exists（自動リンクしない）。
func TestAddEmailUsedByAnotherUser(t *testing.T) {
	l := newLoginEnv(t)
	l.login(t, "fay@example.com")
	_, cookie := l.login(t, "gus@example.com")
	status, res := l.addEmail(t, cookie, "fay@example.com")
	if status != 409 || res["error"] != "email_exists" {
		t.Fatalf("add used email: %d %v", status, res)
	}
	if m := l.methods(t, cookie); len(m.Emails) != 1 {
		t.Fatalf("email added: %+v", m)
	}
}

// 追加のフローは始めた本人のセッションでだけ完了でき、ログインのフローとは混ざらない。
func TestAddEmailFlowIsBound(t *testing.T) {
	l := newLoginEnv(t)
	_, hal := l.login(t, "hal@example.com")
	_, ivy := l.login(t, "ivy@example.com")
	_, st := l.mePost(t, hal, "/v1/me/emails:start", map[string]string{"email": "hal@home.example"})
	flow := st["flow_id"].(string)
	code := l.claimLast(t)
	if status, _ := l.mePost(t, ivy, "/v1/me/emails:verify", map[string]string{"flow_id": flow, "code": code}); status != 401 {
		t.Fatalf("other user's session: %d", status)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": flow, "code": code}); w.Code != 401 {
		t.Fatalf("add flow at the login endpoint: %d %s", w.Code, w.Body)
	}
	if status, res := l.mePost(t, hal, "/v1/me/emails:verify", map[string]string{"flow_id": flow, "code": code}); status != 200 {
		t.Fatalf("own session: %d %v", status, res)
	}
	// ログインのフローは追加の完了に使えない。
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": "hal@example.com"})
	var login struct {
		FlowID string `json:"flow_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	if status, _ := l.mePost(t, hal, "/v1/me/emails:verify", map[string]string{"flow_id": login.FlowID, "code": l.claimLast(t)}); status != 401 {
		t.Fatalf("login flow at the add endpoint: %d", status)
	}
}

// link はログイン済みのセッションで外部 ID を連携する。
func (p *fakeIdP) link(t *testing.T, l *loginEnv, cookie, sub string) (int, map[string]any) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/me/identities/fake:start", map[string]string{"redirect_uri": "https://app.example/cb"})
	if status != 200 {
		t.Fatalf("link start: %d %v", status, st)
	}
	u, _ := url.Parse(st["authorization_url"].(string))
	q := u.Query()
	p.challenge = q.Get("code_challenge")
	now := l.a.deps.Clock.Now()
	p.claims = map[string]any{"iss": "https://fake.example", "aud": "cid", "sub": sub, "email": "ignored@example.com",
		"email_verified": true, "nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	return l.mePost(t, cookie, "/v1/me/identities:complete",
		map[string]string{"flow_id": st["flow_id"].(string), "state": q.Get("state"), "code": "the-code"})
}

func TestLinkAndUnlinkIdentity(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)
	user, cookie := l.login(t, "jo@example.com")

	status, res := idp.link(t, l, cookie, "sub-jo")
	if status != 200 || res["connection"] != "fake" {
		t.Fatalf("link: %d %v", status, res)
	}
	identity := res["id"].(string)
	if m := l.methods(t, cookie); len(m.Identities) != 1 || m.Identities[0].ID != identity || len(m.Emails) != 1 {
		t.Fatalf("methods: %+v", m)
	}
	// 連携した外部 ID でログインすると同じユーザー。メールは足していない。
	status, viaIdP, fedCookie := idp.login(t, l, "sub-jo", "other@example.com", true, "")
	if status != 200 || viaIdP["user_id"] != user["user_id"] {
		t.Fatalf("login with linked identity: %d %v", status, viaIdP)
	}
	// 既に紐付いた外部 ID は、別のユーザーにも同じユーザーにも連携できない。
	_, kim := l.login(t, "kim@example.com")
	if status, res := idp.link(t, l, kim, "sub-jo"); status != 409 || res["error"] != "identity_exists" {
		t.Fatalf("link taken identity: %d %v", status, res)
	}
	if status, res := idp.link(t, l, cookie, "sub-jo"); status != 409 || res["error"] != "identity_exists" {
		t.Fatalf("link own identity again: %d %v", status, res)
	}
	if status, _ := l.mePost(t, kim, "/v1/me/identities/"+identity+":unlink", nil); status != 404 {
		t.Fatalf("unlink another user's identity: %d", status)
	}

	if status, _ := l.mePost(t, cookie, "/v1/me/identities/"+identity+":unlink", nil); status != 204 {
		t.Fatalf("unlink: %d", status)
	}
	if m := l.methods(t, cookie); len(m.Identities) != 0 {
		t.Fatalf("after unlink: %+v", m)
	}
	// 解除した外部 ID で作ったセッションは、遅くとも validity_max_delay の後に使えない。
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.ValidityMaxDelay.D())
	if code, _ := l.me(t, fedCookie); code != 401 {
		t.Fatalf("session from unlinked identity: %d", code)
	}
	// 解除した外部 ID は自動では戻らない。未ログインのログインは、メールが登録済みなので account_exists。
	if status, res, _ := idp.login(t, l, "sub-jo", "jo@example.com", true, ""); status != 409 || res["error"] != "account_exists" {
		t.Fatalf("login with unlinked identity: %d %v", status, res)
	}
	// 本人はまた連携できる。
	if status, res := idp.link(t, l, cookie, "sub-jo"); status != 200 || res["id"] == identity {
		t.Fatalf("relink: %d %v", status, res)
	}
}

// 最後のログインの手段は解除できない（code が無効なら、メールはログインの手段にならない）。
func TestUnlinkLastMethod(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Realm.VerifiedVia = []string{"oauth_provider", "admin"} }, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := newFakeIdP(t, l, owner)
	status, _, cookie := idp.login(t, l, "sub-lee", "lee@example.com", true, "")
	if status != 200 {
		t.Fatalf("signup: %d", status)
	}
	m := l.methods(t, cookie)
	if len(m.Identities) != 1 {
		t.Fatalf("methods: %+v", m)
	}
	if status, res := l.mePost(t, cookie, "/v1/me/identities/"+m.Identities[0].ID+":unlink", nil); status != 409 || res["error"] != "last_method" {
		t.Fatalf("unlink last method: %d %v", status, res)
	}
	// 2つ目を連携すれば、1つ目を解除できる。
	if status, _ := idp.link(t, l, cookie, "sub-lee-2"); status != 200 {
		t.Fatalf("link second: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/identities/"+m.Identities[0].ID+":unlink", nil); status != 204 {
		t.Fatalf("unlink first: %d", status)
	}
	// code が無効なら、メールの追加は始められない。
	if status, res := l.mePost(t, cookie, "/v1/me/emails:start", map[string]string{"email": "lee@home.example"}); status != 400 || res["error"] != "verification_method_disabled" {
		t.Fatalf("add email with code disabled: %d %v", status, res)
	}
}
