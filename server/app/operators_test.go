package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
)

// operator は CLI と同じ手順で運営者を作り、リンクでログインしたセッションのトークンを返す。
func (l *loginEnv) operator(t *testing.T, email, roleName string) (userID, token string) {
	t.Helper()
	op, err := l.a.CreateOperator(context.Background(), email, roleName, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": op.LinkToken, "return_token": true})
	if w.Code != 200 {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	var res struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.UserID != op.UserID {
		t.Fatalf("redeem body: %s", w.Body)
	}
	return op.UserID, res.Token
}

func (l *loginEnv) admin(t *testing.T, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var hdr []string
	if bearer != "" {
		hdr = []string{"Authorization", "Bearer " + bearer}
	}
	w := l.do(t, l.a.AdminHandler(), "POST", path, body, hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestLoginLinkIsOneTimeAndExpires(t *testing.T) {
	l := newLoginEnv(t)
	op, err := l.a.CreateOperator(context.Background(), "ops@example.com", role.RealmOwner, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	redeem := func(tok string) int {
		return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": tok}).Code
	}
	for _, bad := range []string{"", "x", op.LinkToken[:len(op.LinkToken)-2], strings.Repeat("A", 2000)} {
		if c := redeem(bad); c != 401 && c != 400 {
			t.Fatalf("token %q...: %d", bad[:min(len(bad), 8)], c)
		}
	}
	if c := redeem(op.LinkToken); c != 200 {
		t.Fatalf("first use: %d", c)
	}
	if c := redeem(op.LinkToken); c != 401 {
		t.Fatalf("second use: %d", c)
	}
	op2, _ := l.a.CreateOperator(context.Background(), "ops@example.com", role.RealmOwner, time.Minute)
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(2 * time.Minute)
	if c := redeem(op2.LinkToken); c != 401 {
		t.Fatalf("expired: %d", c)
	}
	if _, err := l.a.CreateOperator(context.Background(), "ops@example.com", role.NotificationDelivery, time.Minute); err == nil {
		t.Fatal("system role must not be granted to operators")
	}
	if _, err := l.a.CreateOperator(context.Background(), "ops@example.com", role.RealmOwner, 48*time.Hour); err == nil {
		t.Fatal("ttl over 24h accepted")
	}
}

func TestAdminAPIWithOperatorSession(t *testing.T) {
	l := newLoginEnv(t)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)

	status, res := l.admin(t, "/v1/admin/users", owner, map[string]string{"email": "Bob@Example.com"})
	if status != 201 {
		t.Fatalf("create user: %d %v", status, res)
	}
	bob := res["user_id"].(string)
	if status, res := l.admin(t, "/v1/admin/users", owner, map[string]string{"email": "bob@example.com"}); status != 409 || res["error"] != "email_exists" {
		t.Fatalf("duplicate: %d %v", status, res)
	}
	if status, res := l.admin(t, "/v1/admin/users", support, map[string]string{"email": "c@example.com"}); status != 403 || res["error"] != "permission_denied" {
		t.Fatalf("support: %d %v", status, res)
	}

	// 運営者が発行したリンクで本人がログインできる。
	status, res = l.admin(t, "/v1/admin/users/"+bob+":login_link", owner, map[string]any{"ttl_seconds": 60})
	if status != 200 {
		t.Fatalf("login link: %d %v", status, res)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": res["token"], "return_token": true})
	var login struct {
		SessionID string `json:"session_id"`
		Token     string `json:"token"`
		UserID    string `json:"user_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	if w.Code != 200 || login.UserID != bob {
		t.Fatalf("bob login: %d %s", w.Code, w.Body)
	}
	if status, _ := l.admin(t, "/v1/admin/users/usr_nosuchuser00000000000000:login_link", owner, nil); status != 404 {
		t.Fatalf("unknown user: %d", status)
	}

	// セッションの失効。
	if status, res := l.admin(t, "/v1/admin/sessions/"+login.SessionID+":revoke", owner, nil); status != 204 {
		t.Fatalf("revoke: %d %v", status, res)
	}
	if _, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, login.Token); err == nil {
		// キャッシュの反映遅れの上限を過ぎれば無効になる。
		l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
		if _, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, login.Token); err == nil {
			t.Fatal("revoked session still valid")
		}
	}

	// IdP 接続の登録。シークレットは応答にも監査ログにも出ない。
	conn := map[string]any{"slug": "google", "preset": "google", "client_id": "cid", "client_secret": "very-secret-value",
		"redirect_uris": []string{"https://app.example/callback"}}
	_, owner = l.operator(t, "owner@example.com", role.RealmOwner) // 上で時計を進めたので認証し直す
	if status, res := l.admin(t, "/v1/admin/connections", owner, conn); status != 201 || res["slug"] != "google" {
		t.Fatalf("connection: %d %v", status, res)
	}
	if status, res := l.admin(t, "/v1/admin/connections", owner, conn); status != 409 {
		t.Fatalf("duplicate slug: %d %v", status, res)
	}
	conn["slug"], conn["redirect_uris"] = "g2", []string{}
	if status, res := l.admin(t, "/v1/admin/connections", owner, conn); status != 400 || res["error"] != "invalid_connection" {
		t.Fatalf("no redirect_uris: %d %v", status, res)
	}
	conn["slug"] = "Bad Slug"
	if status, _ := l.admin(t, "/v1/admin/connections", owner, conn); status != 400 {
		t.Fatalf("bad slug: %d", status)
	}
	for _, e := range l.auditTypes(t) {
		if b, _ := json.Marshal(e); strings.Contains(string(b), "very-secret-value") {
			t.Fatalf("client secret in audit: %s", b)
		}
	}
	// out は応答だけを集める（要求の本文は入れない）。
	if strings.Contains(l.out.String(), "very-secret-value") {
		t.Fatal("client secret in a response")
	}

	// 直近の認証を過ぎた運営者のセッションは、再認証を求める。
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.MaxAuthAge.Default.D() + time.Minute)
	if status, res := l.admin(t, "/v1/admin/users", owner, map[string]string{"email": "late@example.com"}); status != 401 || res["error"] != "reauthentication_required" {
		t.Fatalf("stale operator session: %d %v", status, res)
	}
}

// 1要素目だけの制限つきのセッションでは、運営者でも管理 API を使えない（2段階認証を飛ばせない）。
func TestAdminAPIRejectsRestrictedSession(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.operator(t, "owner@example.com", role.RealmOwner)
	secret, status, res, _ := l.enrollTOTP(t, full)
	if status != 200 {
		t.Fatalf("totp confirm: %d %v", status, res)
	}
	login, restricted := l.login(t, "owner@example.com")
	if login["next"] != "second_factor" {
		t.Fatalf("login: %v", login)
	}
	if status, res := l.admin(t, "/v1/admin/users", restricted, map[string]string{"email": "a@example.com"}); status != 401 || res["error"] != "authentication_failed" {
		t.Fatalf("restricted session on admin API: %d %v", status, res)
	}
	l.advance(30 * time.Second)
	status, _, upgraded := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if status != 200 || upgraded == "" {
		t.Fatalf("verify: %d", status)
	}
	if status, res := l.admin(t, "/v1/admin/users", upgraded, map[string]string{"email": "a@example.com"}); status != 201 {
		t.Fatalf("upgraded session: %d %v", status, res)
	}
}

func TestAdminAPIRequiresAuth(t *testing.T) {
	l := newLoginEnv(t)
	for _, tok := range []string{"", "garbage", "ses_00000000000000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if status, res := l.admin(t, "/v1/admin/users", tok, map[string]string{"email": "a@example.com"}); status != 401 || res["error"] != "authentication_failed" {
			t.Fatalf("%q: %d %v", tok, status, res)
		}
	}
	// 配信用のサービスアカウントは管理操作をできない。
	if status, _ := l.admin(t, "/v1/admin/users", l.apiKey, map[string]string{"email": "a@example.com"}); status != 403 {
		t.Fatalf("delivery account: %d", status)
	}
	// 一般のユーザーのセッションでも同じ。
	_, cookie := l.login(t, "user@example.com")
	if status, _ := l.admin(t, "/v1/admin/users", cookie, map[string]string{"email": "b@example.com"}); status != 403 {
		t.Fatalf("plain user: %d", status)
	}
}
