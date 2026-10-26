package app

import (
	"context"
	"crypto/sha1" // #nosec G505 -- テストの偽の確認
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// メール + パスワード（フィーチャー password。design.md 4.1）を HTTP で確かめる。

type fakeBreach map[string]bool

func (f fakeBreach) Breached(_ context.Context, h string) (bool, error) { return f[h], nil }

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s)) // #nosec G401
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

const leaked = "password1234567890"

func newPasswordEnv(t *testing.T) *loginEnv {
	t.Helper()
	return newLoginEnvDeps(t, func(c *config.Config) {
		c.Features = &[]string{feature.Password, feature.Warnings}
		c.Security.Password.Argon2 = config.Argon2{MemoryKiB: 8, Iterations: 1, Parallelism: 1}
	}, feature.Registered(), func(d *Deps) { d.BreachCheck = fakeBreach{sha1Hex(leaked): true} })
}

func (l *loginEnv) passwordLogin(t *testing.T, email, pw string) (int, map[string]any, string) {
	t.Helper()
	return l.post(t, "", "/v1/login/password", map[string]string{"email": email, "password": pw})
}

func TestPasswordSetLoginChangeRemove(t *testing.T) {
	l := newPasswordEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	_, other := l.login(t, "pat@example.com")
	for pw, code := range map[string]string{"too short": "password_too_short", leaked: "password_breached"} {
		if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": pw}); status != 400 || res["error"] != code {
			t.Fatalf("set %q: %d %v", pw, status, res)
		}
	}
	const pw = "a long and memorable passphrase"
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": pw}); status != 204 {
		t.Fatalf("set: %d %v", status, res)
	}
	// 他のセッションは失効し、このセッションは残る（5.2）。
	if status, _ := l.me(t, other); status != 401 {
		t.Fatalf("other session after set: %d", status)
	}
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("current session after set: %d", status)
	}
	var m struct {
		Password *struct{ CreatedAt time.Time } `json:"password"`
	}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+cookie)
	if json.Unmarshal(w.Body.Bytes(), &m) != nil || m.Password == nil {
		t.Fatal("methods: no password")
	}

	status, res, pcookie := l.passwordLogin(t, "Pat@Example.com", pw)
	if status != 200 || pcookie == "" || res["next"] != nil {
		t.Fatalf("password login: %d %v", status, res)
	}
	if got := amr(t, l, pcookie); len(got) != 1 || got[0] != "pwd" {
		t.Fatalf("amr: %v", got)
	}
	for _, c := range [][2]string{{"pat@example.com", "wrong but long enough"}, {"nobody@example.com", pw}} {
		if status, res, _ := l.passwordLogin(t, c[0], c[1]); status != 401 || res["error"] != "authentication_failed" {
			t.Fatalf("login %v: %d %v", c, status, res)
		}
	}
	// 変更には今のパスワードが要る。
	if status, res := l.mePost(t, pcookie, "/v1/me/password:set", map[string]string{"password": "another long passphrase"}); status != 409 || res["error"] != "current_password_mismatch" {
		t.Fatalf("change without current: %d %v", status, res)
	}
	if status, _ := l.mePost(t, pcookie, "/v1/me/password:set", map[string]string{"password": "another long passphrase", "current_password": pw}); status != 204 {
		t.Fatalf("change: %d", status)
	}
	if status, _, _ := l.passwordLogin(t, "pat@example.com", pw); status != 401 {
		t.Fatalf("old password: %d", status)
	}
	if status, res := l.mePost(t, pcookie, "/v1/me/password:remove", map[string]string{"current_password": "another long passphrase"}); status != 204 {
		t.Fatalf("remove: %d %v", status, res)
	}
	if status, _, _ := l.passwordLogin(t, "pat@example.com", "another long passphrase"); status != 401 {
		t.Fatalf("login after remove: %d", status)
	}
	if status, _ := l.mePost(t, pcookie, "/v1/me/password:remove", map[string]string{"current_password": "x"}); status != 404 {
		t.Fatalf("remove twice: %d", status)
	}
}

func TestPasswordReauthAndBreachWarning(t *testing.T) {
	l := newPasswordEnv(t)
	_, cookie := l.login(t, "quinn@example.com")
	l.advance(l.e.cfg.Security.Session.MaxAuthAge.Default.D() + time.Minute)
	// 初めての設定は直近の認証を求める（盗まれたセッションでパスワードを足させない）。
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": "a long and memorable passphrase"}); status != 401 || res["error"] != "reauthentication_required" {
		t.Fatalf("set without recent auth: %d %v", status, res)
	}
	// 設定の後で漏洩が分かったパスワードは、ログインで警告する。
	_, cookie = l.login(t, "quinn@example.com")
	l.a.password.Breach = nil
	if status, _ := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": leaked}); status != 204 {
		t.Fatalf("set: %d", status)
	}
	l.a.password.Breach = fakeBreach{sha1Hex(leaked): true}
	status, res, _ := l.passwordLogin(t, "quinn@example.com", leaked)
	ws, _ := res["warnings"].([]any)
	if status != 200 || len(ws) != 1 || ws[0].(map[string]any)["code"] != "password_breached" {
		t.Fatalf("login with leaked password: %d %v", status, res)
	}
}

func TestPasswordDisabledByDefault(t *testing.T) {
	l := newLoginEnv(t)
	if status, _, _ := l.passwordLogin(t, "a@example.com", "whatever whatever"); status != 404 {
		t.Fatalf("password login without the feature: %d", status)
	}
}
