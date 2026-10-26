package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/server/config"
)

// passkey の登録・ログイン・無効化（design.md 4.1、4.6、2.5）を HTTP で確かめる。

const passkeyOrigin = "https://login.example.com"

func newPasskeyEnv(t *testing.T) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin, "https://app.example.net"}
	}, nil)
}

// ceremony は開始の応答から flow_id と options を取り出す。
func ceremony(t *testing.T, status int, res map[string]any) (string, []byte) {
	t.Helper()
	if status != 200 {
		t.Fatalf("start: %d %v", status, res)
	}
	opts, err := json.Marshal(res["options"])
	if err != nil {
		t.Fatal(err)
	}
	return res["flow_id"].(string), opts
}

// registerPasskey は Cookie のユーザーに認証器 a を登録する。
func (l *loginEnv) registerPasskey(t *testing.T, cookie string, a *passkeytest.Authenticator, name string) (int, map[string]any) {
	t.Helper()
	status, res := l.mePost(t, cookie, "/v1/me/passkeys:start", nil)
	flow, opts := ceremony(t, status, res)
	cred, err := a.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	return l.mePost(t, cookie, "/v1/me/passkeys:finish", map[string]any{"flow_id": flow, "credential": json.RawMessage(cred), "name": name})
}

// passkeyLogin は認証器 a でログインし、応答とセッションの Cookie を返す。
func (l *loginEnv) passkeyLogin(t *testing.T, a *passkeytest.Authenticator) (int, map[string]any, string) {
	t.Helper()
	status, start := l.mePost(t, "", "/v1/login/passkey:start", nil)
	flow, opts := ceremony(t, status, start)
	cred, err := a.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/passkey:finish", map[string]any{"flow_id": flow, "credential": json.RawMessage(cred)})
	var res map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return w.Code, res, c.Value
		}
	}
	return w.Code, res, ""
}

type myPasskeys struct {
	Passkeys []struct {
		ID             string     `json:"id"`
		Name           string     `json:"name"`
		LastUsedAt     *time.Time `json:"last_used_at"`
		BackupEligible bool       `json:"backup_eligible"`
	} `json:"passkeys"`
}

func (l *loginEnv) passkeys(t *testing.T, cookie string) myPasskeys {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+cookie)
	var m myPasskeys
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("methods: %d %s", w.Code, w.Body)
	}
	return m
}

func TestPasskeyRegisterLoginRevoke(t *testing.T) {
	l := newPasskeyEnv(t)
	first, cookie := l.login(t, "pat@example.com")
	a := passkeytest.New(passkeyOrigin)
	status, res := l.registerPasskey(t, cookie, a, "Phone")
	if status != 200 || res["name"] != "Phone" {
		t.Fatalf("register: %d %v", status, res)
	}
	pid := res["id"].(string)
	if m := l.passkeys(t, cookie); len(m.Passkeys) != 1 || m.Passkeys[0].ID != pid || m.Passkeys[0].LastUsedAt != nil {
		t.Fatalf("methods: %+v", m)
	}
	// 関連付けた別のドメインの画面からもログインできる。
	other := *a
	other.Origin = "https://app.example.net"
	status, login, pcookie := l.passkeyLogin(t, &other)
	if status != 200 || login["user_id"] != first["user_id"] || login["created"] != false || pcookie == "" {
		t.Fatalf("passkey login: %d %v", status, login)
	}
	a.SignCount = other.SignCount
	if _, sessions := l.me(t, pcookie); len(sessions) == 0 {
		t.Fatal("passkey session not usable")
	}
	if status, res := l.mePost(t, cookie, "/v1/me/passkeys/"+pid+":rename", map[string]string{"name": " Work phone "}); status != 200 || res["name"] != "Work phone" {
		t.Fatalf("rename: %d %v", status, res)
	}
	if status, res := l.mePost(t, cookie, "/v1/me/passkeys/"+pid+":rename", map[string]string{"name": "  "}); status != 400 || res["error"] != "invalid_name" {
		t.Fatalf("rename to blank: %d %v", status, res)
	}
	// 別のユーザーの passkey は見つからない扱い。
	_, eve := l.login(t, "eve@example.com")
	if status, _ := l.mePost(t, eve, "/v1/me/passkeys/"+pid+":revoke", nil); status != 404 {
		t.Fatalf("revoke another user's passkey: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/passkeys/"+pid+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	if m := l.passkeys(t, cookie); len(m.Passkeys) != 0 {
		t.Fatalf("methods after revoke: %+v", m)
	}
	if status, res, _ := l.passkeyLogin(t, a); status != 401 || res["error"] != "authentication_failed" {
		t.Fatalf("login with revoked passkey: %d %v", status, res)
	}
	// その passkey で作ったセッションは、遅くとも validity_max_delay の後に使えない。
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if status, _ := l.me(t, pcookie); status != 401 {
		t.Fatalf("session of revoked passkey: %d", status)
	}
	// 無効化した passkey は再登録できない（4.6）。
	if status, res := l.registerPasskey(t, cookie, a, ""); status != 409 || res["error"] != "passkey_revoked" {
		t.Fatalf("re-register revoked: %d %v", status, res)
	}
	if status, res := l.registerPasskey(t, cookie, passkeytest.New(passkeyOrigin), ""); status != 200 || res["name"] != "Passkey" {
		t.Fatalf("register new: %d %v", status, res)
	}
}

func TestPasskeyLastMethod(t *testing.T) {
	l := newPasskeyEnv(t)
	_, cookie := l.login(t, "quinn@example.com")
	a := passkeytest.New(passkeyOrigin)
	_, res := l.registerPasskey(t, cookie, a, "Key")
	pid := res["id"].(string)
	l.a.accounts.VerifiedVia = nil // メールのコードを使えなくし、passkey を最後のログインの手段にする
	if status, res := l.mePost(t, cookie, "/v1/me/passkeys/"+pid+":revoke", nil); status != 409 || res["error"] != "last_method" {
		t.Fatalf("revoke last method: %d %v", status, res)
	}
}

func TestPasskeyRejects(t *testing.T) {
	l := newPasskeyEnv(t)
	_, cookie := l.login(t, "rae@example.com")
	a := passkeytest.New(passkeyOrigin)
	if status, res := l.registerPasskey(t, cookie, a, ""); status != 200 {
		t.Fatalf("register: %d %v", status, res)
	}
	if status, res := l.registerPasskey(t, cookie, a, ""); status != 409 || res["error"] != "passkey_exists" {
		t.Fatalf("register twice: %d %v", status, res)
	}
	// 関連付けていない origin からは使えない。
	evil := *a
	evil.Origin = "https://evil.example.org"
	if status, _, _ := l.passkeyLogin(t, &evil); status != 401 {
		t.Fatalf("login from unrelated origin: %d", status)
	}
	// 未ログインでは登録できない。
	if status, _ := l.mePost(t, "", "/v1/me/passkeys:start", nil); status != 401 {
		t.Fatalf("anonymous register: %d", status)
	}
	// 関連付けた origin の一覧を返す（Related Origin Requests）。
	w := l.do(t, l.a.PublicHandler(), "GET", "/.well-known/webauthn", nil)
	var ro struct{ Origins []string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ro) != nil || len(ro.Origins) != 2 {
		t.Fatalf("well-known: %d %s", w.Code, w.Body)
	}
}

func TestPasskeyDisabledWithoutRelyingParty(t *testing.T) {
	l := newLoginEnv(t)
	if status, _ := l.mePost(t, "", "/v1/login/passkey:start", nil); status != 404 {
		t.Fatalf("start without rp: %d", status)
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/.well-known/webauthn", nil); w.Code != 404 {
		t.Fatalf("well-known without rp: %d", w.Code)
	}
}
