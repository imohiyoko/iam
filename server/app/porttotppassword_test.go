package app

import (
	"encoding/base32"
	"slices"
	"strings"
	"testing"
	"time"
)

// TOTP とパスワードを認証方式のポートに載せたこと（ADR 0101）を HTTP で確かめる。汎用のパスと方式専用のパスは同じ処理で動く。

func TestTOTPGenericPaths(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.login(t, "gen@example.com")
	status, st := l.mePost(t, full, "/v1/me/credentials/totp:enroll-begin", nil)
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	p := st["payload"].(map[string]any)
	if !strings.HasPrefix(p["uri"].(string), "otpauth://totp/") {
		t.Fatalf("payload: %v", p)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(p["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, res := l.mePost(t, full, "/v1/me/credentials/totp:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": l.code(t, secret)}})
	if status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	cid := res["credential"].(map[string]any)["id"].(string)
	// 方式専用の登録の開始は、汎用で登録した TOTP も数える（1人に1つ）。
	if status, res := l.mePost(t, full, "/v1/me/totp:start", nil); status != 409 || res["error"] != "totp_exists" {
		t.Fatalf("legacy start after generic enrollment: %d %v", status, res)
	}

	login, restricted := l.login(t, "gen@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"totp"}) {
		t.Fatalf("login: %v", login)
	}
	l.advance(30 * time.Second)
	status, ch, _ := l.post(t, restricted, "/v1/login/second-factor/totp:begin", nil)
	if status != 200 {
		t.Fatalf("second factor begin: %d %v", status, ch)
	}
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor/totp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"code": "abcdef"}}); status != 401 {
		t.Fatalf("wrong code: %d", status)
	}
	status, res, upgraded := l.post(t, restricted, "/v1/login/second-factor/totp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"code": l.code(t, secret)}})
	if status != 200 || res["next"] != nil || upgraded == "" {
		t.Fatalf("second factor complete: %d %v", status, res)
	}
	// amr は方式専用のパスと同じ（ADR 0093 の AAL も変わらない）。
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	// 同じ時間窓のコードは方式専用のパスでも通らない（使った窓は方式のデータにある）。
	_, again := l.login(t, "gen@example.com")
	if status, _, _ := l.post(t, again, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); status != 401 {
		t.Fatalf("reuse through the legacy path: %d", status)
	}
	// 汎用で登録した TOTP も方式専用のパスで無効化できる。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp/"+cid+":revoke", nil, "Cookie", sessionCookie+"="+upgraded); w.Code != 204 {
		t.Fatalf("legacy revoke: %d %s", w.Code, w.Body)
	}
	if login, _ := l.login(t, "gen@example.com"); login["next"] != nil {
		t.Fatalf("login after revoke: %v", login)
	}
}

func TestPasswordGenericPaths(t *testing.T) {
	l := newPasswordEnv(t)
	_, cookie := l.login(t, "gp@example.com")
	_, other := l.login(t, "gp@example.com")
	const pw = "a long and memorable passphrase"
	if status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": "short"}}); status != 400 || res["error"] != "password_too_short" {
		t.Fatalf("too short: %d %v", status, res)
	}
	status, st := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": pw}})
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-complete", map[string]any{"flow_id": st["flow_id"]})
	if status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	cid := res["credential"].(map[string]any)["id"].(string)
	// 他のセッションは失効し、このセッションは残る（5.2。方式専用のパスと同じ）。
	if status, _ := l.me(t, other); status != 401 {
		t.Fatalf("other session after set: %d", status)
	}
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("current session after set: %d", status)
	}
	// 置き換えには今のパスワードが要る。
	if status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": "another long passphrase"}}); status != 409 || res["error"] != "current_password_mismatch" {
		t.Fatalf("change without current: %d %v", status, res)
	}

	login := func(email, password string) (int, map[string]any, string) {
		status, ch, _ := l.post(t, "", "/v1/login/methods/password:begin", nil)
		if status != 200 {
			t.Fatalf("login begin: %d %v", status, ch)
		}
		return l.post(t, "", "/v1/login/methods/password:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"email": email, "password": password}})
	}
	status, res, pcookie := login("GP@example.com", pw)
	if status != 200 || pcookie == "" {
		t.Fatalf("generic login: %d %v", status, res)
	}
	if got := amr(t, l, pcookie); !slices.Equal(got, []any{"pwd"}) {
		t.Fatalf("amr: %v", got)
	}
	for _, c := range [][2]string{{"gp@example.com", "wrong but long enough"}, {"nobody@example.com", pw}} {
		if status, res, _ := login(c[0], c[1]); status != 401 || res["error"] != "authentication_failed" {
			t.Fatalf("login %v: %d %v", c, status, res)
		}
	}
	// 方式専用のパスでも同じパスワードで入れる。
	if status, _, _ := l.passwordLogin(t, "gp@example.com", pw); status != 200 {
		t.Fatalf("legacy login: %d", status)
	}
	// 汎用の無効化。パスワードを外すと、今のセッション以外は失効する。
	_, other = l.login(t, "gp@example.com")
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/credentials/"+cid+":revoke", nil, "Cookie", sessionCookie+"="+cookie); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if status, _ := l.me(t, other); status != 401 {
		t.Fatalf("other session after revoke: %d", status)
	}
	if status, _, _ := l.passwordLogin(t, "gp@example.com", pw); status != 401 {
		t.Fatalf("login after revoke: %d", status)
	}
}
