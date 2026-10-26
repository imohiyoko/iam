package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
)

// 運営者による認証情報の無効化（design.md 4.6）を HTTP で確かめる。

func (l *loginEnv) adminGet(t *testing.T, path, bearer string, out any) int {
	t.Helper()
	w := l.do(t, l.a.AdminHandler(), "GET", path, nil, "Authorization", "Bearer "+bearer)
	if out != nil {
		_ = json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

type userCredentials struct {
	Passkeys []struct{ ID string } `json:"passkeys"`
	Totp     []struct{ ID string } `json:"totp"`
}

func TestAdminRevokeCredentials(t *testing.T) {
	l := newPasskeyEnv(t)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	a := passkeytest.New(passkeyOrigin)
	if status, _ := l.registerPasskey(t, cookie, a, "Key"); status != 200 {
		t.Fatalf("register: %d", status)
	}
	secret, status, _, _ := l.enrollTOTP(t, cookie)
	if status != 200 {
		t.Fatalf("totp: %d", status)
	}
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)

	if status := l.adminGet(t, "/v1/admin/users/"+uid+"/credentials", support, nil); status != 403 {
		t.Fatalf("support lists credentials: %d", status)
	}
	var c userCredentials
	if status := l.adminGet(t, "/v1/admin/users/"+uid+"/credentials", sec, &c); status != 200 || len(c.Passkeys) != 1 || len(c.Totp) != 1 {
		t.Fatalf("credentials: %d %+v", status, c)
	}
	// 本人なら最後の手段で消せない passkey も、運営者は無効化できる。
	via := l.a.accounts.VerifiedVia
	l.a.accounts.VerifiedVia = nil
	path := "/v1/admin/users/" + uid + "/credentials/" + c.Passkeys[0].ID + ":revoke"
	if status, res := l.admin(t, path, sec, nil); status != 204 {
		t.Fatalf("revoke passkey: %d %v", status, res)
	}
	if status, _ := l.admin(t, path, sec, nil); status != 404 {
		t.Fatalf("revoke twice: %d", status)
	}
	l.a.accounts.VerifiedVia = via
	// 別のユーザーの認証情報は見つからない扱い。
	other, _ := l.login(t, "eve@example.com")
	if status, _ := l.admin(t, "/v1/admin/users/"+other["user_id"].(string)+"/credentials/"+c.Totp[0].ID+":revoke", sec, nil); status != 404 {
		t.Fatalf("revoke via another user: %d", status)
	}
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+"/password:revoke", sec, nil); status != 404 {
		t.Fatalf("revoke missing password: %d", status)
	}

	// TOTP を2要素目に使ったセッションは、TOTP を無効化すると遅くとも validity_max_delay の後に使えない。
	_, restricted := l.login(t, "pat@example.com")
	l.advance(30 * time.Second)
	_, _, mfa := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if status, _ := l.me(t, mfa); status != 200 {
		t.Fatalf("mfa session: %d", status)
	}
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+"/credentials/"+c.Totp[0].ID+":revoke", sec, nil); status != 204 {
		t.Fatalf("revoke totp: %d", status)
	}
	l.advance(l.e.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if status, _ := l.me(t, mfa); status != 401 {
		t.Fatalf("session of revoked totp: %d", status)
	}

	// 一括の無効化は、残りの認証情報と全セッションをすぐに無効にする。
	if _, status, _, _ := l.enrollTOTP(t, cookie); status != 200 {
		t.Fatalf("totp again: %d", status)
	}
	status, out := l.admin(t, "/v1/admin/users/"+uid+"/credentials:revoke-all", sec, nil)
	if status != 200 || out["passkeys"] != 0.0 || out["totp"] != 1.0 || out["sessions"].(float64) < 1 {
		t.Fatalf("revoke all: %d %v", status, out)
	}
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("session after revoke all: %d", status)
	}
	c = userCredentials{}
	if status := l.adminGet(t, "/v1/admin/users/"+uid+"/credentials", sec, &c); status != 200 || len(c.Passkeys)+len(c.Totp) != 0 {
		t.Fatalf("credentials after revoke all: %d %+v", status, c)
	}
	if status, _ := l.admin(t, "/v1/admin/users/usr_missing/credentials:revoke-all", sec, nil); status != 404 {
		t.Fatalf("unknown user: %d", status)
	}
}
