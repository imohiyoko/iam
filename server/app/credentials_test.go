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

func TestAdminRevokePassword(t *testing.T) {
	l := newPasswordEnv(t)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	const pw = "a long and memorable passphrase"
	if status, _ := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": pw}); status != 204 {
		t.Fatalf("set: %d", status)
	}
	_, pcookie := l.passwordLoginCookie(t, "pat@example.com", pw)
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+"/password:revoke", sec, nil); status != 204 {
		t.Fatalf("revoke password: %d", status)
	}
	// パスワードはセッションの認証情報に入らないので、全セッションをすぐに失効させる。
	for _, c := range []string{cookie, pcookie} {
		if status, _ := l.me(t, c); status != 401 {
			t.Fatalf("session after password revoke: %d", status)
		}
	}
	if status, _, _ := l.passwordLogin(t, "pat@example.com", pw); status != 401 {
		t.Fatalf("login after revoke: %d", status)
	}
}

func (l *loginEnv) passwordLoginCookie(t *testing.T, email, pw string) (int, string) {
	t.Helper()
	status, _, c := l.passwordLogin(t, email, pw)
	if status != 200 || c == "" {
		t.Fatalf("password login: %d", status)
	}
	return status, c
}

// 下位のロールの運営者は、上位のロールの運営者の認証情報を無効化できず、停止・有効期間も変えられない（ADR 0052、0053）。
func TestAdminActionsRespectOutranks(t *testing.T) {
	l := newPasskeyEnv(t)
	ownerID, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	adminID, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	users := "/v1/admin/users/" + ownerID
	for _, path := range []string{users + "/credentials:revoke-all", users + "/password:revoke", users + "/credentials/psk_missing:revoke"} {
		if status, out := l.admin(t, path, sec, nil); status != 403 {
			t.Fatalf("%s by security: %d %v", path, status, out)
		}
	}
	if status, out := l.admin(t, users+"/suspensions", sec, map[string]any{"category": "security_risk", "reason": "x"}); status != 403 {
		t.Fatalf("suspend owner by security: %d %v", status, out)
	}
	if status, out := l.adminDo(t, "PATCH", admin, users, map[string]any{"valid_until": l.a.deps.Clock.Now().Add(time.Hour)}); status != 403 {
		t.Fatalf("validity of owner by admin: %d %v", status, out)
	}
	// 上位からは変えられる。上位が付けた停止を下位は解除できない。
	status, out := l.admin(t, "/v1/admin/users/"+adminID+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "x"})
	if status != 201 {
		t.Fatalf("suspend admin by owner: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/suspensions/"+out["id"].(string)+":lift", sec, map[string]any{"reason": "x"}); status != 403 {
		t.Fatalf("lift admin's suspension by security: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/suspensions/"+out["id"].(string)+":lift", owner, map[string]any{"reason": "x"}); status != 200 {
		t.Fatalf("lift by owner: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+adminID+"/credentials:revoke-all", owner, nil); status != 200 {
		t.Fatalf("revoke admin's credentials by owner: %d %v", status, out)
	}

	// 最後の使える realm:owner は止められず、終わりのある有効期間も付けられない（予約も同じ）。
	if status, out := l.admin(t, users+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "x"}); status != 409 || out["error"] != "last_owner" {
		t.Fatalf("suspend the last owner: %d %v", status, out)
	}
	if status, out := l.admin(t, users+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "x",
		"starts_at": l.a.deps.Clock.Now().Add(time.Hour)}); status != 409 {
		t.Fatalf("schedule a suspension of the last owner: %d %v", status, out)
	}
	if status, out := l.adminDo(t, "PATCH", owner, users, map[string]any{"valid_until": l.a.deps.Clock.Now().Add(time.Hour)}); status != 409 || out["error"] != "last_owner" {
		t.Fatalf("validity of the last owner: %d %v", status, out)
	}
	if status, out := l.adminDo(t, "PATCH", owner, users, map[string]any{}); status != 200 {
		t.Fatalf("clear the validity of the last owner: %d %v", status, out)
	}

	// リソースを限った付与も比べる（上で無効化した admin とは別の運営者で）。
	admin2ID, admin2 := l.operator(t, "admin2@example.com", role.RealmAdmin)
	_, _ = l.login(t, "carol@example.com")
	carolID := l.userID(t, "carol@example.com")
	status, out = l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "project-admin", "permissions": []string{"project:admin"}})
	if status != 201 {
		t.Fatalf("create role: %d %v", status, out)
	}
	projectAdmin := out["id"].(string)
	bindOn := func(userID string) {
		t.Helper()
		if status, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": projectAdmin, "principal_type": "user", "principal_id": userID,
			"resource_type": "project", "resource_id": "p1"}); status != 201 {
			t.Fatalf("bind on p1: %d %v", status, out)
		}
	}
	bindOn(carolID)
	carol := "/v1/admin/users/" + carolID + "/credentials:revoke-all"
	if status, out := l.admin(t, carol, admin2, nil); status != 403 {
		t.Fatalf("revoke a project admin's credentials without the project role: %d %v", status, out)
	}
	bindOn(admin2ID)
	if status, out := l.admin(t, carol, admin2, nil); status != 200 {
		t.Fatalf("revoke with the same project role: %d %v", status, out)
	}
}
