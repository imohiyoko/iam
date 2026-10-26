package app

import (
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
)

// M2 の完了条件（roadmap.md M2）。条件ごとのテスト：
//   - 最後の認証手段・最後の確認済みメールを本人が消せない：TestUnlinkLastMethod、TestPasskeyLastMethod、TestAddAndRemoveEmail
//   - 無効化した passkey の再登録が拒否される：TestPasskeyRegisterLoginRevoke、下の E2E
//   - 偽の時計で、予約した停止と有効期間の境界が時刻どおりに効く：TestAdminSuspensions、TestAdminValidity、authn/account の TestSuspensionBoundaries
//   - 復旧専用のセッションで認証手段の登録以外が拒否される（復旧の完了とログアウトは使える。ADR 0054）：TestRecoveryCodeFlow ほか（assertRecoveryOnly）、下の E2E
//   - 無効化した認証情報で作られたセッションが使えなくなる：TestPasskeyRegisterLoginRevoke、TestAdminRevokeCredentials、下の E2E
//
// 下の E2E はゴール（1人が複数の手段を持ち、失っても戻れる）を通しで確かめる。

func TestE2EM2LoseEverythingAndRecover(t *testing.T) {
	l := newRecoveryEnv(t, nil)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	l.advance(time.Second)
	if status, _ := l.addEmail(t, cookie, "pat@work.example"); status != 200 {
		t.Fatal("add email")
	}
	a := passkeytest.New(passkeyOrigin)
	status, reg := l.registerPasskey(t, cookie, a, "Phone")
	if status != 200 {
		t.Fatalf("register: %d %v", status, reg)
	}
	codes := codesOf(t, reg["recovery_codes"])
	status, _, pcookie := l.passkeyLogin(t, a)
	if status != 200 {
		t.Fatalf("passkey login: %d", status)
	}

	// 侵害の初動：運営者が全認証情報（リカバリーコードも）と全セッションを無効化する。
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	if status, out := l.admin(t, "/v1/admin/users/"+uid+"/credentials:revoke-all", sec, nil); status != 200 || out["recovery_codes"] != 10.0 {
		t.Fatalf("revoke all: %d %v", status, out)
	}
	for _, c := range []string{cookie, pcookie} {
		if status, _ := l.me(t, c); status != 401 {
			t.Fatalf("session after revoke all: %d", status)
		}
	}
	if status, _, _ := l.passkeyLogin(t, a); status != 401 {
		t.Fatalf("revoked passkey login: %d", status)
	}
	if status, _ := l.mePost(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": codes[0]}); status != 401 {
		t.Fatalf("revoked recovery code: %d", status)
	}

	// 2つ目のメールで復旧する。
	_, st := l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@work.example"})
	code := l.claimLast(t)
	status, out, rec := l.post(t, "", "/v1/recovery/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("email recovery: %d %v", status, out)
	}
	assertRecoveryOnly(t, l, rec)
	l.advance(time.Second)
	// 無効化した passkey は復旧でも登録し直せない。
	if status, out := l.registerPasskey(t, rec, a, ""); status != 409 || out["error"] != "passkey_revoked" {
		t.Fatalf("re-register revoked passkey: %d %v", status, out)
	}
	b := passkeytest.New(passkeyOrigin)
	if status, _ := l.registerPasskey(t, rec, b, "New phone"); status != 200 {
		t.Fatal("register new passkey")
	}
	status, done := l.mePost(t, rec, "/v1/recovery:complete", nil)
	if status != 200 {
		t.Fatalf("complete: %d %v", status, done)
	}
	fresh := codesOf(t, done["recovery_codes"])
	status, _, ncookie := l.passkeyLogin(t, b)
	if status != 200 || l.remaining(t, ncookie) != 10 {
		t.Fatalf("login after recovery: %d", status)
	}
	// 新しいリカバリーコードは使える（次に失ったとき）。
	status, out, rec2 := l.post(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": fresh[0]})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("new recovery code: %d %v", status, out)
	}
	// 復旧専用のセッションでもログアウトはできる（ADR 0054）。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/logout", nil, "Cookie", sessionCookie+"="+rec2); w.Code != 204 {
		t.Fatalf("logout in recovery: %d %s", w.Code, w.Body)
	}
}
