package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// アカウントの復旧（design.md 4.12）を HTTP で確かめる。

// newRecoveryEnv は passkey と警告（フィーチャー warnings）を使える構成。
func newRecoveryEnv(t *testing.T, edit func(*config.Config)) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin}
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

func codesOf(t *testing.T, v any) []string {
	t.Helper()
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.(string))
	}
	if len(out) != 10 {
		t.Fatalf("recovery codes = %v", v)
	}
	return out
}

func (l *loginEnv) remaining(t *testing.T, cookie string) float64 {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 {
		t.Fatalf("methods: %d %s", w.Code, w.Body)
	}
	return out["recovery_codes_remaining"].(float64)
}

// 復旧専用のセッションでは、新しい認証手段の登録と完了のほかは使えない（roadmap M2 の完了条件）。
func assertRecoveryOnly(t *testing.T, l *loginEnv, cookie string) {
	t.Helper()
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("sessions list in recovery: %d", status)
	}
	for _, path := range []string{"/v1/me/recovery-codes:regenerate", "/v1/me/emails:start", "/v1/me/identities/google:start", "/v1/me/sessions/ses_x:revoke"} {
		if status, out := l.mePost(t, cookie, path, map[string]string{"email": "x@example.com"}); status != 401 {
			t.Fatalf("%s in recovery: %d %v", path, status, out)
		}
	}
	if l.remaining(t, cookie) < 0 {
		t.Fatal("methods must be readable in recovery")
	}
}

func TestRecoveryCodeFlow(t *testing.T) {
	l := newPasskeyEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	if l.remaining(t, cookie) != 0 {
		t.Fatal("codes before a strong method")
	}
	// 最初の強い認証手段の登録で、コードを1回だけ返す。
	_, status, res, _ := l.enrollTOTP(t, cookie)
	if status != 200 {
		t.Fatalf("totp: %d %v", status, res)
	}
	codes := codesOf(t, res["recovery_codes"])
	if l.remaining(t, cookie) != 10 {
		t.Fatal("remaining after enroll")
	}
	a := passkeytest.New(passkeyOrigin)
	if status, res := l.registerPasskey(t, cookie, a, "Key"); status != 200 || res["recovery_codes"] != nil {
		t.Fatalf("second strong method: %d %v", status, res)
	}

	// 失敗の理由は返さない。
	if status, out := l.mePost(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": "AAAA-BBBB-CCCC-DDDD"}); status != 401 || out["error"] != "authentication_failed" {
		t.Fatalf("wrong code: %d %v", status, out)
	}
	status, out, rec := l.post(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": codes[0]})
	if status != 200 || out["next"] != "recovery" || rec == "" {
		t.Fatalf("redeem: %d %v", status, out)
	}
	assertRecoveryOnly(t, l, rec)
	if status, out := l.mePost(t, rec, "/v1/recovery:complete", nil); status != 409 || out["error"] != "new_method_required" {
		t.Fatalf("complete before a new method: %d %v", status, out)
	}
	b := passkeytest.New(passkeyOrigin)
	l.advance(time.Second)
	if status, res := l.registerPasskey(t, rec, b, "New key"); status != 200 || res["recovery_codes"] != nil {
		t.Fatalf("register in recovery: %d %v", status, res)
	}
	status, out = l.mePost(t, rec, "/v1/recovery:complete", nil)
	if status != 200 || out["sessions_revoked"].(float64) < 2 {
		t.Fatalf("complete: %d %v", status, out)
	}
	fresh := codesOf(t, out["recovery_codes"])
	// 全セッションが失効し、古いコードは使えない。新しい passkey とコードで入れる。
	for _, c := range []string{cookie, rec} {
		if status, _ := l.me(t, c); status != 401 {
			t.Fatalf("session after recovery: %d", status)
		}
	}
	if status, _ := l.mePost(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": codes[1]}); status != 401 {
		t.Fatalf("old code after recovery: %d", status)
	}
	if status, _, c := l.passkeyLogin(t, b); status != 200 || c == "" {
		t.Fatalf("login with the new passkey: %d", status)
	} else if l.remaining(t, c) != 10 {
		t.Fatal("remaining after recovery")
	} else {
		// 作り直しは直近の認証を求める。
		status, out := l.mePost(t, c, "/v1/me/recovery-codes:regenerate", nil)
		if status != 200 {
			t.Fatalf("regenerate: %d %v", status, out)
		}
		codesOf(t, out["recovery_codes"])
		l.advance(l.e.cfg.Security.Session.MaxAuthAge.Default.D() + time.Second)
		if status, out := l.mePost(t, c, "/v1/me/recovery-codes:regenerate", nil); status != 401 || out["error"] != "reauthentication_required" {
			t.Fatalf("regenerate without recent auth: %d %v", status, out)
		}
	}
	if status, _ := l.mePost(t, "", "/v1/recovery/code:redeem", map[string]string{"email": "pat@example.com", "code": fresh[0]}); status != 401 {
		t.Fatalf("code replaced by regenerate: %d", status)
	}
}

func TestEmailRecovery(t *testing.T) {
	l := newRecoveryEnv(t, nil)
	_, cookie := l.login(t, "pat@example.com")
	if _, status, _, _ := l.enrollTOTP(t, cookie); status != 200 {
		t.Fatal("totp")
	}
	// 未登録のアドレスでも同じ応答で、通知は送らない。
	before := l.notes.count()
	if status, out := l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "nobody@example.com"}); status != 200 || out["flow_id"] == nil {
		t.Fatalf("start unknown: %d %v", status, out)
	}
	if _, err := l.a.notifier.Flush(context.Background()); err != nil || l.notes.count() != before {
		t.Fatalf("notification for unknown address: %v", err)
	}
	status, st := l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"})
	if status != 200 {
		t.Fatalf("start: %d %v", status, st)
	}
	code := l.claimLast(t)
	if n := l.notes.last(t); n.Type != notify.TypeAccountRecovery {
		t.Fatalf("notification = %+v", n)
	}
	// ログインのフローには使えない。
	if status, _ := l.mePost(t, "", "/v1/login/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code}); status != 401 {
		t.Fatalf("recovery flow used for login: %d", status)
	}
	_, st = l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"})
	code = l.claimLast(t)
	status, out, rec := l.post(t, "", "/v1/recovery/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("verify: %d %v", status, out)
	}
	ws, _ := out["warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["code"] != "recovered_via_email" {
		t.Fatalf("warnings = %v", out["warnings"])
	}
	assertRecoveryOnly(t, l, rec)
	l.advance(time.Second)
	if status, _ := l.registerPasskey(t, rec, passkeytest.New(passkeyOrigin), "Key"); status != 200 {
		t.Fatal("register in recovery")
	}
	before = l.notes.count()
	if status, out := l.mePost(t, rec, "/v1/recovery:complete", nil); status != 200 {
		t.Fatalf("complete: %d %v", status, out)
	}
	// 確認済みの全メールに完了を知らせる。
	if _, err := l.a.notifier.Flush(context.Background()); err != nil || l.notes.count() != before+1 || l.notes.last(t).Type != notify.TypeAccountRecovered {
		t.Fatalf("recovered notification: %v %d", err, l.notes.count()-before)
	}

	// realm の設定で警告を deny にすれば、メールでは復旧できない。
	l2 := newRecoveryEnv(t, func(c *config.Config) { c.Security.Warnings = map[string]string{"recovered_via_email": "deny"} })
	l2.login(t, "pat@example.com")
	_, st = l2.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"})
	code = l2.claimLast(t)
	if status, out := l2.mePost(t, "", "/v1/recovery/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code}); status != 403 {
		t.Fatalf("denied email recovery: %d %v", status, out)
	}
	// 経路を無効にすれば 404。
	l3 := newRecoveryEnv(t, func(c *config.Config) { c.Security.Recovery.Methods = []string{"recovery_code"} })
	if status, _ := l3.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"}); status != 404 {
		t.Fatalf("disabled email recovery: %d", status)
	}
}

// 運営者の復旧用リンク。security_risk で止められたユーザーも、復旧で認証手段を入れ替えられる（停止はそのまま）。
func TestRecoveryLinkWhileSuspended(t *testing.T) {
	l := newPasskeyEnv(t)
	res, _ := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	if status, sp := l.admin(t, "/v1/admin/users/"+uid+"/suspensions", sec, map[string]string{"category": "security_risk", "reason": "takeover"}); status != 201 {
		t.Fatalf("suspend: %d %v", status, sp)
	}
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+":recovery_link", sec, map[string]string{"reason": "x"}); status != 403 {
		t.Fatalf("link by security: %d", status)
	}
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+":recovery_link", support, map[string]string{"reason": ""}); status != 400 {
		t.Fatalf("link without reason: %d", status)
	}
	status, link := l.admin(t, "/v1/admin/users/"+uid+":recovery_link", support, map[string]string{"reason": "verified by phone"})
	if status != 200 {
		t.Fatalf("link: %d %v", status, link)
	}
	// ログイン用のリンクとしては使えない。
	if status, _ := l.mePost(t, "", "/v1/login/link:redeem", map[string]string{"token": link["token"].(string)}); status != 401 {
		t.Fatalf("recovery link used for login: %d", status)
	}
	_, link = l.admin(t, "/v1/admin/users/"+uid+":recovery_link", support, map[string]string{"reason": "verified by phone"})
	status, out, rec := l.post(t, "", "/v1/recovery/link:redeem", map[string]string{"token": link["token"].(string)})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("redeem: %d %v", status, out)
	}
	if status, _, _ := l.post(t, "", "/v1/recovery/link:redeem", map[string]string{"token": link["token"].(string)}); status != 401 {
		t.Fatalf("redeem twice: %d", status)
	}
	assertRecoveryOnly(t, l, rec)
	l.advance(time.Second)
	b := passkeytest.New(passkeyOrigin)
	if status, _ := l.registerPasskey(t, rec, b, "Key"); status != 200 {
		t.Fatal("register while suspended")
	}
	if status, out := l.mePost(t, rec, "/v1/recovery:complete", nil); status != 200 {
		t.Fatalf("complete: %d %v", status, out)
	}
	// 停止はセキュリティ担当が解除するまで続く。
	if status, out, _ := l.passkeyLogin(t, b); status != 403 {
		t.Fatalf("login while suspended: %d %v", status, out)
	}
}

// 下位のロールの運営者は、上位のロールの人に復旧用・ログイン用のリンクを出せない（乗っ取りの防止）。
func TestOperatorLinksRequireCoveringRole(t *testing.T) {
	l := newPasskeyEnv(t)
	ownerID, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	adminID, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	reason := map[string]string{"reason": strings.Repeat("電", 1000)} // 文字数で数える
	if status, out := l.admin(t, "/v1/admin/users/"+adminID+":recovery_link", support, reason); status != 403 {
		t.Fatalf("support → admin recovery link: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+ownerID+":login_link", admin, nil); status != 403 {
		t.Fatalf("admin → owner login link: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+adminID+":recovery_link", owner, reason); status != 200 {
		t.Fatalf("owner → admin recovery link: %d %v", status, out)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+adminID+":recovery_link", owner, map[string]string{"reason": strings.Repeat("電", 1001)}); status != 400 {
		t.Fatalf("reason over 1000 chars: %d %v", status, out)
	}
}
