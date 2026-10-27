package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// M3 の完了条件（roadmap.md M3）。条件ごとのテスト：
//   - 仕事用メールでログインすると会社の Org に入る。passkey の既定 Org も効く：TestInvitationBindsInvitedEmail、TestPasskeyPreferredOrg、下の E2E
//   - Org の管理者から、結び付けたメール以外が見えない：TestInvitationBindsInvitedEmail、下の E2E
//     （連携先へのメールの受け渡しは M5 の OIDC で、同じく Membership に結び付けたメールだけを渡す）
//   - 最後のオーナーは抜けられない。個人ユーザーの退会は Org の設定で止められない：TestLeaveOrg、下の E2E
//   - 削除後、監査ログに残った個人情報が復号できない：shared/eventlog の TestClientSealing、下の E2E
//   - Org をオフにした構成で M1・M2 の E2E がそのまま通る：TestE2EOrgOff
//
// 下の E2E はゴール（1人が個人と会社の顔を持ち、会社の管理者には会社の顔だけが見え、抜けても消しても痕跡が読めない）を通しで確かめる。

func TestE2EM3WorkAndPersonal(t *testing.T) {
	const samUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin}
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
	}, feature.Registered())
	l.ua = samUA

	// 会社の Org を作り、個人のアドレスで登録済みの sam を仕事用のアドレスで招待する。
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	_, home := l.login(t, "sam@home.example")
	samID := l.userID(t, "sam@home.example")
	l.advance(time.Second)
	if code, body := l.addEmail(t, home, "sam@acme.example"); code != 200 {
		t.Fatalf("add work email: %d %v", code, body)
	}
	if code, body := l.invite(t, boss, acme, "sam@acme.example", "member"); code != 201 {
		t.Fatalf("invite: %d %v", code, body)
	}
	_, token := l.claimToken(t)
	if code, body := l.accept(t, home, token); code != 200 {
		t.Fatalf("accept: %d %v", code, body)
	}

	// 仕事用のアドレスでログインすると Acme に、個人のアドレスの passkey（既定は個人 Org）では個人 Org に入る。
	l.advance(time.Second)
	res, work := l.login(t, "sam@acme.example")
	if res["org_id"] != acme || res["user_id"] != samID {
		t.Fatalf("work login: %v", res)
	}
	a := passkeytest.New(passkeyOrigin)
	status, reg := l.registerPasskey(t, work, a, "Phone")
	if status != 200 {
		t.Fatalf("register passkey: %d %v", status, reg)
	}
	personal := ""
	_, orgs := l.myOrgs(t, work)
	for _, o := range orgs.Orgs {
		if o.Kind == "personal" {
			personal = o.ID
		}
	}
	if code, body := l.mePost(t, work, "/v1/me/passkeys/"+reg["id"].(string)+":set-org", map[string]string{"org_id": personal}); code != 200 {
		t.Fatalf("set passkey org: %d %v", code, body)
	}
	status, pres, pk := l.passkeyLogin(t, a)
	if status != 200 || pres["org_id"] != personal {
		t.Fatalf("passkey login: %d %v", status, pres)
	}

	// 会社の管理者には、Membership に結び付けた仕事用のアドレスだけが見える。
	code, ms := l.members(t, boss, acme)
	if code != 200 {
		t.Fatalf("members: %d", code)
	}
	seen := false
	for _, m := range ms.Members {
		if m.UserID == samID {
			seen = true
			if m.Email != "sam@acme.example" {
				t.Fatalf("org admin sees %q", m.Email)
			}
		}
		if m.Email == "sam@home.example" {
			t.Fatal("org admin sees the personal email")
		}
	}
	if !seen {
		t.Fatal("org admin does not see sam")
	}

	// 最後のオーナーは抜けられない。sam は Acme の設定に関わらず抜けられ、セッションは個人 Org に移る。
	if code, body := l.mePost(t, boss, "/v1/me/orgs/"+acme+":leave", nil); code != 409 || body["error"] != "last_owner" {
		t.Fatalf("last owner leaves: %d %v", code, body)
	}
	if code, body := l.putSettings(t, boss, acme, map[string]any{"warnings": map[string]string{"single_factor": "deny"}}); code != 200 {
		t.Fatalf("org settings: %d %v", code, body)
	}
	if code, body := l.mePost(t, work, "/v1/me/orgs/"+acme+":leave", nil); code != 204 {
		t.Fatalf("sam leaves: %d %v", code, body)
	}
	if got := l.activeOrgPublic(t, work); got != personal {
		t.Fatalf("after leave active org = %q", got)
	}

	// アカウントを削除すると、監査ログに残った sam の IP と User-Agent の全文は読めなくなる（切り詰めた値だけが残る）。
	var samEvents []audit.Event
	for _, e := range l.auditTypes(t) {
		if e.Actor.ID == samID && e.Client != "" {
			samEvents = append(samEvents, e)
		}
	}
	if len(samEvents) == 0 {
		t.Fatal("no audit events with client data for sam")
	}
	if ip, ua, err := l.openClient(t, samEvents[0]); err != nil || ip == "" || ua != samUA {
		t.Fatalf("open before deletion: %q %q %v", ip, ua, err)
	}
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	if status, out := l.admin(t, "/v1/admin/users/"+samID+":delete", admin, map[string]bool{"immediate": true}); status != 200 {
		t.Fatalf("delete sam: %d %v", status, out)
	}
	for _, e := range samEvents {
		if _, _, err := l.openClient(t, e); !errors.Is(err, eventlog.ErrClientUnreadable) {
			t.Fatalf("%s after deletion: %v", e.Type, err)
		}
		if e.UserAgent != "Chrome on Windows" {
			t.Fatalf("payload user agent = %q", e.UserAgent)
		}
		if e.IP != "" && e.IP[len(e.IP)-3:] != "/24" && e.IP[len(e.IP)-3:] != "/48" {
			t.Fatalf("payload ip = %q", e.IP)
		}
	}
	for _, c := range []string{work, home, pk} {
		if code, _ := l.me(t, c); code != 401 {
			t.Fatalf("session after deletion: %d", code)
		}
	}
	// 同じアドレスでは新しい別のユーザーとして登録できる。
	if res, _ := l.login(t, "sam@acme.example"); res["user_id"] == samID {
		t.Fatalf("re-signup reused the id: %v", res)
	}
}

func (l *loginEnv) openClient(t *testing.T, e audit.Event) (ip, ua string, err error) {
	t.Helper()
	if txErr := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		ip, ua, err = l.a.clientSealer.Open(ctx, tx, e)
		return nil
	}); txErr != nil {
		t.Fatal(txErr)
	}
	return ip, ua, err
}

// orgOff はフィーチャー org を外した構成にする（他のフィーチャーは既定のまま）。
func orgOff(c *config.Config) {
	var names []string
	for _, f := range feature.Registered() {
		if f.DefaultEnabled && f.Name != feature.Org {
			names = append(names, f.Name)
		}
	}
	c.Features = &names
}

// Org をオフにした構成で、M1・M2 の E2E がそのまま通る（roadmap M3 の完了条件）。
func TestE2EOrgOff(t *testing.T) {
	t.Run("M2", func(t *testing.T) { e2eM2LoseEverythingAndRecover(t, newRecoveryEnv(t, orgOff)) })
	t.Run("M1", func(t *testing.T) {
		e2eOAuthSignupLogoutEmailRelogin(t, newLoginEnvWith(t, orgOff, feature.Registered()))
	})
	t.Run("off", func(t *testing.T) {
		l := newRecoveryEnv(t, orgOff)
		_, cookie := l.login(t, "pat@example.com")
		if code, _ := l.myOrgs(t, cookie); code != 404 || l.activeOrg(t, cookie) != "" {
			t.Fatalf("org should be off: %d", code)
		}
	})
}
