package app

import (
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// 仕事用のメールでログインすると、そのメールを結び付けた会社の Org に入る（roadmap M3 の完了条件）。
func TestLoginWithWorkEmailEntersCompanyOrg(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	res, pat := l.login(t, "pat@home.example")
	if res["org_id"] == nil || res["org_id"] == acme {
		t.Fatalf("first login org = %v", res["org_id"])
	}
	l.invite(t, owner, acme, "pat@acme.example", "member")
	_, token := l.claimToken(t)
	if code, body := l.accept(t, pat, token); code != 200 {
		t.Fatalf("accept = %d %v", code, body)
	}

	// 前回の Org は最後に発行したセッションで決まるため、時刻を進めてからログインする。
	l.advance(time.Second)
	res, work := l.login(t, "pat@acme.example")
	if res["org_id"] != acme || res["user_id"] != l.userID(t, "pat@home.example") {
		t.Fatalf("work email login = %v", res)
	}
	if _, got := l.myOrgs(t, work); !activeIs(got, acme) {
		t.Fatalf("orgs after work login = %+v", got)
	}
	// 個人のメールでは手がかりが無いので、前回の Org（Acme）に入る。個人 Org に切り替えられる。
	l.advance(time.Second)
	res, home := l.login(t, "pat@home.example")
	if res["org_id"] != acme {
		t.Fatalf("home email login = %v", res["org_id"])
	}
	_, orgs := l.myOrgs(t, home)
	var personal string
	for _, o := range orgs.Orgs {
		if o.Kind == "personal" {
			personal = o.ID
		}
	}
	code, body, newCookie := l.post(t, home, "/v1/me/orgs/"+personal+":switch", nil)
	if code != 200 || body["org_id"] != personal || newCookie == "" || newCookie == home {
		t.Fatalf("switch = %d %v", code, body)
	}
	// 古い ID はすぐに失効する。
	if code, _ := l.me(t, home); code != 401 {
		t.Fatalf("old session after switch = %d", code)
	}
	if _, got := l.myOrgs(t, newCookie); !activeIs(got, personal) {
		t.Fatalf("orgs after switch = %+v", got)
	}
	// 所属していない Org には切り替えられない。
	_, outsider := l.login(t, "out@example.com")
	if code, _, _ := l.post(t, outsider, "/v1/me/orgs/"+acme+":switch", nil); code != 403 {
		t.Fatalf("outsider switch = %d", code)
	}
}

func activeIs(got myOrgs, orgID string) bool {
	for _, o := range got.Orgs {
		if o.Active {
			return o.ID == orgID
		}
	}
	return false
}

// passkey の既定の Org が効く（roadmap M3 の完了条件）。
func TestPasskeyPreferredOrg(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin}
	}, feature.Registered())
	_, cookie := l.login(t, "pat@example.com")
	acme := l.sharedOrg(t, cookie, "Acme")
	a := passkeytest.New(passkeyOrigin)
	status, res := l.registerPasskey(t, cookie, a, "Laptop")
	if status != 200 {
		t.Fatalf("register: %d %v", status, res)
	}
	pk := res["id"].(string)
	if code, body := l.mePost(t, cookie, "/v1/me/passkeys/"+pk+":set-org", map[string]string{"org_id": acme}); code != 200 || body["org_id"] != acme {
		t.Fatalf("set org = %d %v", code, body)
	}
	if code, _ := l.mePost(t, cookie, "/v1/me/passkeys/"+pk+":set-org", map[string]string{"org_id": "org_nope"}); code != 404 {
		t.Fatalf("set unknown org = %d", code)
	}
	status, login, _ := l.passkeyLogin(t, a)
	if status != 200 || login["org_id"] != acme {
		t.Fatalf("passkey login = %d %v", status, login)
	}
}
