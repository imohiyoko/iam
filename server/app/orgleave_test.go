package app

import (
	"testing"
	"time"
)

// 退会・除名・オーナーの譲渡（design.md 4.10）を HTTP で確かめる。

func TestLeaveOrg(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	l.advance(time.Second)
	_, pat := l.login(t, "pat@acme.example")
	if l.activeOrgPublic(t, pat) != acme {
		t.Fatal("pat should enter acme")
	}
	// 最後のオーナーは抜けられない。個人 Org からは抜けられない。
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":leave", nil); code != 409 || body["error"] != "last_owner" {
		t.Fatalf("last owner leave: %d %v", code, body)
	}
	personal := ""
	_, orgs := l.myOrgs(t, owner)
	for _, o := range orgs.Orgs {
		if o.Kind == "personal" {
			personal = o.ID
		}
	}
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+personal+":leave", nil); code != 409 || body["error"] != "personal_org" {
		t.Fatalf("personal leave: %d %v", code, body)
	}

	// 停止中でも抜けられる。セッションは失効せず個人 Org に移る。
	patM := l.membershipOf(t, owner, acme, l.userID(t, "pat@acme.example"))
	if code, _ := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/members/"+patM+"/suspensions", map[string]string{"reason": "x"}); code != 201 {
		t.Fatalf("suspend: %d", code)
	}
	if code, body := l.mePost(t, pat, "/v1/me/orgs/"+acme+":leave", nil); code != 204 {
		t.Fatalf("leave: %d %v", code, body)
	}
	if code, _ := l.me(t, pat); code != 200 {
		t.Fatalf("session after leave: %d", code)
	}
	if got := l.activeOrgPublic(t, pat); got == acme {
		t.Fatal("session still in acme")
	}
	if _, got := l.myOrgs(t, pat); len(got.Orgs) != 1 {
		t.Fatalf("orgs after leave = %+v", got)
	}
	if code, _ := l.mePost(t, pat, "/v1/me/orgs/"+acme+":leave", nil); code != 404 {
		t.Fatalf("leave twice: %d", code)
	}
	// 再参加は新しい招待で。
	if code, _ := l.invite(t, owner, acme, "pat@acme.example", "member"); code != 201 {
		t.Fatalf("reinvite: %d", code)
	}
	_, token := l.claimToken(t)
	if code, body := l.accept(t, pat, token); code != 200 {
		t.Fatalf("rejoin: %d %v", code, body)
	}
	types := map[string]bool{}
	for _, e := range l.auditTypes(t) {
		types[e.Type] = true
	}
	if !types["membership.ended"] {
		t.Fatalf("audit = %v", types)
	}
}

func TestRemoveAndTransfer(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	mgr := l.join(t, owner, acme, "mgr@acme.example", "admin")
	pat := l.join(t, owner, acme, "pat@acme.example", "member")
	sam := l.join(t, owner, acme, "sam@acme.example", "member")
	ownerM := l.membershipOf(t, owner, acme, l.userID(t, "boss@acme.example"))
	mgrM := l.membershipOf(t, owner, acme, l.userID(t, "mgr@acme.example"))
	patM := l.membershipOf(t, owner, acme, l.userID(t, "pat@acme.example"))
	remove := func(cookie, m string) (int, map[string]any) {
		return l.mePost(t, cookie, "/v1/me/orgs/"+acme+"/members/"+m+":remove", nil)
	}

	if code, body := remove(sam, patM); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("member removes: %d %v", code, body)
	}
	if code, body := remove(mgr, ownerM); code != 403 {
		t.Fatalf("admin removes owner: %d %v", code, body)
	}
	if code, body := remove(mgr, mgrM); code != 403 || body["error"] != "self_target" {
		t.Fatalf("admin removes self: %d %v", code, body)
	}
	if code, body := remove(mgr, patM); code != 204 {
		t.Fatalf("remove: %d %v", code, body)
	}
	if _, got := l.myOrgs(t, pat); len(got.Orgs) != 1 {
		t.Fatalf("removed member orgs = %+v", got)
	}
	if code, _ := remove(mgr, patM); code != 404 {
		t.Fatalf("remove twice: %d", code)
	}

	// 譲渡は owner だけ。譲り先は active なメンバー。
	transfer := func(cookie, m string) (int, map[string]any) {
		return l.mePost(t, cookie, "/v1/me/orgs/"+acme+":transfer", map[string]string{"membership_id": m})
	}
	if code, _ := transfer(mgr, mgrM); code != 403 {
		t.Fatalf("admin transfers: %d", code)
	}
	if code, body := transfer(owner, patM); code != 409 || body["error"] != "not_member" {
		t.Fatalf("transfer to removed: %d %v", code, body)
	}
	if code, body := transfer(owner, mgrM); code != 204 {
		t.Fatalf("transfer: %d %v", code, body)
	}
	// 譲った本人は admin になり、抜けられる。新しいオーナーは最後のオーナーなので抜けられない。
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":leave", nil); code != 204 {
		t.Fatalf("former owner leave: %d %v", code, body)
	}
	if code, body := l.mePost(t, mgr, "/v1/me/orgs/"+acme+":leave", nil); code != 409 || body["error"] != "last_owner" {
		t.Fatalf("new owner leave: %d %v", code, body)
	}
}
