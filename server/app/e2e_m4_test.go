package app

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// M4 の完了条件（roadmap M4）を通しで確かめる。check のレイテンシはベンチマーク（bench/baseline.txt）で見る。

// adminCheck は管理 API の check で判定する。
func (l *loginEnv) adminCheck(t *testing.T, bearer, userID, action, orgID string) bool {
	t.Helper()
	body := map[string]any{"principal_id": userID, "action": action}
	if orgID != "" {
		body["org_id"] = orgID
	}
	code, out := l.admin(t, "/v1/admin/authz:check", bearer, body)
	if code != 200 {
		t.Fatalf("check %s %s: %d %v", userID, action, code, out)
	}
	return out["allowed"] == true
}

// TestE2EM4OrgScope は Org オンの構成で、Org の範囲の判定と、その反映の遅れの上限と、権限の無い操作の拒否を確かめる。
func TestE2EM4OrgScope(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	beta := l.sharedOrg(t, owner, "Beta")
	l.join(t, owner, acme, "sam@acme.example", "member")
	l.join(t, owner, beta, "sam@acme.example", "member")
	_, sam := l.login(t, "sam@acme.example")
	samID := l.userID(t, "sam@acme.example")
	delay := l.e.cfg.Security.Session.ValidityMaxDelay.D()

	// 1. 独自のロールを Group 経由で Acme にだけ付与する。判定は Org ごと、realm の範囲には効かない。
	_, body := l.meDo(t, "POST", owner, "/v1/me/orgs/"+acme+"/roles", map[string]any{"name": "editor", "permissions": []string{"doc:read", "doc:write"}})
	editor := body["id"].(string)
	_, body = l.meDo(t, "POST", owner, "/v1/me/orgs/"+acme+"/groups", map[string]any{"name": "Writers"})
	writers := body["id"].(string)
	if code, body := l.meDo(t, "POST", owner, "/v1/me/orgs/"+acme+"/role-bindings", map[string]any{"role": editor, "principal_type": "group", "principal_id": writers}); code != 201 {
		t.Fatalf("bind group: %d %v", code, body)
	}
	if l.adminCheck(t, checker, samID, "doc:write", acme) {
		t.Fatal("allowed before joining the group")
	}
	// 管理の変更は、このインスタンスではすぐに反映する。
	if code, _ := l.meDo(t, "POST", owner, "/v1/me/orgs/"+acme+"/groups/"+writers+"/members", map[string]any{"principal_type": "user", "principal_id": samID}); code != 204 {
		t.Fatalf("add member: %d", code)
	}
	for _, c := range []struct {
		action, org string
		want        bool
	}{
		{"doc:write", acme, true},
		{"doc:delete", acme, false},
		{"doc:write", beta, false},
		{"doc:write", "", false},
		{role.PermOrgRead, beta, true},
		{role.PermOrgInvite, acme, false},
	} {
		if got := l.adminCheck(t, checker, samID, c.action, c.org); got != c.want {
			t.Errorf("check(%s, %q) = %v, want %v", c.action, c.org, got, c.want)
		}
	}
	// 本人の check は active な Org（ログインで選ばれた Org）か、指定した Org で判定する。
	if code, out := l.meDo(t, "POST", sam, "/v1/me:check", map[string]any{"action": "doc:write", "org_id": acme}); code != 200 || out["allowed"] != true {
		t.Fatalf("self check: %d %v", code, out)
	}

	// 2. 所属の変更（Org の外での変更を含む）は、遅くとも validity_max_delay の後に反映する。
	uid, oid := l.internalIDs(t, samID, acme)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		m, err := tx.Memberships().GetByUserOrg(ctx, l.a.realm.ID, uid, oid)
		if err != nil {
			return err
		}
		m.ValidUntil = new(l.a.deps.Clock.Now())
		return tx.Memberships().Update(ctx, m)
	})
	if err != nil {
		t.Fatal(err)
	}
	l.advance(delay + time.Second)
	if l.adminCheck(t, checker, samID, "doc:write", acme) || l.adminCheck(t, checker, samID, role.PermOrgRead, acme) {
		t.Fatal("membership outside validity still allowed after the delay")
	}
	// 本人の check は、realm の範囲の付与があっても、使える所属の無い Org では allowed: false。
	err = l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return role.Grant(ctx, tx, l.a.realm.ID, role.RealmSupport, port.PrincipalUser, uid, l.a.deps.Clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	l.advance(delay + time.Second)
	for org, want := range map[string]bool{acme: false, beta: true} {
		if code, out := l.meDo(t, "POST", sam, "/v1/me:check", map[string]any{"action": role.PermSuspensionsRead, "org_id": org}); code != 200 || out["allowed"] != want {
			t.Errorf("self check in %s: %d %v, want %v", org, code, out, want)
		}
	}
	// 対象が Org なら、その Org が判定先（所属を確かめる）。org_id と食い違えば invalid_request。
	if code, out := l.meDo(t, "POST", sam, "/v1/me:check", map[string]any{"action": role.PermSuspensionsRead, "resource_type": "org", "resource_id": acme}); code != 200 || out["allowed"] != false {
		t.Errorf("self check on org resource: %d %v", code, out)
	}
	if code, out := l.meDo(t, "POST", sam, "/v1/me:check", map[string]any{"action": role.PermSuspensionsRead, "org_id": beta, "resource_type": "org", "resource_id": acme}); code != 400 {
		t.Errorf("self check with mismatched org: %d %v", code, out)
	}

	// 3. 権限の無い管理操作は permission_denied。
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	if code, out := l.admin(t, "/v1/admin/authz:check", support, map[string]any{"principal_id": samID, "action": "doc:read"}); code != 403 || out["error"] != "permission_denied" {
		t.Fatalf("support check: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/users", support, map[string]any{"email": "x@example.com"}); code != 403 || out["error"] != "permission_denied" {
		t.Fatalf("support creates user: %d %v", code, out)
	}
	if code, out := l.meDo(t, "POST", sam, "/v1/me/orgs/"+beta+"/roles", map[string]any{"name": "x", "permissions": []string{}}); code != 403 || out["error"] != "permission_denied" {
		t.Fatalf("member creates role: %d %v", code, out)
	}
}

// TestE2EM4RealmScope は Org オフの構成で、realm の範囲の判定と、その反映の遅れの上限を確かめる。
func TestE2EM4RealmScope(t *testing.T) {
	l := newLoginEnvWith(t, orgOff, feature.Registered())
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, _ = l.login(t, "pat@example.com")
	patID := l.userID(t, "pat@example.com")
	delay := l.e.cfg.Security.Session.ValidityMaxDelay.D()

	code, body := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "reviewer", "permissions": []string{"doc:read", "orgs:read"}})
	if code != 201 {
		t.Fatalf("create realm role: %d %v", code, body)
	}
	reviewer := body["id"].(string)
	if code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": reviewer, "principal_type": "user", "principal_id": patID}); code != 201 {
		t.Fatalf("bind: %d %v", code, body)
	}
	if !l.adminCheck(t, checker, patID, "doc:read", "") || l.adminCheck(t, checker, patID, "doc:write", "") {
		t.Fatal("realm role not applied")
	}
	// Org がオフなら org_id は無視して realm の範囲で判定する。
	if !l.adminCheck(t, checker, patID, "doc:read", "org_unknown") {
		t.Fatal("org id should be ignored with org off")
	}
	// リソースを限った付与。
	if code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": reviewer, "principal_type": "user", "principal_id": l.userID(t, "app@example.com"),
		"resource_type": "doc", "resource_id": "d1"}); code != 201 {
		t.Fatalf("bind resource: %d %v", code, body)
	}
	appID := l.userID(t, "app@example.com")
	for _, c := range []struct {
		rtype, rid string
		want       bool
	}{{"doc", "d1", true}, {"doc", "d2", false}, {"", "", false}} {
		body := map[string]any{"principal_id": appID, "action": "doc:read"}
		if c.rtype != "" {
			body["resource_type"], body["resource_id"] = c.rtype, c.rid
		}
		if code, out := l.admin(t, "/v1/admin/authz:check", checker, body); code != 200 || out["allowed"] != c.want {
			t.Errorf("resource check %v = %d %v", c, code, out)
		}
	}
	// 付与した独自のロールが管理 API にも効く（sessions:revoke を持たない realm:support に足す）。
	opsID, ops := l.operator(t, "help@example.com", role.RealmSupport)
	revoke := func() int {
		code, _ := l.admin(t, "/v1/admin/sessions/ses_none:revoke", ops, nil)
		return code
	}
	if code := revoke(); code != 403 {
		t.Fatalf("support revokes session: %d", code)
	}
	code, body = l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "revoker", "permissions": []string{role.PermSessionsRevoke}})
	if code != 201 {
		t.Fatalf("create revoker: %d %v", code, body)
	}
	if code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": body["id"], "principal_type": "user", "principal_id": opsID}); code != 201 {
		t.Fatalf("bind revoker: %d %v", code, body)
	}
	if code := revoke(); code == 403 {
		t.Fatalf("revoker still denied: %d", code)
	}
	// 別のインスタンスでの変更（ここでは Storage への直接の付与）は、遅くとも validity_max_delay の後に反映する。
	if l.adminCheck(t, checker, patID, role.PermUsersRecover, "") {
		t.Fatal("allowed before grant")
	}
	uid := l.internalUserID(t, patID)
	if err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return role.Grant(ctx, tx, l.a.realm.ID, role.RealmSupport, port.PrincipalUser, uid, l.a.deps.Clock.Now())
	}); err != nil {
		t.Fatal(err)
	}
	// キャッシュの期限までは古い判定のことがある（上限は validity_max_delay）。
	if l.adminCheck(t, checker, patID, role.PermUsersRecover, "") {
		t.Fatal("cached decision unexpectedly refreshed before the delay")
	}
	l.advance(delay + time.Second)
	if !l.adminCheck(t, checker, patID, role.PermUsersRecover, "") {
		t.Fatal("grant not applied after the delay")
	}
}
