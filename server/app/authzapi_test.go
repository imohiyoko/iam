package app

import (
	"encoding/json"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

// ロール・付与・Group の管理の API（ADR 0064）を HTTP で確かめる。

func (l *loginEnv) meDo(t *testing.T, method, cookie, path string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), method, path, body, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (l *loginEnv) adminDo(t *testing.T, method, bearer, path string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.AdminHandler(), method, path, body, "Authorization", "Bearer "+bearer)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestOrgRolesAndGroupsAPI(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "ann@acme.example", "admin")
	l.join(t, owner, acme, "sam@acme.example", "member")
	_, ann := l.login(t, "ann@acme.example")
	_, sam := l.login(t, "sam@acme.example")
	samID := l.userID(t, "sam@acme.example")
	base := "/v1/me/orgs/" + acme
	canInvite := func(email string) int {
		code, _ := l.invite(t, sam, acme, email, "member")
		return code
	}

	// 一覧は管理の権限が要る。組み込みの Org のロールは見えるが付与できない。
	if code, _ := l.meDo(t, "GET", sam, base+"/roles", nil); code != 403 {
		t.Fatalf("member lists roles: %d", code)
	}
	code, body := l.meDo(t, "GET", ann, base+"/roles", nil)
	if code != 200 || len(body["roles"].([]any)) != 3 {
		t.Fatalf("list roles: %d %v", code, body)
	}
	// org:admin は持たない権限（org:delete）を渡せない。realm の管理の権限は Org のロールに入れられない。
	if code, body := l.meDo(t, "POST", ann, base+"/roles", map[string]any{"name": "deleter", "permissions": []string{role.PermOrgDelete}}); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("escalate: %d %v", code, body)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/roles", map[string]any{"name": "ops", "permissions": []string{"users:update"}}); code != 400 || body["error"] != "invalid_permission" {
		t.Fatalf("realm perm: %d %v", code, body)
	}
	code, body = l.meDo(t, "POST", ann, base+"/roles", map[string]any{"name": "inviter", "permissions": []string{role.PermOrgInvite}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, body)
	}
	roleID := body["id"].(string)
	if code, body := l.meDo(t, "POST", ann, base+"/roles", map[string]any{"name": "inviter", "permissions": []string{}}); code != 409 || body["error"] != "role_exists" {
		t.Fatalf("duplicate role: %d %v", code, body)
	}

	// 付与で sam が招待できるようになり、取り消せば戻る。
	if c := canInvite("x1@example.com"); c != 403 {
		t.Fatalf("invite before bind: %d", c)
	}
	code, body = l.meDo(t, "POST", ann, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "user", "principal_id": samID})
	if code != 201 || body["role"] != roleID || body["principal_id"] != samID {
		t.Fatalf("bind: %d %v", code, body)
	}
	bindingID := body["id"].(string)
	if c := canInvite("x2@example.com"); c != 201 {
		t.Fatalf("invite after bind: %d", c)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/role-bindings", map[string]any{"role": role.RealmAdmin, "principal_type": "user", "principal_id": samID}); code != 400 || body["error"] != "unknown_role" {
		t.Fatalf("bind operator role: %d %v", code, body)
	}
	_, _ = l.login(t, "zed@example.com")
	if code, body := l.meDo(t, "POST", ann, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "user", "principal_id": l.userID(t, "zed@example.com")}); code != 409 || body["error"] != "not_member" {
		t.Fatalf("bind outsider: %d %v", code, body)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/role-bindings/"+bindingID+":delete", nil); code != 204 {
		t.Fatalf("unbind: %d %v", code, body)
	}
	if c := canInvite("x3@example.com"); c != 403 {
		t.Fatalf("invite after unbind: %d", c)
	}

	// Group に付与し、所属で効かせる。
	code, body = l.meDo(t, "POST", ann, base+"/groups", map[string]any{"name": "Recruiters"})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, body)
	}
	groupID := body["id"].(string)
	if code, body := l.meDo(t, "POST", ann, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "group", "principal_id": groupID}); code != 201 {
		t.Fatalf("bind group: %d %v", code, body)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/groups/"+groupID+"/members", map[string]any{"principal_type": "user", "principal_id": samID}); code != 204 {
		t.Fatalf("add member: %d %v", code, body)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/groups/"+groupID+"/members", map[string]any{"principal_type": "user", "principal_id": samID}); code != 409 || body["error"] != "member_exists" {
		t.Fatalf("add member twice: %d %v", code, body)
	}
	if c := canInvite("x4@example.com"); c != 201 {
		t.Fatalf("invite via group: %d", c)
	}
	code, body = l.meDo(t, "GET", ann, base+"/groups/"+groupID+"/members", nil)
	if ms := body["members"].([]any); code != 200 || len(ms) != 1 || ms[0].(map[string]any)["principal_id"] != samID {
		t.Fatalf("list members: %d %v", code, body)
	}
	if code, body := l.meDo(t, "PATCH", ann, base+"/groups/"+groupID, map[string]any{"name": "Hiring"}); code != 200 || body["name"] != "Hiring" {
		t.Fatalf("rename: %d %v", code, body)
	}
	if code, body := l.meDo(t, "PUT", ann, base+"/roles/"+roleID, map[string]any{"name": "reader", "permissions": []string{role.PermOrgRead}}); code != 200 || body["name"] != "reader" {
		t.Fatalf("update role: %d %v", code, body)
	}
	if c := canInvite("x5@example.com"); c != 403 {
		t.Fatalf("invite after role update: %d", c)
	}
	code, body = l.meDo(t, "GET", ann, base+"/role-bindings", nil)
	if code != 200 || len(body["bindings"].([]any)) != 1 {
		t.Fatalf("list bindings: %d %v", code, body)
	}
	// 除名すると Org の範囲の付与と Group の所属も外れる。
	if code, body := l.meDo(t, "POST", ann, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "user", "principal_id": samID}); code != 201 {
		t.Fatalf("bind sam again: %d %v", code, body)
	}
	if code, body := l.meDo(t, "POST", ann, base+"/members/"+l.membershipOf(t, ann, acme, samID)+":remove", nil); code != 204 {
		t.Fatalf("remove sam: %d %v", code, body)
	}
	code, body = l.meDo(t, "GET", ann, base+"/role-bindings", nil)
	if code != 200 || len(body["bindings"].([]any)) != 1 {
		t.Fatalf("bindings after removal: %d %v", code, body)
	}
	code, body = l.meDo(t, "GET", ann, base+"/groups/"+groupID+"/members", nil)
	if code != 200 || len(body["members"].([]any)) != 0 {
		t.Fatalf("group members after removal: %d %v", code, body)
	}
	if code, _ := l.meDo(t, "POST", ann, base+"/groups/"+groupID+":delete", nil); code != 204 {
		t.Fatalf("delete group: %d", code)
	}
	if code, _ := l.meDo(t, "POST", ann, base+"/roles/"+roleID+":delete", nil); code != 204 {
		t.Fatalf("delete role: %d", code)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	for _, typ := range []string{"role.created", "role.updated", "role.deleted", "role.granted", "role.revoked", "group.created", "group.renamed",
		"group.member_added", "group.deleted"} {
		if types[typ] == 0 {
			t.Errorf("audit missing %s: %v", typ, types)
		}
	}
}

func TestRealmRoleBindingsAPI(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	_, _ = l.login(t, "pat@example.com")
	patID := l.userID(t, "pat@example.com")
	ownerID, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)

	// realm:admin は運営者ロールを付与できない（roles:manage は realm:owner だけ）。
	if code, _ := l.admin(t, "/v1/admin/role-bindings", admin, map[string]any{"role": role.RealmSupport, "principal_type": "user", "principal_id": patID}); code != 403 {
		t.Fatalf("admin grants: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", admin, "/v1/admin/roles", nil); code != 403 {
		t.Fatalf("admin lists roles: %d", code)
	}
	code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmSupport, "principal_type": "user", "principal_id": patID})
	if code != 201 || body["role"] != role.RealmSupport {
		t.Fatalf("grant support: %d %v", code, body)
	}
	if code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmSupport, "principal_type": "user", "principal_id": patID}); code != 409 || body["error"] != "binding_exists" {
		t.Fatalf("grant twice: %d %v", code, body)
	}
	if code, body := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.NotificationDelivery, "principal_type": "user", "principal_id": patID}); code != 400 || body["error"] != "unknown_role" {
		t.Fatalf("grant system role: %d %v", code, body)
	}
	code, body = l.adminDo(t, "GET", owner, "/v1/admin/role-bindings", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, body)
	}
	var ownerBinding string
	for _, x := range body["bindings"].([]any) {
		b := x.(map[string]any)
		if b["role"] == role.RealmOwner {
			ownerBinding = b["id"].(string)
			// 応答の主体は公開 ID（ADR 0045）。
			if b["principal_id"] != ownerID {
				t.Fatalf("owner binding principal = %v, want %s", b["principal_id"], ownerID)
			}
		}
	}
	// 最後の realm:owner は外せない。
	if code, body := l.admin(t, "/v1/admin/role-bindings/"+ownerBinding+":delete", owner, nil); code != 409 || body["error"] != "last_owner" {
		t.Fatalf("revoke last owner: %d %v", code, body)
	}
	code, body = l.adminDo(t, "GET", owner, "/v1/admin/roles", nil)
	if code != 200 {
		t.Fatalf("roles: %d %v", code, body)
	}
	for _, x := range body["roles"].([]any) {
		if r := x.(map[string]any); r["id"] == role.NotificationDelivery || r["id"] == role.OrgOwner {
			t.Fatalf("listed non-assignable builtin: %v", r)
		}
	}
	// realm の Group：realm:admin が作れる（groups:manage）。
	if code, body := l.admin(t, "/v1/admin/groups", admin, map[string]any{"name": "Support"}); code != 201 {
		t.Fatalf("create realm group: %d %v", code, body)
	}
}
