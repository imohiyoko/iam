package app

import (
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

// 本人の Group の一覧と、Group に限った所属の参照（ADR 0085）を HTTP で確かめる。

func TestMyGroupsAndGroupScopedRead(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "tom@acme.example", "member")
	l.join(t, owner, acme, "sam@acme.example", "member")
	l.join(t, owner, acme, "eve@acme.example", "member")
	_, tom := l.login(t, "tom@acme.example")
	_, sam := l.login(t, "sam@acme.example")
	_, eve := l.login(t, "eve@acme.example")
	tomID, samID, eveID := l.userID(t, "tom@acme.example"), l.userID(t, "sam@acme.example"), l.userID(t, "eve@acme.example")
	base := "/v1/me/orgs/" + acme
	group := func(name string) string {
		t.Helper()
		code, body := l.meDo(t, "POST", owner, base+"/groups", map[string]any{"name": name})
		if code != 201 {
			t.Fatalf("create group %s: %d %v", name, code, body)
		}
		return body["id"].(string)
	}
	classA, classB := group("Class A"), group("Class B")
	if code, body := l.meDo(t, "POST", owner, base+"/groups/"+classA+"/members", map[string]any{"principal_type": "user", "principal_id": samID}); code != 204 {
		t.Fatalf("add member: %d %v", code, body)
	}

	// 本人は権限なしで自分の Group を読める。所属していない Org は無いものとして扱う。
	code, body := l.meDo(t, "GET", sam, base+"/my-groups", nil)
	if gs := body["groups"].([]any); code != 200 || len(gs) != 1 || gs[0].(map[string]any)["id"] != classA || gs[0].(map[string]any)["direct"] != true {
		t.Fatalf("my groups: %d %v", code, body)
	}
	if code, body := l.meDo(t, "GET", eve, base+"/my-groups", nil); code != 200 || len(body["groups"].([]any)) != 0 {
		t.Fatalf("my groups (none): %d %v", code, body)
	}
	_, zed := l.login(t, "zed@example.com")
	if code, _ := l.meDo(t, "GET", zed, base+"/my-groups", nil); code != 404 {
		t.Fatalf("my groups of outsider: %d", code)
	}

	// 権限が無ければ所属は読めない。
	if code, _ := l.meDo(t, "GET", tom, base+"/groups/"+classA+"/members", nil); code != 403 {
		t.Fatalf("members without permission: %d", code)
	}
	// org:groups.read を Class A に限って付与すると、Class A の所属だけを読める。書けず、一覧も読めない。
	code, body = l.meDo(t, "POST", owner, base+"/roles", map[string]any{"name": "instructor", "permissions": []string{role.PermOrgGroupsRead, "learning:view"}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, body)
	}
	roleID := body["id"].(string)
	code, body = l.meDo(t, "POST", owner, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "user", "principal_id": tomID,
		"resource_type": "group", "resource_id": classA})
	if code != 201 {
		t.Fatalf("bind on group: %d %v", code, body)
	}
	code, body = l.meDo(t, "GET", tom, base+"/groups/"+classA+"/members", nil)
	if ms := body["members"].([]any); code != 200 || len(ms) != 1 || ms[0].(map[string]any)["principal_id"] != samID {
		t.Fatalf("scoped members: %d %v", code, body)
	}
	if code, _ := l.meDo(t, "GET", tom, base+"/groups/"+classB+"/members", nil); code != 403 {
		t.Fatalf("members of another group: %d", code)
	}
	if code, _ := l.meDo(t, "GET", tom, base+"/groups", nil); code != 403 {
		t.Fatalf("list groups with scoped grant: %d", code)
	}
	if code, _ := l.meDo(t, "POST", tom, base+"/groups/"+classA+"/members", map[string]any{"principal_type": "user", "principal_id": eveID}); code != 403 {
		t.Fatalf("add member with read grant: %d", code)
	}
	// 連携先の権限も、その Group を対象にした判定でだけ効く。
	check := func(cookie, gid string) any {
		t.Helper()
		code, body := l.meDo(t, "POST", cookie, "/v1/me:check", map[string]any{"action": "learning:view", "org_id": acme, "resource_type": "group", "resource_id": gid})
		if code != 200 {
			t.Fatalf("check: %d %v", code, body)
		}
		return body["allowed"]
	}
	if check(tom, classA) != true || check(tom, classB) != false {
		t.Fatalf("check on groups: %v %v", check(tom, classA), check(tom, classB))
	}

	// Org 全体に付与すれば、Group の一覧とどの Group の所属も読める。
	if code, body := l.meDo(t, "POST", owner, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "user", "principal_id": eveID}); code != 201 {
		t.Fatalf("bind org-wide: %d %v", code, body)
	}
	if code, body := l.meDo(t, "GET", eve, base+"/groups", nil); code != 200 || len(body["groups"].([]any)) != 2 {
		t.Fatalf("list groups org-wide: %d %v", code, body)
	}
	if code, _ := l.meDo(t, "GET", eve, base+"/groups/"+classB+"/members", nil); code != 200 {
		t.Fatalf("members org-wide: %d", code)
	}
	// 別の Org の Group は無いものとして扱う。
	other := l.sharedOrg(t, owner, "Other")
	code, body = l.meDo(t, "POST", owner, "/v1/me/orgs/"+other+"/groups", map[string]any{"name": "Class C"})
	if code != 201 {
		t.Fatalf("create other group: %d %v", code, body)
	}
	if code, _ := l.meDo(t, "GET", eve, base+"/groups/"+body["id"].(string)+"/members", nil); code != 404 {
		t.Fatalf("members of another org's group: %d", code)
	}
}
