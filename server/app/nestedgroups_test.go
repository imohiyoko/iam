package app

import (
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Group のネスト（design.md 11.5、ADR 0079）を HTTP で確かめる。

func nestedGroupsEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.NestedGroups)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestNestedGroups(t *testing.T) {
	l := nestedGroupsEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "sam@acme.example", "member")
	_, sam := l.login(t, "sam@acme.example")
	samID := l.userID(t, "sam@acme.example")
	base := "/v1/me/orgs/" + acme
	n := 0
	canInvite := func() int {
		n++
		code, _ := l.invite(t, sam, acme, "x"+string(rune('a'+n))+"@example.com", "member")
		return code
	}
	group := func(name string) string {
		t.Helper()
		code, body := l.meDo(t, "POST", owner, base+"/groups", map[string]any{"name": name})
		if code != 201 {
			t.Fatalf("create group %s: %d %v", name, code, body)
		}
		return body["id"].(string)
	}
	add := func(parent, typ, child string) (int, map[string]any) {
		return l.meDo(t, "POST", owner, base+"/groups/"+parent+"/members", map[string]any{"principal_type": typ, "principal_id": child})
	}
	mustAdd := func(parent, typ, child string) {
		t.Helper()
		if code, body := add(parent, typ, child); code != 204 {
			t.Fatalf("add %s %s to %s: %d %v", typ, child, parent, code, body)
		}
	}
	code, body := l.meDo(t, "POST", owner, base+"/roles", map[string]any{"name": "inviter", "permissions": []string{role.PermOrgInvite}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, body)
	}
	roleID := body["id"].(string)

	// all ⊃ eng ⊃ backend ∋ sam。all の付与が sam に効く。
	all, eng, backend := group("all"), group("eng"), group("backend")
	if code, body := l.meDo(t, "POST", owner, base+"/role-bindings", map[string]any{"role": roleID, "principal_type": "group", "principal_id": all}); code != 201 {
		t.Fatalf("bind group: %d %v", code, body)
	}
	mustAdd(backend, "user", samID)
	if c := canInvite(); c != 403 {
		t.Fatalf("invite before nesting: %d", c)
	}
	mustAdd(eng, "group", backend)
	mustAdd(all, "group", eng)
	if c := canInvite(); c != 201 {
		t.Fatalf("invite via nested group: %d", c)
	}
	// 本人の Group の一覧には、所属する Group を含む Group も載る（ADR 0085）。
	code, body = l.meDo(t, "GET", sam, base+"/my-groups", nil)
	if code != 200 {
		t.Fatalf("my groups: %d %v", code, body)
	}
	var mine []string
	for _, g := range body["groups"].([]any) {
		m := g.(map[string]any)
		mine = append(mine, m["id"].(string)+"/"+map[bool]string{true: "direct", false: "nested"}[m["direct"].(bool)])
	}
	if want := []string{all + "/nested", backend + "/direct", eng + "/nested"}; !slices.Equal(mine, want) {
		t.Fatalf("my groups: %v, want %v", mine, want)
	}
	code, body = l.meDo(t, "GET", owner, base+"/groups/"+eng+"/members", nil)
	if ms := body["members"].([]any); code != 200 || len(ms) != 1 || ms[0].(map[string]any)["principal_type"] != "group" || ms[0].(map[string]any)["principal_id"] != backend {
		t.Fatalf("list members: %d %v", code, body)
	}

	// 循環は作れない。
	for _, c := range [][2]string{{backend, all}, {eng, eng}} {
		if code, body := add(c[0], "group", c[1]); code != 409 || body["error"] != "group_cycle" {
			t.Fatalf("cycle %v: %d %v", c, code, body)
		}
	}
	// 入れ子は 5 段まで（top ⊃ g5 ⊃ g4 ⊃ all ⊃ eng ⊃ backend は 6 段）。
	g4, g5, top := group("g4"), group("g5"), group("top")
	mustAdd(g4, "group", all)
	mustAdd(g5, "group", g4)
	if code, body := add(top, "group", g5); code != 409 || body["error"] != "group_too_deep" {
		t.Fatalf("too deep: %d %v", code, body)
	}
	// realm の Group は Org の Group に入れられない。
	_, op := l.operator(t, "ops@example.com", role.RealmAdmin)
	code, body = l.adminDo(t, "POST", op, "/v1/admin/groups", map[string]any{"name": "staff"})
	if code != 201 {
		t.Fatalf("create realm group: %d %v", code, body)
	}
	if code, body := add(all, "group", body["id"].(string)); code != 400 || body["error"] != "invalid_principal" {
		t.Fatalf("realm group into org group: %d %v", code, body)
	}

	// 途中の所属を外すと効かなくなり、戻せば効く。途中の Group を消すと効かなくなる。
	if code, body := l.meDo(t, "POST", owner, base+"/groups/"+eng+"/members:remove", map[string]any{"principal_type": "group", "principal_id": backend}); code != 204 {
		t.Fatalf("remove nested group: %d %v", code, body)
	}
	if c := canInvite(); c != 403 {
		t.Fatalf("invite after removing nesting: %d", c)
	}
	mustAdd(eng, "group", backend)
	if c := canInvite(); c != 201 {
		t.Fatalf("invite after nesting again: %d", c)
	}
	if code, body := l.meDo(t, "POST", owner, base+"/groups/"+eng+":delete", nil); code != 204 {
		t.Fatalf("delete middle group: %d %v", code, body)
	}
	if c := canInvite(); c != 403 {
		t.Fatalf("invite after deleting the middle group: %d", c)
	}
	// eng が消えたので、top ⊃ g5 ⊃ g4 ⊃ all ⊃ backend… は作れる（5 段）。
	mustAdd(all, "group", backend)
	mustAdd(top, "group", g5)
	if c := canInvite(); c != 201 {
		t.Fatalf("invite after nesting directly: %d", c)
	}
}

func TestNestedGroupsOff(t *testing.T) {
	l := nestedGroupsEnv(t, false)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	base := "/v1/me/orgs/" + acme
	var ids []string
	for _, name := range []string{"all", "eng"} {
		code, body := l.meDo(t, "POST", owner, base+"/groups", map[string]any{"name": name})
		if code != 201 {
			t.Fatalf("create group: %d %v", code, body)
		}
		ids = append(ids, body["id"].(string))
	}
	if code, body := l.meDo(t, "POST", owner, base+"/groups/"+ids[0]+"/members", map[string]any{"principal_type": "group", "principal_id": ids[1]}); code != 400 || body["error"] != "invalid_principal" {
		t.Fatalf("nest while off: %d %v", code, body)
	}
}
