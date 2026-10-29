package app

import (
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

func newHierarchyEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.OrgHierarchy)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestOrgHierarchyOff(t *testing.T) {
	l := newHierarchyEnv(t, false)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.adminDo(t, "POST", admin, "/v1/admin/orgs/"+acme+":set-parent", map[string]any{}); code != 404 || out["error"] != "hierarchy_disabled" {
		t.Fatalf("set parent with the feature off: %d %v", code, out)
	}
}

func TestOrgHierarchy(t *testing.T) {
	l := newHierarchyEnv(t, true)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	_, lead := l.login(t, "lead@acme.example")
	sales := l.sharedOrg(t, lead, "Sales")
	// boss は Sales では一般のメンバー。
	if code, out := l.invite(t, lead, sales, "boss@acme.example", "member"); code != 201 {
		t.Fatalf("invite boss: %d %v", code, out)
	}
	_, token := l.claimToken(t)
	if code, out := l.accept(t, boss, token); code != 200 {
		t.Fatalf("accept: %d %v", code, out)
	}
	if code, _ := l.invite(t, boss, sales, "new@acme.example", "member"); code != 403 {
		t.Fatalf("member invites without hierarchy: %d", code)
	}

	setParent := func(child string, parent any) (int, map[string]any) {
		return l.adminDo(t, "POST", admin, "/v1/admin/orgs/"+child+":set-parent", map[string]any{"parent_id": parent})
	}
	code, out := setParent(sales, acme)
	if code != 200 || out["parent_id"] != acme {
		t.Fatalf("set parent: %d %v", code, out)
	}
	// 親の Org の owner は、子の Org で owner の権限を持つ（子での役割はメンバーのまま）。
	if code, out := l.invite(t, boss, sales, "new@acme.example", "member"); code != 201 {
		t.Fatalf("parent owner invites in child: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", admin, "/v1/admin/orgs/"+acme, nil); code != 200 || out["parent_id"] != nil {
		t.Fatalf("get parent org: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", admin, "/v1/admin/orgs/"+acme+"/children", nil); code != 200 || len(out["orgs"].([]any)) != 1 {
		t.Fatalf("children: %d %v", code, out)
	}

	// 循環・自分自身・存在しない親・個人 Org は拒む。
	if code, out := setParent(acme, sales); code != 409 || out["error"] != "hierarchy_cycle" {
		t.Fatalf("cycle: %d %v", code, out)
	}
	if code, out := setParent(acme, acme); code != 409 || out["error"] != "hierarchy_cycle" {
		t.Fatalf("self: %d %v", code, out)
	}
	if code, out := setParent(sales, "org_missing"); code != 400 || out["error"] != "parent_not_found" {
		t.Fatalf("missing parent: %d %v", code, out)
	}
	personal := ""
	code, out = l.meDo(t, "GET", boss, "/v1/me/orgs", nil)
	if code != 200 {
		t.Fatalf("list my orgs: %d %v", code, out)
	}
	for _, o := range out["orgs"].([]any) {
		if m := o.(map[string]any); m["kind"] == "personal" {
			personal = m["id"].(string)
		}
	}
	if personal == "" {
		t.Fatalf("personal org not found: %v", out)
	}
	if code, out := setParent(personal, acme); code != 409 || out["error"] != "personal_org" {
		t.Fatalf("personal org: %d %v", code, out)
	}
	// 段数の上限（根を含めて 5）。
	chain := []string{sales}
	for i := range 3 {
		o := l.sharedOrg(t, lead, "Team"+string(rune('A'+i)))
		if code, out := setParent(o, chain[len(chain)-1]); code != 200 {
			t.Fatalf("chain %d: %d %v", i, code, out)
		}
		chain = append(chain, o)
	}
	extra := l.sharedOrg(t, lead, "TooDeep")
	if code, out := setParent(extra, chain[len(chain)-1]); code != 409 || out["error"] != "hierarchy_too_deep" {
		t.Fatalf("too deep: %d %v", code, out)
	}

	// 親を外すと、親の権限は効かない。
	if code, out := setParent(sales, nil); code != 200 || out["parent_id"] != nil {
		t.Fatalf("clear parent: %d %v", code, out)
	}
	if code, _ := l.invite(t, boss, sales, "other@acme.example", "member"); code != 403 {
		t.Fatalf("invite after clearing parent: %d", code)
	}

	// Org の削除で子は根になる。
	if code, out := setParent(sales, acme); code != 200 {
		t.Fatalf("set parent again: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", admin, "/v1/admin/orgs/"+acme+":delete", map[string]any{"immediate": true}); code != 200 {
		t.Fatalf("delete parent: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", admin, "/v1/admin/orgs/"+sales, nil); code != 200 || out["parent_id"] != nil {
		t.Fatalf("child after parent deletion: %d %v", code, out)
	}
}
