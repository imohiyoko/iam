package app

import (
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// /v1/admin/authz:batch-check（#153）。

func TestBatchCheck(t *testing.T) {
	l := featureEnv(t, func(c *config.Config) { c.Authz.BatchCheckMax = 4 }, feature.ServiceAccounts)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	_, _ = l.login(t, "pat@example.com")
	pat := l.userID(t, "pat@example.com")
	code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "reader", "permissions": []string{"app.doc:read"}})
	if code != 201 {
		t.Fatalf("role: %d %v", code, out)
	}
	reader := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": reader, "principal_type": "user", "principal_id": pat}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": roleWithPerms(t, l, owner, "writer", "app.doc:write"),
		"principal_type": "user", "principal_id": pat, "resource_type": "doc", "resource_id": "d1"}); code != 201 {
		t.Fatalf("bind resource: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": roleWithPerms(t, l, owner, "approver", "app.payment:approve"),
		"principal_type": "user", "principal_id": pat, "condition": map[string]any{"amr_has": []string{"hwk"}}}); code != 201 {
		t.Fatalf("bind conditional: %d %v", code, out)
	}
	batch := func(body map[string]any) (int, map[string]any) {
		t.Helper()
		return l.admin(t, "/v1/admin/authz:batch-check", checker, body)
	}
	checks := []map[string]any{
		{"action": "app.doc:read"},
		{"action": "app.doc:write", "resource_type": "doc", "resource_id": "d1"},
		{"action": "app.doc:write", "resource_type": "doc", "resource_id": "d2"},
		{"action": "app.payment:approve"},
	}
	code, out = batch(map[string]any{"principal_id": pat, "checks": checks})
	if code != 200 {
		t.Fatalf("batch: %d %v", code, out)
	}
	results := out["results"].([]any)
	want := []bool{true, true, false, false}
	if len(results) != len(want) {
		t.Fatalf("results: %v", results)
	}
	for i, w := range want {
		r := results[i].(map[string]any)
		if r["allowed"] != w {
			t.Fatalf("result %d = %v, want %v", i, r, w)
		}
	}
	// 条件だけで拒んだ判定は、1 件の check と同じく満たさなかった条件を返す。
	if u := results[3].(map[string]any)["unmet"]; !reflect.DeepEqual(u, []any{"condition.amr"}) {
		t.Fatalf("unmet: %v", u)
	}
	// 1 件ずつの check と同じ結果になる。
	for i, c := range checks {
		body := map[string]any{"principal_id": pat}
		for k, v := range c {
			body[k] = v
		}
		code, one := l.admin(t, "/v1/admin/authz:check", checker, body)
		if code != 200 || one["allowed"] != results[i].(map[string]any)["allowed"] {
			t.Fatalf("check %d: %d %v, batch %v", i, code, one, results[i])
		}
	}

	// 上限・空・Org を対象にする判定・知らない操作は 400。
	for name, body := range map[string]map[string]any{
		"too many": {"principal_id": pat, "checks": append(append([]map[string]any{}, checks...), map[string]any{"action": "app.doc:read"})},
		"empty":    {"principal_id": pat, "checks": []map[string]any{}},
		"org":      {"principal_id": pat, "checks": []map[string]any{{"action": "app.doc:read", "resource_type": "org", "resource_id": "org_x"}}},
		"half":     {"principal_id": pat, "checks": []map[string]any{{"action": "app.doc:read", "resource_type": "doc"}}},
		"bad":      {"principal_id": pat, "checks": []map[string]any{{"action": "no colon"}}},
		"type":     {"principal_type": "group", "principal_id": pat, "checks": checks[:1]},
	} {
		if code, out := batch(body); code != 400 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// 無い主体は 404。
	if code, _ := batch(map[string]any{"principal_id": "usr_00000000000000000000000000", "checks": checks[:1]}); code != 404 {
		t.Fatalf("unknown principal: %d", code)
	}
	// 権限の無い呼び出し元は 403。
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	if code, _ := l.admin(t, "/v1/admin/authz:batch-check", support, map[string]any{"principal_id": pat, "checks": checks[:1]}); code != 403 {
		t.Fatalf("support: %d", code)
	}

	// サービスアカウントも同じ。
	sa, _ := l.serviceAccountSecret(t, owner, "bot")
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": reader, "principal_type": "service_account", "principal_id": sa}); code != 201 {
		t.Fatalf("bind sa: %d %v", code, out)
	}
	code, out = batch(map[string]any{"principal_type": "service_account", "principal_id": sa, "checks": checks[:2]})
	if code != 200 {
		t.Fatalf("sa batch: %d %v", code, out)
	}
	if r := out["results"].([]any); r[0].(map[string]any)["allowed"] != true || r[1].(map[string]any)["allowed"] != false {
		t.Fatalf("sa results: %v", r)
	}

	// 使えない主体は、すべての結果が allowed: false で同じ理由。
	_, _ = l.login(t, "sam@example.com")
	sam := l.userID(t, "sam@example.com")
	if code, out := l.admin(t, "/v1/admin/users/"+sam+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "spam"}); code != 201 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	code, out = batch(map[string]any{"principal_id": sam, "checks": checks[:2]})
	if code != 200 {
		t.Fatalf("suspended batch: %d %v", code, out)
	}
	for _, r := range out["results"].([]any) {
		if m := r.(map[string]any); m["allowed"] != false || m["reasons"] == nil {
			t.Fatalf("suspended result: %v", m)
		}
	}
}

// roleWithPerms は realm のロールを作って ID を返す。
func roleWithPerms(t *testing.T, l *loginEnv, owner, name string, perms ...string) string {
	t.Helper()
	code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": name, "permissions": perms})
	if code != 201 {
		t.Fatalf("role: %d %v", code, out)
	}
	return out["id"].(string)
}
