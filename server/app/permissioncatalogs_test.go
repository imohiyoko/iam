package app

import (
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

// 連携先の権限のカタログ（ADR 0121）。

func TestPermissionCatalogs(t *testing.T) {
	l := newLoginEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	create := func(bearer string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return l.admin(t, "/v1/admin/permission-catalogs", bearer, body)
	}
	docs := map[string]any{"prefix": "docs", "display_name": " Docs ", "permissions": []map[string]any{
		{"name": "docs.doc:write"}, {"name": "docs.doc:read", "description": "文書を読む"}, {"name": "docs.folder:read"}}}

	// permission_catalogs:manage が要る（realm:admin は持たない）。
	if code, _ := create(admin, docs); code != 403 {
		t.Fatalf("create by admin: %d", code)
	}
	code, out := create(owner, docs)
	if code != 201 || out["display_name"] != "Docs" {
		t.Fatalf("create: %d %v", code, out)
	}
	// 権限は名前の順に並べる。
	if ps := out["permissions"].([]any); len(ps) != 3 || ps[0].(map[string]any)["name"] != "docs.doc:read" ||
		ps[0].(map[string]any)["description"] != "文書を読む" || ps[2].(map[string]any)["name"] != "docs.folder:read" {
		t.Fatalf("permissions: %v", ps)
	}
	if code, out := create(owner, docs); code != 409 || out["error"] != "catalog_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	for name, body := range map[string]map[string]any{
		"bad prefix":       {"prefix": "Docs", "display_name": "x", "permissions": []map[string]any{}},
		"dotted prefix":    {"prefix": "a.b", "display_name": "x", "permissions": []map[string]any{}},
		"long prefix":      {"prefix": strings.Repeat("a", 33), "display_name": "x", "permissions": []map[string]any{}},
		"other prefix":     {"prefix": "wiki", "display_name": "x", "permissions": []map[string]any{{"name": "docs.page:read"}}},
		"iam permission":   {"prefix": "wiki", "display_name": "x", "permissions": []map[string]any{{"name": "users:read"}}},
		"wildcard":         {"prefix": "wiki", "display_name": "x", "permissions": []map[string]any{{"name": "wiki.page:*"}}},
		"duplicate":        {"prefix": "wiki", "display_name": "x", "permissions": []map[string]any{{"name": "wiki.page:read"}, {"name": "wiki.page:read"}}},
		"empty name":       {"prefix": "wiki", "display_name": " ", "permissions": []map[string]any{}},
		"control in descr": {"prefix": "wiki", "display_name": "x", "permissions": []map[string]any{{"name": "wiki.page:read", "description": "a\nb"}}},
	} {
		if code, out := create(owner, body); code != 400 || out["error"] != "invalid_catalog" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// 名前の長さは部分ごとに数える（接頭辞 32、リソース 64、操作 64）。
	long := strings.Repeat("p", 32) + "." + strings.Repeat("r", 64) + ":" + strings.Repeat("a", 64)
	if code, out := create(owner, map[string]any{"prefix": strings.Repeat("p", 32), "display_name": "Long",
		"permissions": []map[string]any{{"name": long}}}); code != 201 {
		t.Fatalf("longest permission: %d %v", code, out)
	}

	// 独自のロールには、カタログにある権限と、カタログにあるリソースの `*` だけを入れられる。
	reader := roleWithPerms(t, l, owner, "docs-reader", "docs.doc:read", "docs.folder:*", long)
	for _, ps := range [][]string{{"docs.doc:delete"}, {"docs.page:*"}, {"nope.doc:read"}, {"doc:read"}} {
		code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "bad", "permissions": ps})
		want := "unknown_permission"
		if ps[0] == "doc:read" {
			want = "invalid_permission"
		}
		if code != 400 || out["error"] != want {
			t.Errorf("role %v: %d %v", ps, code, out)
		}
	}

	// 使っている権限は外せず、使っているカタログは消せない。
	put := func(prefix string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return l.adminDo(t, "PUT", owner, "/v1/admin/permission-catalogs/"+prefix, body)
	}
	code, out = put("docs", map[string]any{"display_name": "Docs", "permissions": []map[string]any{{"name": "docs.doc:read"}}})
	if code != 409 || out["error"] != "catalog_in_use" || !strings.Contains(out["message"].(string), reader) {
		t.Fatalf("remove used permission: %d %v", code, out)
	}
	// 使っていない権限は外せる。
	code, out = put("docs", map[string]any{"display_name": "Documents", "permissions": []map[string]any{{"name": "docs.doc:read"}, {"name": "docs.folder:read"}}})
	if code != 200 || out["display_name"] != "Documents" || len(out["permissions"].([]any)) != 2 {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/permission-catalogs/docs:delete", nil); code != 409 || out["error"] != "catalog_in_use" {
		t.Fatalf("delete used: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "POST", owner, "/v1/admin/roles/"+reader+":delete", nil); code != 204 {
		t.Fatalf("delete role: %d", code)
	}
	if code, _ := l.adminDo(t, "POST", owner, "/v1/admin/permission-catalogs/docs:delete", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/permission-catalogs/docs", nil); code != 404 {
		t.Fatalf("get deleted: %d", code)
	}
	code, out = l.adminDo(t, "GET", owner, "/v1/admin/permission-catalogs", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	var prefixes []string
	for _, c := range out["catalogs"].([]any) {
		prefixes = append(prefixes, c.(map[string]any)["prefix"].(string))
	}
	if strings.Join(prefixes, ",") != "app,"+strings.Repeat("p", 32) {
		t.Fatalf("list: %v", prefixes)
	}
	types := map[string]int{}
	for _, ev := range l.auditTypes(t) {
		types[ev.Type]++
	}
	if types["permission_catalog.created"] != 2 || types["permission_catalog.updated"] != 1 || types["permission_catalog.deleted"] != 1 {
		t.Fatalf("audit: %v", types)
	}
}

// 判定の問い合わせは、呼び出し元が受け持つカタログの権限に限る。
func TestCheckLimitedToCallerCatalog(t *testing.T) {
	l := newLoginEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, realmChecker := l.operator(t, "tools@example.com", role.RealmAdmin)
	appID, appChecker := l.operator(t, "app-api@example.com", role.RealmSupport)
	if code, out := l.admin(t, "/v1/admin/permission-catalogs", owner, map[string]any{"prefix": "other", "display_name": "Other",
		"permissions": []map[string]any{{"name": "other.doc:read"}}}); code != 201 {
		t.Fatalf("catalog: %d %v", code, out)
	}
	_, _ = l.login(t, "pat@example.com")
	pat := l.userID(t, "pat@example.com")
	reader := roleWithPerms(t, l, owner, "reader", "app.doc:read", "other.doc:read")
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": reader, "principal_type": "user", "principal_id": pat}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	// app の連携先には、カタログ app の authz:check だけを渡す。
	checker := roleWithPerms(t, l, owner, "app-checker", role.PermAuthzCheck)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": checker, "principal_type": "user", "principal_id": appID,
		"resource_type": "permission_catalog", "resource_id": "app"}); code != 201 {
		t.Fatalf("bind checker: %d %v", code, out)
	}
	check := func(bearer, action string) (int, map[string]any) {
		t.Helper()
		return l.admin(t, "/v1/admin/authz:check", bearer, map[string]any{"principal_id": pat, "action": action})
	}
	if code, out := check(appChecker, "app.doc:read"); code != 200 || out["allowed"] != true {
		t.Fatalf("own catalog: %d %v", code, out)
	}
	for _, a := range []string{"other.doc:read", "users:read"} {
		if code, out := check(appChecker, a); code != 403 {
			t.Errorf("%s by app checker: %d %v", a, code, out)
		}
	}
	// realm 全体の authz:check は、すべてのカタログと IAM 自身の権限に効く。
	for a, want := range map[string]bool{"app.doc:read": true, "other.doc:read": true, "users:read": false} {
		if code, out := check(realmChecker, a); code != 200 || out["allowed"] != want {
			t.Errorf("%s by realm checker: %d %v", a, code, out)
		}
	}
	// バッチの判定は、すべての項目を受け持っていなければ拒む。
	batch := func(actions ...string) int {
		t.Helper()
		var cs []map[string]any
		for _, a := range actions {
			cs = append(cs, map[string]any{"action": a})
		}
		code, _ := l.admin(t, "/v1/admin/authz:batch-check", appChecker, map[string]any{"principal_id": pat, "checks": cs})
		return code
	}
	if code := batch("app.doc:read", "app.doc:write"); code != 200 {
		t.Fatalf("batch own: %d", code)
	}
	if code := batch("app.doc:read", "other.doc:read"); code != 403 {
		t.Fatalf("batch mixed: %d", code)
	}
}
