package app

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
)

// 操作の名前空間の要件と Org の要件（ADR 0084）を HTTP で確かめる。

func TestRequirements(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, op := l.operator(t, "root@example.com", role.RealmOwner)
	supportID, support := l.operator(t, "help@example.com", role.RealmSupport)
	put := func(bearer, name string, body map[string]any) (int, map[string]any) {
		return l.adminDo(t, "PUT", bearer, "/v1/admin/action-namespaces/"+name, body)
	}
	get := func(bearer, name string) (int, map[string]any) {
		return l.adminDo(t, "GET", bearer, "/v1/admin/action-namespaces/"+name, nil)
	}

	// 設定していない名前空間は空。
	if code, out := get(op, "payment"); code != 200 || len(out["requirements"].(map[string]any)) != 0 || out["updated_at"] != nil {
		t.Fatalf("get empty: %d %v", code, out)
	}
	for _, c := range []struct {
		name string
		body map[string]any
		err  string
	}{
		{"Payment", map[string]any{}, "invalid_namespace"},
		{"payment", map[string]any{"requirements": map[string]any{"doc:read": map[string]any{"auth_within": 300}}}, "invalid_requirement"},
		{"payment", map[string]any{"requirements": map[string]any{"payment:send": map[string]any{}}}, "invalid_condition"},
		{"payment", map[string]any{"requirements": map[string]any{"payment:send": map[string]any{"nope": 1}}}, "invalid_condition"},
		{"payment", map[string]any{"bands": map[string]any{"account": map[string]any{"medium": 40, "high": 60}}}, "invalid_band"},
		{"payment", map[string]any{"bands": map[string]any{"payment.fraud": map[string]any{"medium": 10, "high": 20}}}, "invalid_band"},
	} {
		if code, out := put(op, c.name, c.body); code != 400 || out["error"] != c.err {
			t.Fatalf("put %s %v: %d %v", c.name, c.body, code, out)
		}
	}
	reqs := map[string]any{"payment:send": map[string]any{"factors_at_least": float64(2)}, "payment:*": map[string]any{"auth_within": float64(3600)}}
	bands := map[string]any{"account": map[string]any{"medium": float64(20), "high": float64(60)}}
	code, out := put(op, "payment", map[string]any{"requirements": reqs, "bands": bands})
	if code != 200 || !reflect.DeepEqual(out["requirements"], reqs) || !reflect.DeepEqual(out["bands"], bands) || out["updated_at"] == nil {
		t.Fatalf("put: %d %v", code, out)
	}
	if code, got := get(op, "payment"); code != 200 || !reflect.DeepEqual(got, out) {
		t.Fatalf("get: %d %v, want %v", code, got, out)
	}
	ev := lastAudit(l.auditTypes(t), "authz.requirement_updated")
	if ev == nil || ev.Details["namespace"] != "payment" || ev.Details["settings"] == nil || ev.Details["previous"] != nil {
		t.Fatalf("audit: %+v", ev)
	}
	n := countAudit(l.auditTypes(t), "authz.requirement_updated")
	if code, _ := put(op, "payment", map[string]any{"requirements": reqs, "bands": bands}); code != 200 || countAudit(l.auditTypes(t), "authz.requirement_updated") != n {
		t.Fatalf("unchanged put: %d", code)
	}

	// 要件は付与で許した操作に求める（メールのコードの1要素では満たさない）。
	code, out = l.admin(t, "/v1/admin/roles", op, map[string]any{"name": "payer", "permissions": []string{"payment:send", "payment:read", "doc:read"}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, out)
	}
	payer := out["id"].(string)
	_, alice := l.login(t, "alice@example.com")
	if code, out := l.admin(t, "/v1/admin/role-bindings", op, map[string]any{"role": payer, "principal_type": "user", "principal_id": l.userID(t, "alice@example.com")}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	meCheck := func(cookie, action string, extra map[string]any) map[string]any {
		body := map[string]any{"action": action}
		for k, v := range extra {
			body[k] = v
		}
		code, out := l.mePost(t, cookie, "/v1/me:check", body)
		if code != 200 {
			t.Fatalf("me:check %s: %d %v", action, code, out)
		}
		return out
	}
	if out := meCheck(alice, "payment:send", nil); out["allowed"] != false || !reflect.DeepEqual(out["unmet"], []any{"condition.factors"}) {
		t.Fatalf("send: %v", out)
	}
	for _, a := range []string{"payment:read", "doc:read"} {
		if out := meCheck(alice, a, nil); out["allowed"] != true {
			t.Fatalf("%s: %v", a, out)
		}
	}

	// 1つの名前空間に限った requirements:manage。
	code, out = l.admin(t, "/v1/admin/roles", op, map[string]any{"name": "payment-requirements", "permissions": []string{role.PermRequirementsManage}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", op, map[string]any{"role": out["id"], "principal_type": "user", "principal_id": supportID,
		"resource_type": "action_namespace", "resource_id": "payment"}); code != 201 {
		t.Fatalf("bind scoped: %d %v", code, out)
	}
	if code, out := get(support, "payment"); code != 200 {
		t.Fatalf("scoped get: %d %v", code, out)
	}
	for _, name := range []string{"doc", "requirements"} {
		if code, _ := get(support, name); code != 403 {
			t.Fatalf("scoped get %s: %d", name, code)
		}
		if code, _ := put(support, name, map[string]any{}); code != 403 {
			t.Fatalf("scoped put %s: %d", name, code)
		}
	}

	// 自分を締め出す設定は拒む（変更は残らない）。
	if code, out := put(op, "requirements", map[string]any{"requirements": map[string]any{"requirements:manage": map[string]any{"amr_has": []string{"hwk"}}}}); code != 409 || out["error"] != "requirement_lockout" {
		t.Fatalf("lockout: %d %v", code, out)
	}
	if code, out := get(op, "requirements"); code != 200 || out["updated_at"] != nil {
		t.Fatalf("after lockout: %d %v", code, out)
	}

	// Org の要件：この Org を文脈にした判定に足す。
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	for _, c := range []struct {
		reqs map[string]any
		err  string
	}{
		{map[string]any{"bad": map[string]any{"amr_has": []string{"hwk"}}}, "invalid_requirement"},
		{map[string]any{"org:invite": map[string]any{}}, "invalid_condition"},
		{map[string]any{"org:invite": map[string]any{"risk_below": map[string]any{"type": "nope.x", "score": 10}}}, "invalid_condition"},
	} {
		if code, out := l.putSettings(t, boss, acme, map[string]any{"requirements": c.reqs}); code != 400 || out["error"] != c.err {
			t.Fatalf("put org requirements %v: %d %v", c.reqs, code, out)
		}
	}
	orgReqs := map[string]any{"org:invite": map[string]any{"amr_has": []any{"hwk"}}}
	code, out = l.putSettings(t, boss, acme, map[string]any{"requirements": orgReqs})
	if code != 200 || !reflect.DeepEqual(out["settings"].(map[string]any)["requirements"], orgReqs) {
		t.Fatalf("put org requirements: %d %v", code, out)
	}
	if out := meCheck(boss, "org:invite", map[string]any{"org_id": acme}); out["allowed"] != false || !reflect.DeepEqual(out["unmet"], []any{"condition.amr"}) {
		t.Fatalf("org requirement: %v", out)
	}
	if out := meCheck(boss, "org:read", map[string]any{"org_id": acme}); out["allowed"] != true {
		t.Fatalf("org read: %v", out)
	}
	// 管理 API の設定も同じ形。
	code, out = l.adminDo(t, "GET", op, "/v1/admin/orgs/"+acme+"/settings", nil)
	if code != 200 || !reflect.DeepEqual(out["settings"].(map[string]any)["requirements"], orgReqs) {
		t.Fatalf("admin get org settings: %d %v", code, out)
	}

	// 見ている条件が残る種類は止められない。
	// 自分を締め出す要件（org:settings を満たさなくなる）は拒む。
	if code, out := l.putSettings(t, boss, acme, map[string]any{"requirements": map[string]any{"org:*": map[string]any{"risk_below": map[string]any{"type": "account", "score": 50}}}}); code != 409 || out["error"] != "requirement_lockout" {
		t.Fatalf("org lockout: %d %v", code, out)
	}
	if code, out := l.putSettings(t, boss, acme, map[string]any{"requirements": map[string]any{"org:invite": map[string]any{"risk_below": map[string]any{"type": "account", "score": 50}}}}); code != 200 {
		t.Fatalf("put org risk requirement: %d %v", code, out)
	}
	code, out = l.adminDo(t, "PUT", op, "/v1/admin/risk-types/account", map[string]any{"enabled": false})
	if msg, _ := out["message"].(string); code != 409 || out["error"] != "risk_type_in_use" || !strings.Contains(msg, "action namespaces payment") || !strings.Contains(msg, "requirements of 1 orgs") {
		t.Fatalf("disable referenced: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/risk-types/device", map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("disable unreferenced: %d %v", code, out)
	}
	if code, _ := put(op, "payment", map[string]any{}); code != 200 {
		t.Fatalf("clear namespace: %d", code)
	}
	if code, _ := l.putSettings(t, boss, acme, map[string]any{}); code != 200 {
		t.Fatalf("clear org: %d", code)
	}
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/risk-types/account", map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("disable after clearing: %d %v", code, out)
	}
	// 条件を外したので、すぐに通る。
	if out := meCheck(alice, "payment:send", nil); out["allowed"] != true {
		t.Fatalf("send after clearing: %v", out)
	}
}

// 本人の重要な操作は、max_auth_age に加えて名前空間 me の要件を求める（max_auth_age の載せ替え。ADR 0084）。
func TestSensitiveOperationRequirements(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, op := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/action-namespaces/me", map[string]any{"requirements": map[string]any{
		role.ActionMeDelete: map[string]any{"auth_within": 60}}}); code != 200 {
		t.Fatalf("put me: %d %v", code, out)
	}
	_, alice := l.login(t, "alice@example.com")
	// max_auth_age（15 分）の内でも、要件の 60 秒を過ぎれば再認証を求める。要件の無い操作は今までどおり。
	l.advance(2 * time.Minute)
	if code, out := l.mePost(t, alice, "/v1/me/account:delete", nil); code != 401 || out["error"] != "reauthentication_required" {
		t.Fatalf("delete after 2m: %d %v", code, out)
	}
	if code, out := l.mePost(t, alice, "/v1/me/recovery-codes:regenerate", nil); code != 200 {
		t.Fatalf("regenerate after 2m: %d %v", code, out)
	}
	_, alice = l.login(t, "alice@example.com")
	if code, out := l.mePost(t, alice, "/v1/me/account:delete", nil); code != 200 {
		t.Fatalf("delete after login: %d %v", code, out)
	}
}
