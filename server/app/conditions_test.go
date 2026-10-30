package app

import (
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

// 付与の条件（ADR 0084）を HTTP で確かめる。

func TestBindingConditions(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "payment-approver", "permissions": []string{"payment:approve"}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, out)
	}
	approver := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "payment-reader", "permissions": []string{"payment:read"}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, out)
	}
	reader := out["id"].(string)
	bind := func(roleID string, cond any) (int, map[string]any) {
		body := map[string]any{"role": roleID, "principal_type": "user", "principal_id": aliceID}
		if cond != nil {
			body["condition"] = cond
		}
		return l.admin(t, "/v1/admin/role-bindings", owner, body)
	}
	deep := map[string]any{"all": []any{map[string]any{"all": []any{map[string]any{"all": []any{map[string]any{"all": []any{map[string]any{"attested": true}}}}}}}}}
	for _, cond := range []any{
		map[string]any{},
		map[string]any{"amr_has": []string{"hwk"}, "attested": true},
		map[string]any{"amr": []string{"hwk"}},
		map[string]any{"factors_at_least": 4},
		map[string]any{"risk_below": map[string]any{"type": "payment.fraud", "score": 30}},
		map[string]any{"risk_at_most": map[string]any{"type": "account", "level": "extreme"}},
		map[string]any{"any": []any{}},
		deep,
	} {
		if code, out := bind(approver, cond); code != 400 || out["error"] != "invalid_condition" {
			t.Fatalf("bind with %v: %d %v", cond, code, out)
		}
	}
	cond := map[string]any{"amr_has": []any{"hwk"}}
	code, out = bind(approver, cond)
	if code != 201 || !reflect.DeepEqual(out["condition"], cond) {
		t.Fatalf("bind with condition: %d %v", code, out)
	}
	if code, out := bind(reader, map[string]any{"all": []any{map[string]any{"factors_at_least": 1}, map[string]any{"auth_within": 3600}}}); code != 201 {
		t.Fatalf("bind reader: %d %v", code, out)
	}
	ev := lastAudit(l.auditTypes(t), "role.granted")
	if ev == nil || ev.Details["condition"] == nil {
		t.Fatalf("role.granted: %+v", ev)
	}
	code, out = l.adminDo(t, "GET", owner, "/v1/admin/role-bindings", nil)
	found := false
	for _, b := range out["bindings"].([]any) {
		if m := b.(map[string]any); m["role"] == approver && reflect.DeepEqual(m["condition"], cond) {
			found = true
		}
	}
	if code != 200 || !found {
		t.Fatalf("list bindings: %d %v", code, out)
	}

	// 条件を満たさないので許さず、理由を返す。満たす付与は効く。付与の無い操作は理由なし。
	meCheck := func(action string) map[string]any {
		code, out := l.mePost(t, alice, "/v1/me:check", map[string]any{"action": action})
		if code != 200 {
			t.Fatalf("me:check %s: %d %v", action, code, out)
		}
		return out
	}
	if out := meCheck("payment:approve"); out["allowed"] != false || !reflect.DeepEqual(out["unmet"], []any{"condition.amr"}) {
		t.Fatalf("approve: %v", out)
	}
	if out := meCheck("payment:read"); out["allowed"] != true || out["unmet"] != nil {
		t.Fatalf("read: %v", out)
	}
	if out := meCheck("payment:send"); out["allowed"] != false || out["unmet"] != nil {
		t.Fatalf("send: %v", out)
	}
	// 管理 API の判定は主体だけでは文脈が無いので、条件付きの付与は満たさない。
	code, out = l.admin(t, "/v1/admin/authz:check", owner, map[string]any{"principal_id": aliceID, "action": "payment:read"})
	if code != 200 || out["allowed"] != false || !reflect.DeepEqual(out["unmet"], []any{"condition.auth_age", "condition.factors"}) {
		t.Fatalf("admin check: %d %v", code, out)
	}

	// 条件付きの realm:owner は、条件を満たさない文脈では管理の操作に効かない（権限の引き上げの検査も同じ）。
	ownerID := l.userID(t, "root@example.com")
	_, boss := l.login(t, "boss@example.com")
	bossID := l.userID(t, "boss@example.com")
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmOwner, "principal_type": "user", "principal_id": bossID,
		"condition": map[string]any{"amr_has": []string{"hwk"}}}); code != 201 {
		t.Fatalf("bind conditional owner: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", boss, map[string]any{"role": reader, "principal_type": "user", "principal_id": ownerID}); code != 403 {
		t.Fatalf("conditional owner binds: %d %v", code, out)
	}
}
