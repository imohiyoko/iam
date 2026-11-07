package app

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
)

// /v1/admin/authz:check の主体にサービスアカウントを指定する（#152）。

func TestCheckServiceAccount(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	sa, secret := l.serviceAccountSecret(t, owner, "partner-bot")
	other, otherSecret := l.serviceAccountSecret(t, owner, "other-bot")
	code, out := l.admin(t, "/v1/admin/service-accounts/"+sa+"/credentials", owner, map[string]any{"type": "api_key"})
	if code != 201 {
		t.Fatalf("api key: %d %v", code, out)
	}
	apiKey := out["secret"].(string)
	check := func(body map[string]any) map[string]any {
		t.Helper()
		body["principal_type"] = "service_account"
		code, out := l.admin(t, "/v1/admin/authz:check", checker, body)
		if code != 200 {
			t.Fatalf("check %v: %d %v", body, code, out)
		}
		return out
	}
	allowed := func(principal, action string) bool {
		t.Helper()
		return check(map[string]any{"principal_id": principal, "action": action})["allowed"] == true
	}
	roleWith := func(name string, perms ...string) string {
		t.Helper()
		code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": name, "permissions": perms})
		if code != 201 {
			t.Fatalf("role: %d %v", code, out)
		}
		return out["id"].(string)
	}
	bind := func(body map[string]any) {
		t.Helper()
		if code, out := l.admin(t, "/v1/admin/role-bindings", owner, body); code != 201 {
			t.Fatalf("bind %v: %d %v", body, code, out)
		}
	}

	// 直接の付与。
	bind(map[string]any{"role": roleWith("reader", "app.doc:read"), "principal_type": "service_account", "principal_id": sa})
	if !allowed(sa, "app.doc:read") || allowed(sa, "app.doc:write") || allowed(other, "app.doc:read") {
		t.Fatal("direct binding")
	}
	// Group の所属を通した付与。
	code, out = l.admin(t, "/v1/admin/groups", owner, map[string]any{"name": "partners"})
	if code != 201 {
		t.Fatalf("group: %d %v", code, out)
	}
	gid := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/groups/"+gid+"/members", owner, map[string]any{"principal_type": "service_account", "principal_id": sa}); code != 204 {
		t.Fatalf("member: %d %v", code, out)
	}
	bind(map[string]any{"role": roleWith("writer", "app.doc:write"), "principal_type": "group", "principal_id": gid})
	if !allowed(sa, "app.doc:write") || allowed(other, "app.doc:write") {
		t.Fatal("group binding")
	}
	// リソースを限った付与。
	bind(map[string]any{"role": roleWith("deleter", "app.doc:delete"), "principal_type": "service_account", "principal_id": sa, "resource_type": "doc", "resource_id": "d1"})
	for rid, want := range map[string]bool{"d1": true, "d2": false} {
		if out := check(map[string]any{"principal_id": sa, "action": "app.doc:delete", "resource_type": "doc", "resource_id": rid}); out["allowed"] != want {
			t.Fatalf("resource %s: %v", rid, out)
		}
	}

	// 条件付きの付与は、主体のアクセストークンから組み立てた文脈（attested）でだけ効く。
	bind(map[string]any{"role": roleWith("approver", "app.payment:approve"), "principal_type": "service_account", "principal_id": sa,
		"condition": map[string]any{"amr_has": []string{"client_secret"}}})
	if out := check(map[string]any{"principal_id": sa, "action": "app.payment:approve"}); out["allowed"] != false || out["unmet"] == nil {
		t.Fatalf("without a token: %v", out)
	}
	token := func(form url.Values, basic string) string {
		t.Helper()
		code, out := l.token(t, form, basic)
		if code != 200 {
			t.Fatalf("token: %d %v", code, out)
		}
		return out["access_token"].(string)
	}
	adminTok := token(url.Values{"grant_type": {"client_credentials"}}, sa+":"+secret)
	if out := check(map[string]any{"principal_id": sa, "action": "app.payment:approve", "access_token": adminTok}); out["allowed"] != true {
		t.Fatalf("with its admin token: %v", out)
	}
	// 自前の API 向けのトークン（リソースサーバーが受けたもの）でも組み立てる。
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"app.orders:read"}, "service_accounts": []string{sa, other}}); code != 201 {
		t.Fatalf("resource: %d %v", code, out)
	}
	resTok := token(url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, sa+":"+secret)
	if out := check(map[string]any{"principal_id": sa, "action": "app.payment:approve", "access_token": resTok}); out["allowed"] != true {
		t.Fatalf("with its resource token: %v", out)
	}
	// ほかの主体のトークン、API キー、申告の文脈、ユーザーの sid は文脈にしない。
	otherTok := token(url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, other+":"+otherSecret)
	for name, body := range map[string]map[string]any{
		"other's token": {"access_token": otherTok},
		"api key":       {"access_token": apiKey},
		"bogus token":   {"access_token": "sat_bogus"},
		"declared":      {"context": map[string]any{"amr": []string{"client_secret"}}},
		"sid":           {"sid": "ses_none"},
	} {
		body["principal_id"], body["action"] = sa, "app.payment:approve"
		if out := check(body); out["allowed"] != false {
			t.Fatalf("%s: %v", name, out)
		}
	}

	// リソースを消すと、そのリソースに向けたトークンは文脈にならない。
	_, res := l.adminDo(t, "GET", owner, "/v1/admin/oauth/resources", nil)
	rid := res["resources"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.admin(t, "/v1/admin/oauth/resources/"+rid+":delete", owner, nil); code != 204 {
		t.Fatalf("delete resource: %d", code)
	}
	if out := check(map[string]any{"principal_id": sa, "action": "app.payment:approve", "access_token": resTok}); out["allowed"] != false {
		t.Fatalf("resource token after the resource was deleted: %v", out)
	}

	// 停止中・削除済みは allowed: false と理由のコード。
	if code, out := l.admin(t, "/v1/admin/service-accounts/"+sa+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "leaked"}); code != 201 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	if out := check(map[string]any{"principal_id": sa, "action": "app.doc:read"}); out["allowed"] != false || out["reasons"] == nil {
		t.Fatalf("suspended: %v", out)
	}
	if code, out := l.admin(t, "/v1/admin/service-accounts/"+other+":delete", owner, nil); code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if out := check(map[string]any{"principal_id": other, "action": "app.doc:read"}); out["allowed"] != false || !reflect.DeepEqual(out["reasons"], []any{"inactive"}) {
		t.Fatalf("deleted: %v", out)
	}

	// 無い主体は 404、知らない種類は 400。
	if code, out := l.admin(t, "/v1/admin/authz:check", checker, map[string]any{"principal_type": "service_account", "principal_id": "sva_00000000000000000000000000",
		"action": "app.doc:read"}); code != 404 {
		t.Fatalf("unknown: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/authz:check", checker, map[string]any{"principal_type": "group", "principal_id": gid, "action": "app.doc:read"}); code != 400 {
		t.Fatalf("group principal: %d %v", code, out)
	}
}

// 所属の Org が使えないサービスアカウントは、どの範囲の判定でも allowed: false。
func TestCheckOrgServiceAccount(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	code, out := l.admin(t, "/v1/admin/users", owner, map[string]any{"email": "boss@acme.example"})
	if code != 201 {
		t.Fatalf("user: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/orgs", owner, map[string]any{"name": "Acme", "owner_id": out["user_id"]})
	if code != 201 {
		t.Fatalf("org: %d %v", code, out)
	}
	acme := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "acme-bot", "org_id": acme})
	if code != 201 {
		t.Fatalf("service account: %d %v", code, out)
	}
	sa := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "reader", "permissions": []string{"app.doc:read"}})
	if code != 201 {
		t.Fatalf("role: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": out["id"], "principal_type": "service_account", "principal_id": sa}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	check := func(org string) map[string]any {
		t.Helper()
		body := map[string]any{"principal_type": "service_account", "principal_id": sa, "action": "app.doc:read"}
		if org != "" {
			body["org_id"] = org
		}
		code, out := l.admin(t, "/v1/admin/authz:check", checker, body)
		if code != 200 {
			t.Fatalf("check: %d %v", code, out)
		}
		return out
	}
	if a, r := check(acme), check(""); a["allowed"] != true || r["allowed"] != true {
		t.Fatalf("before suspension: %v %v", a, r)
	}
	if code, out := l.admin(t, "/v1/admin/orgs/"+acme+"/suspensions", owner, map[string]any{"category": "billing", "reason": "unpaid"}); code != 201 {
		t.Fatalf("suspend org: %d %v", code, out)
	}
	for _, org := range []string{acme, ""} {
		if out := check(org); out["allowed"] != false || out["reasons"] == nil {
			t.Fatalf("org suspended (%q): %v", org, out)
		}
	}
}

// フィーチャー service_accounts が止まっていれば、サービスアカウントの判定は 400。
func TestCheckServiceAccountFeatureOff(t *testing.T) {
	l := featureEnv(t, nil)
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	if code, out := l.admin(t, "/v1/admin/authz:check", checker, map[string]any{"principal_type": "service_account", "principal_id": "sva_00000000000000000000000000",
		"action": "app.doc:read"}); code != 400 || out["error"] != "invalid_request" {
		t.Fatalf("feature off: %d %v", code, out)
	}
}

// DPoP に結び付けたトークンは、鍵の証明を確かめられないので判定の文脈にしない（ADR 0113）。
func TestCheckServiceAccountDPoPToken(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP, feature.ServiceAccounts)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, checker := l.operator(t, "app@example.com", role.RealmAdmin)
	sa, secret := l.serviceAccountSecret(t, owner, "partner-bot")
	code, out := l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "approver", "permissions": []string{"app.payment:approve"}})
	if code != 201 {
		t.Fatalf("role: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": out["id"], "principal_type": "service_account", "principal_id": sa,
		"condition": map[string]any{"amr_has": []string{"client_secret"}}}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret}}
	check := func(token string) bool {
		t.Helper()
		code, out := l.admin(t, "/v1/admin/authz:check", checker, map[string]any{"principal_type": "service_account", "principal_id": sa,
			"action": "app.payment:approve", "access_token": token})
		if code != 200 {
			t.Fatalf("check: %d %v", code, out)
		}
		return out["allowed"] == true
	}
	w, tok := l.form(t, l.a.AdminHandler(), "POST", adminTokenPath, form, nil)
	if w.Code != 200 || tok["token_type"] != "Bearer" {
		t.Fatalf("bearer token: %d %v", w.Code, tok)
	}
	if !check(tok["access_token"].(string)) {
		t.Fatal("bearer token should give the context")
	}
	k := dpoptest.NewKey(t)
	w, tok = l.form(t, l.a.AdminHandler(), "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("dpop token: %d %v", w.Code, tok)
	}
	if check(tok["access_token"].(string)) {
		t.Fatal("a DPoP-bound token without a proof gave the context")
	}
}
