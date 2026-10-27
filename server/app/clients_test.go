package app

import (
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

func TestClientsAdminAPI(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	body := map[string]any{"name": "Shop", "redirect_uris": []string{"https://shop.example.com/cb"}, "token_endpoint_auth_method": "client_secret"}
	if code, _ := l.admin(t, "/v1/admin/clients", admin, body); code != 403 {
		t.Fatalf("admin creates client: %d", code)
	}
	code, out := l.admin(t, "/v1/admin/clients", owner, body)
	if code != 201 || out["client_secret"] == nil || out["id_token_signed_response_alg"] != "ES256" || out["trust_level"] != "first_party" {
		t.Fatalf("create: %d %v", code, out)
	}
	cid := out["client_id"].(string)
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "Bad", "redirect_uris": []string{"http://evil.example/cb"},
		"token_endpoint_auth_method": "none"}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("bad redirect: %d %v", code, out)
	}
	code, out = l.adminDo(t, "GET", owner, "/v1/admin/clients/"+cid, nil)
	if code != 200 || out["client_secret"] != nil {
		t.Fatalf("get: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/clients/"+cid+":rotate-secret", owner, nil)
	if code != 200 || out["client_secret"] == "" {
		t.Fatalf("rotate: %d %v", code, out)
	}
	body["token_endpoint_auth_method"], body["id_token_signed_response_alg"] = "none", "ML-DSA-65"
	code, out = l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+cid, body)
	if code != 200 || out["id_token_signed_response_alg"] != "ML-DSA-65" || out["client_secret"] != nil {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/clients/"+cid+":rotate-secret", owner, nil); code != 409 || out["error"] != "no_client_secret" {
		t.Fatalf("rotate public client: %d %v", code, out)
	}
	code, out = l.adminDo(t, "GET", owner, "/v1/admin/clients", nil)
	if code != 200 || len(out["clients"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := l.admin(t, "/v1/admin/clients/"+cid+":delete", owner, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+cid, nil); code != 404 {
		t.Fatalf("get deleted: %d", code)
	}
	// 署名鍵のローテーションは realm:owner だけ。
	if code, _ := l.admin(t, "/v1/admin/signing-keys:rotate", admin, map[string]any{"alg": "ES256"}); code != 403 {
		t.Fatalf("admin rotates key: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/signing-keys:rotate", owner, map[string]any{"alg": "ML-DSA-65"}); code != 200 || out["kid"] == "" {
		t.Fatalf("rotate key: %d %v", code, out)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	for _, typ := range []string{"client.created", "client.secret_rotated", "client.updated", "client.deleted", "signing_key.rotated"} {
		if types[typ] != 1 {
			t.Errorf("audit %s = %d", typ, types[typ])
		}
	}
}
