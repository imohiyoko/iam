package app

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// カスタム属性（design.md 11.7、ADR 0080）を HTTP で確かめる。

func attributesEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.CustomAttributes)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestCustomAttributes(t *testing.T) {
	l := attributesEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	define := func(body map[string]any) (int, map[string]any) {
		return l.adminDo(t, "POST", owner, "/v1/admin/attributes", body)
	}
	for _, body := range []map[string]any{
		{"key": "department", "type": "string", "max_length": 8, "user_editable": true, "in_token": true},
		{"key": "tier", "type": "enum", "values": []string{"gold", "silver"}, "in_token": true, "encrypted": true},
		{"key": "employee_no", "type": "integer"},
		{"key": "newsletter", "type": "boolean", "user_editable": true},
	} {
		if code, out := define(body); code != 201 {
			t.Fatalf("define %v: %d %v", body["key"], code, out)
		}
	}
	for _, c := range []struct {
		body map[string]any
		code int
		err  string
	}{
		{map[string]any{"key": "department", "type": "string"}, 409, "attribute_exists"},
		{map[string]any{"key": "Bad-Key", "type": "string"}, 400, "invalid_attribute"},
		{map[string]any{"key": "color", "type": "enum"}, 400, "invalid_attribute"},
		{map[string]any{"key": "flag", "type": "boolean", "values": []string{"x"}}, 400, "invalid_attribute"},
	} {
		if code, out := define(c.body); code != c.code || out["error"] != c.err {
			t.Fatalf("define %v: %d %v", c.body, code, out)
		}
	}
	if code, _ := l.adminDo(t, "POST", support, "/v1/admin/attributes", map[string]any{"key": "x", "type": "string"}); code != 403 {
		t.Fatalf("support defines: %d", code)
	}
	code, out := l.adminDo(t, "GET", support, "/v1/admin/attributes", nil)
	if code != 200 || len(out["attributes"].([]any)) != 4 || out["attributes"].([]any)[0].(map[string]any)["key"] != "department" {
		t.Fatalf("list defs: %d %v", code, out)
	}

	// 運営者が値を書く。どれかが誤りなら何も書かない。
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	base := "/v1/admin/users/" + aliceID + "/attributes"
	for _, c := range []struct {
		attrs map[string]any
		err   string
	}{
		{map[string]any{"tier": "bronze"}, "invalid_attribute_value"},
		{map[string]any{"department": "toolongvalue"}, "invalid_attribute_value"},
		{map[string]any{"employee_no": 1.5}, "invalid_attribute_value"},
		{map[string]any{"newsletter": "yes"}, "invalid_attribute_value"},
		{map[string]any{"tier": "gold", "nope": 1}, "unknown_attribute"},
	} {
		if code, out := l.adminDo(t, "PATCH", owner, base, map[string]any{"attributes": c.attrs}); code != 400 || out["error"] != c.err {
			t.Fatalf("write %v: %d %v", c.attrs, code, out)
		}
	}
	code, out = l.adminDo(t, "PATCH", owner, base, map[string]any{"attributes": map[string]any{"tier": "gold", "employee_no": 1234, "department": "sales"}})
	if a, _ := out["attributes"].(map[string]any); code != 200 || a["tier"] != "gold" || a["employee_no"] != float64(1234) || a["department"] != "sales" {
		t.Fatalf("write: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "PATCH", support, base, map[string]any{"attributes": map[string]any{"tier": "silver"}}); code != 403 {
		t.Fatalf("support writes: %d", code)
	}
	if code, out := l.adminDo(t, "GET", support, base, nil); code != 200 || out["attributes"].(map[string]any)["tier"] != "gold" {
		t.Fatalf("support reads: %d %v", code, out)
	}
	// 暗号化する属性は平文で保存しない。
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, aliceID)
		if err != nil {
			return err
		}
		vs, err := tx.Attributes().ListValues(ctx, l.a.realm.ID, u.ID)
		for _, v := range vs {
			if v.Key == "tier" && strings.Contains(string(v.Value), "gold") {
				t.Fatal("encrypted attribute stored in plaintext")
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// 本人は編集できる属性だけを書ける。
	code, out = l.meDo(t, "GET", alice, "/v1/me/attributes", nil)
	if ed, _ := out["editable"].([]any); code != 200 || len(ed) != 2 || out["attributes"].(map[string]any)["employee_no"] != float64(1234) {
		t.Fatalf("my attributes: %d %v", code, out)
	}
	if code, out := l.meDo(t, "PATCH", alice, "/v1/me/attributes", map[string]any{"attributes": map[string]any{"tier": "silver"}}); code != 403 || out["error"] != "attribute_not_editable" {
		t.Fatalf("self writes tier: %d %v", code, out)
	}
	code, out = l.meDo(t, "PATCH", alice, "/v1/me/attributes", map[string]any{"attributes": map[string]any{"department": "eng", "newsletter": true}})
	if a, _ := out["attributes"].(map[string]any); code != 200 || a["department"] != "eng" || a["newsletter"] != true {
		t.Fatalf("self writes: %d %v", code, out)
	}
	if code, out := l.meDo(t, "PATCH", alice, "/v1/me/attributes", map[string]any{"attributes": map[string]any{"newsletter": nil}}); code != 200 || out["attributes"].(map[string]any)["newsletter"] != nil {
		t.Fatalf("self clears: %d %v", code, out)
	}

	// スコープ attributes の ID トークンと UserInfo に、in_token の属性だけを載せる。
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if !strings.Contains(w.Body.String(), `"attributes"`) {
		t.Fatalf("discovery lacks attributes: %s", w.Body)
	}
	codeA, _ := p.login(t, "alice@example.com", url.Values{"scope": {"openid attributes"}})
	status, tok := p.exchange(t, codeA, nil)
	if status != 200 || tok["scope"] != "openid attributes" {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	if a, _ := claims["attributes"].(map[string]any); len(a) != 2 || a["department"] != "eng" || a["tier"] != "gold" || claims["email"] != nil {
		t.Fatalf("id token attributes: %v", claims)
	}
	if status, info := l.userinfo(t, tok["access_token"].(string)); status != 200 || info["attributes"].(map[string]any)["tier"] != "gold" {
		t.Fatalf("userinfo: %d %v", status, info)
	}
	codeB, _ := p.login(t, "alice@example.com", nil)
	if _, tok := p.exchange(t, codeB, nil); l.idClaims(t, tok["id_token"].(string), port.AlgES256)["attributes"] != nil {
		t.Fatal("attributes without the scope")
	}

	// 定義を変え・消す。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/tier", map[string]any{"values": []string{"gold", "platinum"}}); code != 200 || out["in_token"] != false || out["encrypted"] != true {
		t.Fatalf("update def: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "POST", owner, "/v1/admin/attributes/department:delete", nil); code != 204 {
		t.Fatalf("delete def: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, base, nil); code != 200 || out["attributes"].(map[string]any)["department"] != nil {
		t.Fatalf("values after delete: %d %v", code, out)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	for _, typ := range []string{"attribute.defined", "attribute.updated", "attribute.deleted", "user.attributes_updated"} {
		if types[typ] == 0 {
			t.Errorf("audit missing %s: %v", typ, types)
		}
	}
}

func TestCustomAttributesOff(t *testing.T) {
	l := attributesEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/attributes", nil); code != 404 || out["error"] != "attributes_disabled" {
		t.Fatalf("list while off: %d %v", code, out)
	}
	_, alice := l.login(t, "alice@example.com")
	if code, _ := l.meDo(t, "GET", alice, "/v1/me/attributes", nil); code != 404 {
		t.Fatalf("me while off: %d", code)
	}
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if strings.Contains(w.Body.String(), `"attributes"`) {
		t.Fatalf("discovery has attributes while off: %s", w.Body)
	}
}
