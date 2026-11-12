package app

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// フィーチャー standard_claims（カスタム属性から OIDC の標準クレームへの対応付け。ADR 0127）を HTTP で確かめる。

func standardClaimsEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.CustomAttributes)
		if on {
			names = append(names, feature.StandardClaims)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestStandardClaimsOff(t *testing.T) {
	l := standardClaimsEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/attributes", map[string]any{"key": "full_name", "type": "string", "claim": "name"}); code != 400 ||
		out["error"] != "invalid_attribute" {
		t.Fatalf("claim while off: %d %v", code, out)
	}
	if s := l.discoveryScopes(t); slices.Contains(s, any("profile")) {
		t.Fatalf("profile advertised while off: %v", s)
	}
}

func TestStandardClaims(t *testing.T) {
	l := standardClaimsEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	define := func(body map[string]any) (int, map[string]any) {
		return l.adminDo(t, "POST", owner, "/v1/admin/attributes", body)
	}
	for _, body := range []map[string]any{
		{"key": "full_name", "type": "string", "claim": "name"},
		{"key": "lang", "type": "enum", "values": []string{"ja-JP", "en-US"}, "claim": "locale"},
		{"key": "mobile", "type": "string", "claim": "phone_number", "encrypted": true},
		{"key": "mobile_ok", "type": "boolean", "claim": "phone_number_verified"},
		{"key": "zip", "type": "string", "claim": "address.postal_code"},
		{"key": "city", "type": "string", "claim": "address.locality"},
		{"key": "department", "type": "string", "in_token": true},
	} {
		if code, out := define(body); code != 201 || out["claim"] != body["claim"] {
			t.Fatalf("define %v: %d %v", body["key"], code, out)
		}
	}
	for _, c := range []struct {
		body map[string]any
		code int
		err  string
	}{
		{map[string]any{"key": "nick", "type": "string", "claim": "name"}, 409, "claim_taken"},
		{map[string]any{"key": "mail", "type": "string", "claim": "email"}, 400, "invalid_attribute"},
		{map[string]any{"key": "age", "type": "integer", "claim": "birthdate"}, 400, "invalid_attribute"},
		{map[string]any{"key": "verified", "type": "string", "claim": "phone_number_verified"}, 400, "invalid_attribute"},
		{map[string]any{"key": "addr", "type": "string", "claim": "address"}, 400, "invalid_attribute"},
	} {
		if code, out := define(c.body); code != c.code || out["error"] != c.err {
			t.Fatalf("define %v: %d %v", c.body, code, out)
		}
	}
	// 更新でも確かめ、claim を省けば対応付けを外す。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/mobile_ok", map[string]any{"user_editable": true, "claim": "phone_number_verified"}); code != 400 ||
		out["error"] != "invalid_attribute" {
		t.Fatalf("make phone_number_verified user-editable: %d %v", code, out)
	}
	// 本人が書けた属性を後から *_verified に対応付けることもできない（既にある値は本人が書いたものかもしれない）。
	if code, out := define(map[string]any{"key": "self_ok", "type": "boolean", "user_editable": true}); code != 201 {
		t.Fatalf("define self_ok: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/self_ok", map[string]any{"claim": "phone_number_verified"}); code != 400 ||
		out["error"] != "invalid_attribute" {
		t.Fatalf("map an existing attribute to phone_number_verified: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/department", map[string]any{"in_token": true, "claim": "name"}); code != 409 ||
		out["error"] != "claim_taken" {
		t.Fatalf("update to taken claim: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/department", map[string]any{"in_token": true, "claim": "nickname"}); code != 200 ||
		out["claim"] != "nickname" {
		t.Fatalf("update claim: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/department", map[string]any{"in_token": true}); code != 200 || out["claim"] != nil {
		t.Fatalf("clear claim: %d %v", code, out)
	}

	scopes := l.discoveryScopes(t)
	for _, s := range []string{"profile", "phone", "address"} {
		if !slices.Contains(scopes, any(s)) {
			t.Fatalf("%s not advertised: %v", s, scopes)
		}
	}

	_, _ = l.login(t, "alice@example.com")
	alice := l.userID(t, "alice@example.com")
	if code, out := l.adminDo(t, "PATCH", owner, "/v1/admin/users/"+alice+"/attributes", map[string]any{"attributes": map[string]any{
		"full_name": "Alice Example", "lang": "ja-JP", "mobile": "+81-90-0000-0000", "mobile_ok": true, "zip": "100-0001", "city": "Chiyoda",
		"department": "sales"}}); code != 200 {
		t.Fatalf("set attributes: %d %v", code, out)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	// profile だけなら name と locale。phone・address・attributes のものは出ない。
	code, cookie := p.login(t, "alice@example.com", url.Values{"scope": {"openid profile"}})
	_, tok := p.exchange(t, code, nil)
	id := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	if id["name"] != "Alice Example" || id["locale"] != "ja-JP" || id["phone_number"] != nil || id["address"] != nil || id["attributes"] != nil {
		t.Fatalf("profile id token: %v", id)
	}
	status, info := l.userinfo(t, tok["access_token"].(string))
	if status != 200 || info["name"] != "Alice Example" || info["phone_number"] != nil {
		t.Fatalf("profile userinfo: %d %v", status, info)
	}

	// phone と address。暗号化した属性も読める。address は 1 つのオブジェクトにまとめる。
	c := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"scope": {"openid phone address"}}), nil, cookie))
	_, tok = p.exchange(t, c, nil)
	status, info = l.userinfo(t, tok["access_token"].(string))
	addr, _ := info["address"].(map[string]any)
	if status != 200 || info["phone_number"] != "+81-90-0000-0000" || info["phone_number_verified"] != true || info["name"] != nil ||
		len(addr) != 2 || addr["postal_code"] != "100-0001" || addr["locality"] != "Chiyoda" {
		t.Fatalf("phone address userinfo: %d %v", status, info)
	}

	// 無効化の片付けは、対応付けた 6 つの定義の claim を外す（属性と値は残る）。
	ctx := context.Background()
	// custom_attributes は standard_claims が有効な間は無効にできない（依存）。
	if _, err := l.a.DisableFeature(ctx, feature.CustomAttributes, false); !errors.Is(err, ErrFeatureRequired) {
		t.Fatalf("disable custom_attributes first: %v", err)
	}
	res, err := l.a.DisableFeature(ctx, feature.StandardClaims, true)
	if err != nil || !res.Done || res.Purged != 6 {
		t.Fatalf("disable: %+v %v", res, err)
	}
	err = l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ds, err := tx.Attributes().ListDefs(ctx, l.a.realm.ID)
		if err != nil || len(ds) != 8 {
			t.Fatalf("defs after disable: %+v %v", ds, err)
		}
		for _, d := range ds {
			if d.Claim != "" {
				t.Fatalf("claim left: %+v", d)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
