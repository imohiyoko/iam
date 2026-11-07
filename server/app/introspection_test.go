package app

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
)

// TestIntrospectionCallers は、リソースの introspection_clients に載せた連携先だけが、そのリソースに向けたトークンを
// イントロスペクションできること（空なら今までどおり。ADR 0120）。
func TestIntrospectionCallers(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	rs := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	other := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	sa, secret := l.serviceAccountSecret(t, owner, "worker")

	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders", "scopes": []string{"app.orders:read"},
		"introspection_clients": []string{"cli_00000000000000000000000000"}}); code != 400 || out["error"] != "invalid_resource" {
		t.Fatalf("unknown introspection client: %d %v", code, out)
	}
	body := map[string]any{"uri": ordersAPI, "name": "Orders", "scopes": []string{"app.orders:read"}, "clients": []string{p.clientID},
		"service_accounts": []string{sa}, "introspection_clients": []string{rs.clientID, rs.clientID}}
	code, res := l.admin(t, "/v1/admin/oauth/resources", owner, body)
	if code != 201 || !reflect.DeepEqual(res["introspection_clients"], []any{rs.clientID}) {
		t.Fatalf("create: %d %v", code, res)
	}
	rid := res["id"].(string)

	c, _ := p.login(t, "alice@example.com", url.Values{"resource": {ordersAPI}, "scope": {"openid orders:read"}})
	st, tok := p.exchange(t, c, url.Values{"resource": {ordersAPI}})
	if st != 200 {
		t.Fatalf("token: %d %v", st, tok)
	}
	at := tok["access_token"].(string)
	code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, sa+":"+secret)
	if code != 200 {
		t.Fatalf("sa token: %d %v", code, out)
	}
	sat := out["access_token"].(string)
	// 連携先自身の、リソースに向けないトークンには効かない。
	c2, _ := p.login(t, "bob@example.com", nil)
	_, plain := p.exchange(t, c2, nil)

	for name, tc := range map[string]struct {
		caller *rp
		token  string
		active bool
	}{
		"listed caller, user token":  {rs, at, true},
		"listed caller, sa token":    {rs, sat, true},
		"other caller, user token":   {other, at, false},
		"other caller, sa token":     {other, sat, false},
		"issuing client, user token": {p, at, false},
		"other caller, client token": {other, plain["access_token"].(string), true},
	} {
		in := tc.caller.introspect(t, tc.token)
		if in["active"] != tc.active || (!tc.active && len(in) != 1) {
			t.Fatalf("%s: %v", name, in)
		}
	}

	// 主体の種類と認証の方式（ADR 0120）。
	if in := rs.introspect(t, at); in["principal_type"] != "user" {
		t.Fatalf("user principal_type: %v", in)
	}
	if in := rs.introspect(t, sat); in["principal_type"] != "service_account" || !reflect.DeepEqual(in["amr"], []any{"client_secret"}) ||
		in["auth_time"] == nil {
		t.Fatalf("sa principal_type: %v", in)
	}

	// 一覧を空にすれば、今までどおりどの連携先でもよい。変更は発行済みのトークンにも効く。
	body["introspection_clients"] = []string{}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/oauth/resources/"+rid, body); code != 200 ||
		!reflect.DeepEqual(out["introspection_clients"], []any{}) {
		t.Fatalf("update: %d %v", code, out)
	}
	if in := other.introspect(t, sat); in["active"] != true {
		t.Fatalf("after clearing: %v", in)
	}
}

// TestAPIKeyIntrospection は、フィーチャー api_key_introspection が動いているときだけ API キーをイントロスペクションで
// 確かめられ、停止・無効化が次の要求から効くこと（ADR 0120）。
func TestAPIKeyIntrospection(t *testing.T) {
	for _, on := range []bool{false, true} {
		features := []string{feature.ServiceAccounts}
		if on {
			features = append(features, feature.APIKeyIntrospection)
		}
		l := featureEnv(t, nil, features...)
		_, owner := l.operator(t, "root@example.com", role.RealmOwner)
		rs := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
		code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "ci"})
		if code != 201 {
			t.Fatalf("service account: %d %v", code, out)
		}
		sa := out["id"].(string)
		base := "/v1/admin/service-accounts/" + sa
		code, out = l.admin(t, base+"/credentials", owner, map[string]any{"type": "api_key"})
		if code != 201 {
			t.Fatalf("api key: %d %v", code, out)
		}
		key, cred := out["secret"].(string), out["id"].(string)

		in := rs.introspect(t, key)
		if !on {
			if in["active"] != false || len(in) != 1 {
				t.Fatalf("feature off: %v", in)
			}
			continue
		}
		if in["active"] != true || in["sub"] != sa || in["principal_type"] != "service_account" || in["token_type"] != "api_key" ||
			!reflect.DeepEqual(in["amr"], []any{"sak"}) || in["iss"] != testIssuer || in["aud"] != nil || in["scope"] != nil ||
			in["client_id"] != nil || in["auth_time"] == nil {
			t.Fatalf("api key: %v", in)
		}
		if in := rs.introspect(t, key+"x"); in["active"] != false {
			t.Fatalf("wrong secret: %v", in)
		}
		// 停止は次の要求から効き、解けば戻る。
		code, out = l.admin(t, base+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "leak"})
		if code != 201 {
			t.Fatalf("suspend: %d %v", code, out)
		}
		if in := rs.introspect(t, key); in["active"] != false {
			t.Fatalf("suspended: %v", in)
		}
		if code, out := l.admin(t, "/v1/admin/suspensions/"+out["id"].(string)+":lift", owner, map[string]any{"reason": "rotated"}); code != 200 {
			t.Fatalf("lift: %d %v", code, out)
		}
		if in := rs.introspect(t, key); in["active"] != true {
			t.Fatalf("lifted: %v", in)
		}
		if code, out := l.admin(t, base+"/credentials/"+cred+":revoke", owner, nil); code != 200 {
			t.Fatalf("revoke: %d %v", code, out)
		}
		if in := rs.introspect(t, key); in["active"] != false {
			t.Fatalf("revoked: %v", in)
		}
	}
}
