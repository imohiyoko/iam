package app

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
)

// 自前の API（リソースサーバー）向けのトークン（RFC 8707、ADR 0112）を HTTP で確かめる。

const ordersAPI = "https://api.example.com/orders"

// serviceAccountSecret はサービスアカウントと client_secret を作る。
func (l *loginEnv) serviceAccountSecret(t *testing.T, owner, name string) (id, secret string) {
	t.Helper()
	code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": name})
	if code != 201 {
		t.Fatalf("service account: %d %v", code, out)
	}
	id = out["id"].(string)
	code, out = l.admin(t, "/v1/admin/service-accounts/"+id+"/credentials", owner, map[string]any{"type": "client_secret"})
	if code != 201 {
		t.Fatalf("client secret: %d %v", code, out)
	}
	return id, out["secret"].(string)
}

func TestResourceIndicatorsOff(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders", "scopes": []string{}}); code != 404 ||
		out["error"] != "resource_indicators_disabled" {
		t.Fatalf("create while off: %d %v", code, out)
	}
	// 管理 API 向けのトークンを、resource を付けた要求に渡さない。
	sa, secret := l.serviceAccountSecret(t, owner, "worker")
	if code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, sa+":"+secret); code != 400 ||
		out["error"] != "invalid_target" {
		t.Fatalf("resource while off: %d %v", code, out)
	}
	// 認可要求の resource は見ない（aud は今までどおり連携先）。
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	code, _ := p.login(t, "alice@example.com", url.Values{"resource": {ordersAPI}})
	_, tok := p.exchange(t, code, nil)
	if in := p.introspect(t, tok["access_token"].(string)); !reflect.DeepEqual(in["aud"], []any{p.clientID}) {
		t.Fatalf("aud while off: %v", in)
	}
}

func TestResourceIndicators(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	other := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	sa, secret := l.serviceAccountSecret(t, owner, "worker")
	sa2, secret2 := l.serviceAccountSecret(t, owner, "other")

	// 登録の確かめ。
	for name, body := range map[string]map[string]any{
		"fragment":        {"uri": ordersAPI + "#x", "name": "O", "scopes": []string{}},
		"query":           {"uri": ordersAPI + "?x=1", "name": "O", "scopes": []string{}},
		"not https":       {"uri": "ftp://api.example.com/", "name": "O", "scopes": []string{}},
		"relative":        {"uri": "/orders", "name": "O", "scopes": []string{}},
		"oidc scope":      {"uri": ordersAPI, "name": "O", "scopes": []string{"email"}},
		"bad scope":       {"uri": ordersAPI, "name": "O", "scopes": []string{"a b"}},
		"unknown client":  {"uri": ordersAPI, "name": "O", "scopes": []string{}, "clients": []string{"cli_00000000000000000000000000"}},
		"unknown account": {"uri": ordersAPI, "name": "O", "scopes": []string{}, "service_accounts": []string{"sva_00000000000000000000000000"}},
		"blank name":      {"uri": ordersAPI, "name": " ", "scopes": []string{}},
	} {
		if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, body); code != 400 || out["error"] != "invalid_resource" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	if code, _ := l.adminDo(t, "GET", support, "/v1/admin/oauth/resources", nil); code != 403 {
		t.Fatalf("support lists: %d", code)
	}
	code, res := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"orders:write", "orders:read"}, "clients": []string{p.clientID}, "service_accounts": []string{sa}})
	if code != 201 || !reflect.DeepEqual(res["scopes"], []any{"orders:read", "orders:write"}) {
		t.Fatalf("create: %d %v", code, res)
	}
	rid := res["id"].(string)
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Dup", "scopes": []string{}}); code != 409 ||
		out["error"] != "resource_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/oauth/resources", nil); code != 200 || len(out["resources"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}

	// 認可コードフロー：aud はリソース、スコープはリソースのものも選べる（知らないものは落とす）。
	code2, cookie := p.login(t, "alice@example.com", url.Values{"resource": {ordersAPI}, "scope": {"openid orders:read bogus"}})
	st, tok := p.exchange(t, code2, url.Values{"resource": {ordersAPI}})
	if st != 200 || tok["scope"] != "openid orders:read" {
		t.Fatalf("token: %d %v", st, tok)
	}
	at := tok["access_token"].(string)
	in := p.introspect(t, at)
	if in["active"] != true || !reflect.DeepEqual(in["aud"], []any{ordersAPI}) || in["scope"] != "openid orders:read" {
		t.Fatalf("introspect: %v", in)
	}
	if c := l.idClaims(t, tok["id_token"].(string), "ES256"); c["aud"] != p.clientID {
		t.Fatalf("id token aud: %v", c["aud"])
	}
	// IAM 自身の UserInfo では使えない。
	if status, _ := l.userinfo(t, at); status != 401 {
		t.Fatalf("userinfo with a resource token: %d", status)
	}
	// リフレッシュ：同じ resource は受け、別の resource は invalid_target（リフレッシュトークンは使わない）。
	rt := tok["refresh_token"].(string)
	if status, out := p.post(t, oidcToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"https://other.example.com/"}}); status != 400 ||
		out["error"] != "invalid_target" {
		t.Fatalf("refresh other resource: %d %v", status, out)
	}
	status, out := p.post(t, oidcToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {ordersAPI}})
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, out)
	}
	rt = out["refresh_token"].(string)
	// token エンドポイントで別の resource に替えられない。
	c3 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"resource": {ordersAPI}}), nil, cookie))
	if status, out := p.exchange(t, c3, url.Values{"resource": {"https://other.example.com/"}}); status != 400 || out["error"] != "invalid_target" {
		t.Fatalf("exchange other resource: %d %v", status, out)
	}
	c4 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	if status, out := p.exchange(t, c4, url.Values{"resource": {ordersAPI}}); status != 400 || out["error"] != "invalid_target" {
		t.Fatalf("resource only at the token endpoint: %d %v", status, out)
	}
	// 許していない連携先・知らないリソース・2 つ以上は、戻り先に invalid_target を返す。
	for name, c := range map[string]struct {
		p     *rp
		extra url.Values
	}{
		"other client": {other, url.Values{"resource": {ordersAPI}}},
		"unknown":      {p, url.Values{"resource": {"https://unknown.example.com/"}}},
		"two":          {p, url.Values{"resource": {ordersAPI, ordersAPI}}},
	} {
		u := location(t, l.oidcDo(t, "GET", c.p.authorizeURL(c.extra), nil, cookie))
		if u.Query().Get("error") != "invalid_target" || u.Query().Get("state") != c.p.state || !strings.HasPrefix(u.String(), c.p.redirect) {
			t.Fatalf("%s: %s", name, u)
		}
	}

	// client credentials：サービスアカウントのトークンを自前の API に向けて発行する。
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}, "scope": {"orders:read"}}
	code, out = l.token(t, form, sa+":"+secret)
	if code != 200 || out["scope"] != "orders:read" {
		t.Fatalf("sa token: %d %v", code, out)
	}
	sat := out["access_token"].(string)
	if code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, sa+":"+secret); code != 200 ||
		out["scope"] != "orders:read orders:write" {
		t.Fatalf("sa token without scope: %d %v", code, out)
	}
	for name, c := range map[string]struct {
		form  url.Values
		basic string
		want  string
	}{
		"scope not on the resource": {url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}, "scope": {"orders:delete"}}, sa + ":" + secret, "invalid_scope"},
		"two resources":             {url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI, ordersAPI}}, sa + ":" + secret, "invalid_target"},
		"unknown resource":          {url.Values{"grant_type": {"client_credentials"}, "resource": {"https://unknown.example.com/"}}, sa + ":" + secret, "invalid_target"},
		"account not allowed":       {url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, sa2 + ":" + secret2, "invalid_target"},
	} {
		if code, out := l.token(t, c.form, c.basic); code != 400 || out["error"] != c.want {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// 自前の API 向けのトークンは管理 API では使えない。
	if code, _ := l.adminDo(t, "GET", sat, "/v1/admin/service-accounts/"+sa, nil); code != 401 {
		t.Fatalf("resource token on the admin API: %d", code)
	}
	// リソースサーバーはイントロスペクションで aud とスコープを確かめる。管理 API 向けのトークンは active: false。
	in = p.introspect(t, sat)
	if in["active"] != true || !reflect.DeepEqual(in["aud"], []any{ordersAPI}) || in["scope"] != "orders:read" || in["sub"] != sa ||
		in["client_id"] != sa || in["iss"] != testIssuer {
		t.Fatalf("introspect sa token: %v", in)
	}
	_, adminTok := l.token(t, url.Values{"grant_type": {"client_credentials"}}, sa+":"+secret)
	if in := p.introspect(t, adminTok["access_token"].(string)); in["active"] != false {
		t.Fatalf("introspect admin token: %v", in)
	}

	// 許可を外すと、発行済みのトークンも次の検証から使えない。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/oauth/resources/"+rid, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"orders:read"}, "clients": []string{}, "service_accounts": []string{sa}}); code != 200 {
		t.Fatalf("update: %d %v", code, out)
	}
	if in := p.introspect(t, at); in["active"] != false {
		t.Fatalf("introspect after the client was removed: %v", in)
	}
	if status, out := p.refresh(t, rt); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after the client was removed: %d %v", status, out)
	}
	if code, _ := l.admin(t, "/v1/admin/oauth/resources/"+rid+":delete", owner, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if in := p.introspect(t, sat); in["active"] != false {
		t.Fatalf("introspect after delete: %v", in)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/oauth/resources/"+rid, nil); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}

func TestDisableResourceIndicatorsWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders", "scopes": []string{"a"}}); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	disableWithData(t, l, feature.ResourceIndicators, 1)
}

// Org に属するサービスアカウントのリソース向けトークンは、イントロスペクションに Org の公開 ID を載せる（#190）。
// Org が停止されれば active: false。Org に属さなければ org_id は無い。
func TestResourceTokenOrgID(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
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
		t.Fatalf("org service account: %d %v", code, out)
	}
	orgSA := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/service-accounts/"+orgSA+"/credentials", owner, map[string]any{"type": "client_secret"})
	if code != 201 {
		t.Fatalf("client secret: %d %v", code, out)
	}
	orgSecret := out["secret"].(string)
	realmSA, realmSecret := l.serviceAccountSecret(t, owner, "worker")
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"orders:read"}, "service_accounts": []string{orgSA, realmSA}}); code != 201 {
		t.Fatalf("resource: %d %v", code, out)
	}
	issue := func(basic string) string {
		t.Helper()
		code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}, "resource": {ordersAPI}}, basic)
		if code != 200 {
			t.Fatalf("sa token: %d %v", code, out)
		}
		return out["access_token"].(string)
	}
	orgTok, realmTok := issue(orgSA+":"+orgSecret), issue(realmSA+":"+realmSecret)
	if in := p.introspect(t, orgTok); in["active"] != true || in["org_id"] != acme || in["sub"] != orgSA {
		t.Fatalf("introspect org sa token: %v", in)
	}
	if in := p.introspect(t, realmTok); in["active"] != true || in["org_id"] != nil {
		t.Fatalf("introspect realm sa token: %v", in)
	}
	if code, out := l.admin(t, "/v1/admin/orgs/"+acme+"/suspensions", owner, map[string]any{"category": "billing", "reason": "unpaid"}); code != 201 {
		t.Fatalf("suspend org: %d %v", code, out)
	}
	if in := p.introspect(t, orgTok); in["active"] != false || len(in) != 1 {
		t.Fatalf("introspect after the org was suspended: %v", in)
	}
}
