package app

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Token Exchange（RFC 8693）の委任となりすまし（ADR 0099）を HTTP で確かめる。

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	typeAccessToken    = "urn:ietf:params:oauth:token-type:access_token"
	typeIDToken        = "urn:ietf:params:oauth:token-type:id_token"
)

// exchangeEnv は既定のフィーチャーに extra を足した構成。edit で設定を変える。
func exchangeEnv(t *testing.T, edit func(*config.Config), extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

// tokenExchange は連携先 p として交換を求める。
func (p *rp) tokenExchange(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	f := url.Values{"grant_type": {grantTokenExchange}}
	for k, v := range form {
		f[k] = v
	}
	return p.post(t, oidcToken, f)
}

// delegate は subject のアクセストークンを aud 向けに交換し、アクセストークンを返す。
func (p *rp) delegate(t *testing.T, subject string, aud ...string) string {
	t.Helper()
	status, out := p.tokenExchange(t, url.Values{"subject_token": {subject}, "subject_token_type": {typeAccessToken}, "audience": aud})
	if status != 200 || out["issued_token_type"] != typeAccessToken || out["token_type"] != "Bearer" {
		t.Fatalf("exchange: %d %v", status, out)
	}
	return out["access_token"].(string)
}

func (l *loginEnv) setExchange(t *testing.T, owner, clientID string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+clientID+"/token-exchange", body)
}

func TestTokenExchangeDelegation(t *testing.T) {
	l := exchangeEnv(t, nil, feature.TokenExchange)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	web := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	api := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://api.example.com/cb"}})
	down := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	pub := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})

	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	if gt, _ := disc["grant_types_supported"].([]any); !slices.Contains(gt, any(grantTokenExchange)) {
		t.Fatalf("grant types: %v", gt)
	}

	code, _ := web.login(t, "alice@example.com", nil)
	_, tok := web.exchange(t, code, nil)
	at := tok["access_token"].(string)

	// 既定は何も許さない。
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+api.clientID+"/token-exchange", nil); code != 200 ||
		len(out["audiences"].([]any)) != 0 || out["impersonation"] != nil {
		t.Fatalf("default policy: %d %v", code, out)
	}
	if status, out := api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}); status != 400 ||
		out["error"] != "unauthorized_client" {
		t.Fatalf("not allowed: %d %v", status, out)
	}

	// 許可の検査：知らない連携先、URI でない aud、公開クライアント、フィーチャーの無いなりすまし、aud の無い許可。
	for name, c := range map[string]struct {
		client string
		body   map[string]any
	}{
		"unknown subject client": {api.clientID, map[string]any{"audiences": []string{down.clientID}, "subject_clients": []string{"cli_unknown"}}},
		"bad audience":           {api.clientID, map[string]any{"audiences": []string{"not a uri"}}},
		"public client":          {pub.clientID, map[string]any{"audiences": []string{down.clientID}}},
		"impersonation off":      {api.clientID, map[string]any{"audiences": []string{down.clientID}, "impersonation": true}},
		"no audience":            {api.clientID, map[string]any{"audiences": []string{}, "subject_clients": []string{web.clientID}}},
	} {
		if code, out := l.setExchange(t, owner, c.client, c.body); code != 400 || out["error"] != "invalid_client_metadata" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if code, out := l.setExchange(t, owner, "cli_missing", map[string]any{"audiences": []string{down.clientID}}); code != 404 {
		t.Fatalf("missing client: %d %v", code, out)
	}
	if code, out := l.setExchange(t, owner, api.clientID, map[string]any{"audiences": []string{down.clientID, "https://down.example.com/v1"},
		"subject_clients": []string{web.clientID}}); code != 200 || len(out["audiences"].([]any)) != 2 {
		t.Fatalf("set policy: %d %v", code, out)
	}
	// 連携先の内容の置き換えでは、交換の許可は変わらない。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+api.clientID, map[string]any{"name": "API", "redirect_uris": []string{"https://api.example.com/cb"},
		"token_endpoint_auth_method": "client_secret"}); code != 200 {
		t.Fatalf("update client: %d %v", code, out)
	}

	// 委任：web のトークンを、api が down 向けに交換する。
	status, out := api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID},
		"scope": {"openid"}})
	if status != 200 || out["scope"] != "openid" || out["refresh_token"] != nil || out["id_token"] != nil || out["expires_in"].(float64) > 600 {
		t.Fatalf("delegate: %d %v", status, out)
	}
	x := out["access_token"].(string)
	alice := l.userID(t, "alice@example.com")
	in := down.introspect(t, x)
	act, _ := in["act"].(map[string]any)
	if in["active"] != true || in["sub"] != alice || in["client_id"] != api.clientID || in["scope"] != "openid" || act["sub"] != api.clientID ||
		in["sid"] == nil || in["impersonation"] != nil {
		t.Fatalf("introspect exchanged: %v", in)
	}
	if aud, _ := in["aud"].([]any); len(aud) != 1 || aud[0] != down.clientID {
		t.Fatalf("aud: %v", in["aud"])
	}
	// 交換したトークンでも UserInfo は縮めたスコープで答える（email を返さない）。
	if status, ui := l.userinfo(t, x); status != 200 || ui["sub"] != alice || ui["email"] != nil {
		t.Fatalf("userinfo: %d %v", status, ui)
	}

	// 許していない aud、範囲を超えるスコープ、URI でない resource、subject_token の誤り。
	for name, c := range map[string]struct {
		form url.Values
		want string
	}{
		"audience":    {url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {web.clientID}}, "invalid_target"},
		"no audience": {url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}}, "invalid_target"},
		"resource":    {url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "resource": {"urn:x"}}, "invalid_target"},
		"scope":       {url.Values{"subject_token": {x}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}, "scope": {"email"}}, "invalid_grant"},
		"wider scope": {url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}, "scope": {"openid attributes"}}, "invalid_scope"},
		"bad token":   {url.Values{"subject_token": {"atk_x.y"}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}, "invalid_grant"},
		"refresh":     {url.Values{"subject_token": {tok["refresh_token"].(string)}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}, "invalid_grant"},
		"token type":  {url.Values{"subject_token": {at}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}, "audience": {down.clientID}}, "invalid_request"},
		"requested":   {url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}, "requested_token_type": {typeIDToken}}, "invalid_request"},
	} {
		if status, out := api.tokenExchange(t, c.form); status != 400 || out["error"] != c.want {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	// resource（RFC 8707）も aud になる。
	status, out = api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "resource": {"https://down.example.com/v1"}})
	if status != 200 {
		t.Fatalf("resource: %d %v", status, out)
	}
	if in := down.introspect(t, out["access_token"].(string)); in["active"] != true || in["aud"].([]any)[0] != "https://down.example.com/v1" {
		t.Fatalf("resource introspect: %v", in)
	}

	// 交換を許していない連携先（web）は交換できない。
	if status, out := web.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}); status != 400 ||
		out["error"] != "unauthorized_client" {
		t.Fatalf("web: %d %v", status, out)
	}

	// 交換を重ねる：down が受け取ったトークン（aud に down）を、さらに下流向けに交換する。act は入れ子になる。
	if code, out := l.setExchange(t, owner, down.clientID, map[string]any{"audiences": []string{"https://final.example.com/", down.clientID}}); code != 200 {
		t.Fatalf("down policy: %d %v", code, out)
	}
	y := down.delegate(t, x, "https://final.example.com/")
	in = down.introspect(t, y)
	act, _ = in["act"].(map[string]any)
	if inner, _ := act["act"].(map[string]any); in["active"] != true || act["sub"] != down.clientID || inner["sub"] != api.clientID {
		t.Fatalf("chained: %v", in)
	}

	// 重ねられるのは MaxExchangeDepth 回まで。
	z := x
	for i := 2; i <= provider.MaxExchangeDepth; i++ {
		z = down.delegate(t, z, down.clientID)
	}
	if status, out := down.tokenExchange(t, url.Values{"subject_token": {z}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}); status != 400 ||
		out["error"] != "invalid_grant" {
		t.Fatalf("too deep: %d %v", status, out)
	}

	// ID トークンも subject_token にできる。
	status, out = api.tokenExchange(t, url.Values{"subject_token": {tok["id_token"].(string)}, "subject_token_type": {typeIDToken}, "audience": {down.clientID}})
	if status != 200 || out["scope"] != "openid" {
		t.Fatalf("id token: %d %v", status, out)
	}
	if in := down.introspect(t, out["access_token"].(string)); in["active"] != true || in["sub"] != alice {
		t.Fatalf("id token introspect: %v", in)
	}

	// actor_token：api にログインした bob が行為者。
	code, _ = api.login(t, "bob@example.com", nil)
	_, btok := api.exchange(t, code, nil)
	status, out = api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID},
		"actor_token": {btok["access_token"].(string)}, "actor_token_type": {typeAccessToken}})
	if status != 200 {
		t.Fatalf("actor token: %d %v", status, out)
	}
	act, _ = down.introspect(t, out["access_token"].(string))["act"].(map[string]any)
	if act["sub"] != l.userID(t, "bob@example.com") || act["client_id"] != api.clientID {
		t.Fatalf("actor act: %v", act)
	}
	// 別の連携先に発行した actor_token は使えない。
	if status, out := api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID},
		"actor_token": {at}, "actor_token_type": {typeAccessToken}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("foreign actor token: %d %v", status, out)
	}

	// 元のトークンの失効（RFC 7009）は、交換したトークンにも、それを交換したトークンにも効く。
	if status, _ := web.post(t, oidcRevoke, url.Values{"token": {at}}); status != 200 {
		t.Fatalf("revoke: %d", status)
	}
	for _, tk := range []string{x, y} {
		if in := down.introspect(t, tk); in["active"] != false {
			t.Fatalf("after revoking the original: %v", in)
		}
	}
	if status, out := api.tokenExchange(t, url.Values{"subject_token": {at}, "subject_token_type": {typeAccessToken}, "audience": {down.clientID}}); status != 400 ||
		out["error"] != "invalid_grant" {
		t.Fatalf("exchange revoked: %d %v", status, out)
	}

	// ログインの系列が終われば（ログアウト）、交換したトークンも使えない。Logout Token は交換した連携先には送らない。
	_, cookie := l.login(t, "alice@example.com")
	code = web.code(t, l.oidcDo(t, "GET", web.authorizeURL(nil), nil, cookie))
	_, tok = web.exchange(t, code, nil)
	x = api.delegate(t, tok["access_token"].(string), down.clientID)
	if in := down.introspect(t, x); in["active"] != true {
		t.Fatalf("before logout: %v", in)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/logout", nil, "Cookie", sessionCookie+"="+cookie); w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	if in := down.introspect(t, x); in["active"] != false {
		t.Fatalf("after logout: %v", in)
	}

	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	if types["oidc.token_exchanged"] != 6+provider.MaxExchangeDepth-1 || types["client.token_exchange_updated"] != 2 {
		t.Fatalf("audit: %v", types)
	}
	if strings.Contains(l.out.String(), l.internalUserID(t, alice)) {
		t.Fatal("internal user id leaked")
	}
}

// supportEnv はなりすましの構成：運営者がサポートの道具（support）にログインし、down 向けになりすます。
type supportEnv struct {
	l             *loginEnv
	owner         string
	support, down *rp
}

func newSupportEnv(t *testing.T, edit func(*config.Config)) supportEnv {
	t.Helper()
	l := exchangeEnv(t, edit, feature.TokenExchange, feature.Impersonation)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	support := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	down := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if code, out := l.setExchange(t, owner, support.clientID, map[string]any{"audiences": []string{down.clientID}, "impersonation": true}); code != 200 ||
		out["impersonation"] != true {
		t.Fatalf("support policy: %d %v", code, out)
	}
	return supportEnv{l: l, owner: owner, support: support, down: down}
}

// operatorToken は email の運営者が support にログインして得たアクセストークンと、セッションの Cookie を返す。
func (s supportEnv) operatorToken(t *testing.T, email string) (string, string) {
	t.Helper()
	code, cookie := s.support.login(t, email, nil)
	_, tok := s.support.exchange(t, code, nil)
	return tok["access_token"].(string), cookie
}

func (s supportEnv) impersonate(t *testing.T, subject, userID string) (int, map[string]any) {
	t.Helper()
	return s.support.tokenExchange(t, url.Values{"subject_token": {subject}, "subject_token_type": {typeAccessToken}, "audience": {s.down.clientID},
		"requested_subject": {userID}})
}

func TestImpersonation(t *testing.T) {
	s := newSupportEnv(t, func(c *config.Config) { c.OIDC.Impersonation.MinFactors = 0 })
	l := s.l
	_, _ = l.login(t, "alice@example.com")
	alice := l.userID(t, "alice@example.com")
	opID, _ := l.operator(t, "ops@example.com", role.RealmOwner)
	opToken, opCookie := s.operatorToken(t, "ops@example.com")
	before := l.notes.count()

	status, out := s.impersonate(t, opToken, alice)
	if status != 200 || out["expires_in"].(float64) > 600 {
		t.Fatalf("impersonate: %d %v", status, out)
	}
	imp := out["access_token"].(string)
	in := s.down.introspect(t, imp)
	act, _ := in["act"].(map[string]any)
	if in["active"] != true || in["sub"] != alice || in["impersonation"] != true || act["sub"] != opID || in["sid"] != nil ||
		in["client_id"] != s.support.clientID {
		t.Fatalf("introspect impersonation: %v", in)
	}
	// 本人に知らせる。
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := l.notes.last(t); l.notes.count() <= before || n.Type != "impersonated" || n.UserID != alice {
		t.Fatalf("notification: %+v", n)
	}
	// なりすましのトークンは、さらに交換できない。
	if code, out := l.setExchange(t, s.owner, s.down.clientID, map[string]any{"audiences": []string{"https://final.example.com/"}}); code != 200 {
		t.Fatalf("down policy: %d %v", code, out)
	}
	if status, out := s.down.tokenExchange(t, url.Values{"subject_token": {imp}, "subject_token_type": {typeAccessToken},
		"audience": {"https://final.example.com/"}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("exchange impersonation: %d %v", status, out)
	}

	// 拒む場合：知らない本人、自分自身、権限の無い運営者、actor_token との併用。理由は返さない。
	for name, uid := range map[string]string{"unknown": "usr_00000000000000000000000000", "self": opID} {
		if status, out := s.impersonate(t, opToken, uid); status != 400 || out["error"] != "invalid_grant" || out["error_description"] != nil {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	_, _ = l.operator(t, "help@example.com", role.RealmSupport)
	helpToken, _ := s.operatorToken(t, "help@example.com")
	if status, out := s.impersonate(t, helpToken, alice); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("support role: %d %v", status, out)
	}
	if status, out := s.support.tokenExchange(t, url.Values{"subject_token": {opToken}, "subject_token_type": {typeAccessToken}, "audience": {s.down.clientID},
		"requested_subject": {alice}, "actor_token": {opToken}, "actor_token_type": {typeAccessToken}}); status != 400 || out["error"] != "invalid_request" {
		t.Fatalf("with actor token: %d %v", status, out)
	}
	// 交換を許していても、なりすましを許していない連携先は使えない。
	if code, out := l.setExchange(t, s.owner, s.down.clientID, map[string]any{"audiences": []string{s.down.clientID}}); code != 200 {
		t.Fatalf("down policy: %d %v", code, out)
	}
	if status, out := s.down.tokenExchange(t, url.Values{"subject_token": {opToken}, "subject_token_type": {typeAccessToken}, "audience": {s.down.clientID},
		"requested_subject": {alice}}); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("not allowed client: %d %v", status, out)
	}

	// outranks：users:impersonate だけを持つ運営者は、上位のロール（realm:support）の本人にはなりすませない。
	code, out := l.adminDo(t, "POST", s.owner, "/v1/admin/roles", map[string]any{"name": "impersonator", "permissions": []string{role.PermUsersImpersonate}})
	if code != 201 {
		t.Fatalf("role: %d %v", code, out)
	}
	impersonator := out["id"].(string)
	l.login(t, "agent@example.com")
	if code, out := l.adminDo(t, "POST", s.owner, "/v1/admin/role-bindings", map[string]any{"role": impersonator, "principal_type": "user",
		"principal_id": l.userID(t, "agent@example.com")}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	agentToken, _ := s.operatorToken(t, "agent@example.com")
	if status, out := s.impersonate(t, agentToken, l.userID(t, "help@example.com")); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("outranked: %d %v", status, out)
	}
	if status, out := s.impersonate(t, agentToken, alice); status != 200 {
		t.Fatalf("agent impersonates alice: %d %v", status, out)
	}

	// step-up：運営者の直近の認証から max_auth_age（既定 5 分）を過ぎたら、再認証を促す。
	l.advance(6 * time.Minute)
	if status, out := s.impersonate(t, opToken, alice); status != 400 || out["error"] != "invalid_grant" ||
		out["error_description"] != "step-up authentication required" {
		t.Fatalf("step-up: %d %v", status, out)
	}
	// なりすましの寿命は短い（元のアクセストークンの期限を超えない）。
	if in := s.down.introspect(t, imp); in["active"] != true {
		t.Fatalf("still active: %v", in)
	}
	l.advance(5 * time.Minute)
	if in := s.down.introspect(t, imp); in["active"] != false {
		t.Fatalf("after ttl: %v", in)
	}

	// 運営者のログアウトで、なりすましのトークンも使えなくなる。本人の停止でも同じ。
	opToken, opCookie = s.operatorToken(t, "ops@example.com")
	_, res2 := s.impersonate(t, opToken, alice)
	imp2, _ := res2["access_token"].(string)
	_, res3 := s.impersonate(t, opToken, alice)
	imp3, _ := res3["access_token"].(string)
	if status, out := l.admin(t, "/v1/admin/users/"+alice+"/suspensions", s.owner, map[string]any{"category": "tos_violation", "reason": "x"}); status != 201 {
		t.Fatalf("suspend: %d %v", status, out)
	}
	if in := s.down.introspect(t, imp2); in["active"] != false {
		t.Fatalf("after suspension: %v", in)
	}
	if status, out := s.impersonate(t, opToken, alice); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("suspended subject: %d %v", status, out)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/logout", nil, "Cookie", sessionCookie+"="+opCookie); w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	if in := s.down.introspect(t, imp3); in["active"] != false {
		t.Fatalf("after operator logout: %v", in)
	}

	var ok, denied int
	reasons := map[string]bool{}
	for _, e := range l.auditTypes(t) {
		if e.Type != "oidc.impersonated" {
			continue
		}
		if e.Result == "success" {
			ok++
			continue
		}
		denied++
		reasons[e.Details["reason"].(string)] = true
	}
	if ok != 4 || !reasons["subject_unavailable"] || !reasons["permission_denied"] || !reasons["outranked"] || !reasons["step_up_required"] {
		t.Fatalf("audit: ok=%d denied=%d %v", ok, denied, reasons)
	}
}

// TestImpersonationRequiresFactors は、既定（min_factors 2）では 1 要素の運営者がなりすませないことを確かめる。
func TestImpersonationRequiresFactors(t *testing.T) {
	s := newSupportEnv(t, nil)
	_, _ = s.l.login(t, "alice@example.com")
	_, _ = s.l.operator(t, "ops@example.com", role.RealmOwner)
	opToken, _ := s.operatorToken(t, "ops@example.com")
	if status, out := s.impersonate(t, opToken, s.l.userID(t, "alice@example.com")); status != 400 || out["error_description"] != "step-up authentication required" {
		t.Fatalf("single factor: %d %v", status, out)
	}
}

// TestTokenExchangeOff は、フィーチャーが動いていなければ今までと同じ（grant_type を受け付けない、管理 API は 404）ことを確かめる。
func TestTokenExchangeOff(t *testing.T) {
	l := exchangeEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	api := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if strings.Contains(w.Body.String(), grantTokenExchange) {
		t.Fatalf("discovery: %s", w.Body)
	}
	code, _ := api.login(t, "alice@example.com", nil)
	_, tok := api.exchange(t, code, nil)
	if status, out := api.tokenExchange(t, url.Values{"subject_token": {tok["access_token"].(string)}, "subject_token_type": {typeAccessToken},
		"audience": {api.clientID}}); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("exchange: %d %v", status, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+api.clientID+"/token-exchange", nil); code != 404 || out["error"] != "token_exchange_disabled" {
		t.Fatalf("admin: %d %v", code, out)
	}
	if code, out := l.setExchange(t, owner, api.clientID, map[string]any{"audiences": []string{api.clientID}}); code != 404 {
		t.Fatalf("admin put: %d %v", code, out)
	}
}

// TestDisableTokenExchangeWithData は、連携先の許可と交換の認可が残る間は無効化が終わらず、片付ければ終わることを確かめる。
// 片付けの後に残った交換のトークンは使えない（fail-closed）。
func TestDisableTokenExchangeWithData(t *testing.T) {
	s := newSupportEnv(t, func(c *config.Config) { c.OIDC.Impersonation.MinFactors = 0 })
	l := s.l
	_, _ = l.login(t, "alice@example.com")
	_, _ = l.operator(t, "ops@example.com", role.RealmOwner)
	opToken, _ := s.operatorToken(t, "ops@example.com")
	status, out := s.impersonate(t, opToken, l.userID(t, "alice@example.com"))
	if status != 200 {
		t.Fatalf("impersonate: %d %v", status, out)
	}
	imp := out["access_token"].(string)
	// なりすまし：support の許可（impersonation）と、なりすましの認可が 1 件。
	disableWithData(t, l, feature.Impersonation, 2)
	if in := s.down.introspect(t, imp); in["active"] != false {
		t.Fatalf("impersonation token after disable: %v", in)
	}
	all := feature.Registered()
	rest := names(without(all, feature.Impersonation))
	if _, err := l.restart(t, rest, without(all, feature.Impersonation)); err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Clients().GetByPublicID(ctx, l.a.realm.ID, s.support.clientID)
		if err == nil {
			err = json.Unmarshal(c.TokenExchange, &p)
		}
		return err
	})
	if err != nil || p["impersonation"] != nil || p["audiences"] == nil {
		t.Fatalf("policy after impersonation purge: %v %v", p, err)
	}
	ctx := context.Background()
	res, err := l.a.DisableFeature(ctx, feature.TokenExchange, false)
	if err != nil || res.Done || res.Remaining != 1 {
		t.Fatalf("disable token_exchange: %+v %v", res, err)
	}
	if res, err := l.a.DisableFeature(ctx, feature.TokenExchange, true); err != nil || !res.Done || res.Purged != 1 {
		t.Fatalf("purge token_exchange: %+v %v", res, err)
	}
}
