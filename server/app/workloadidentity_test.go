package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Workload Identity Federation（ADR 0116）。

const wifIssuer = "https://token.actions.githubusercontent.example"

type wifPlatform struct {
	key *ecdsa.PrivateKey
	n   int
}

func newWIFPlatform(t *testing.T) *wifPlatform {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &wifPlatform{key: k}
}

func (p *wifPlatform) jwks(t *testing.T) map[string]any {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "gh1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// token は基盤が渡す JWT（GitHub Actions に似たクレーム）。
func (p *wifPlatform) token(t *testing.T, now time.Time, edit func(map[string]any)) string {
	t.Helper()
	p.n++
	c := map[string]any{"iss": wifIssuer, "aud": "https://iam.example", "sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app",
		"ref": "refs/heads/main", "jti": fmt.Sprintf("jti-%d", p.n), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	if edit != nil {
		edit(c)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "gh1"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(s).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wifForm(tok string) url.Values {
	return url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {tok},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}}
}

func TestWorkloadIdentityExchange(t *testing.T) {
	l := senderEnv(t, nil, feature.ServiceAccounts, feature.WorkloadIdentity, feature.DPoP)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	plat := newWIFPlatform(t)

	// 管理 API：発行者。
	if code, _ := l.admin(t, "/v1/admin/workload-identity/providers", support, map[string]any{"name": "x"}); code != 403 {
		t.Fatalf("support creates: %d", code)
	}
	for name, body := range map[string]map[string]any{
		"http issuer": {"name": "gh", "issuer": "http://x.example", "audiences": []string{"a"}},
		"no audience": {"name": "gh", "issuer": wifIssuer, "audiences": []string{}},
		"hs256":       {"name": "gh", "issuer": wifIssuer, "audiences": []string{"a"}, "algorithms": []string{"HS256"}},
	} {
		if code, out := l.admin(t, "/v1/admin/workload-identity/providers", owner, body); code != 400 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	code, out := l.admin(t, "/v1/admin/workload-identity/providers", owner, map[string]any{"name": "GitHub", "issuer": wifIssuer,
		"audiences": []string{"https://iam.example"}, "jwks": plat.jwks(t), "algorithms": []string{"ES256"}})
	if code != 201 || out["max_token_lifetime"] != float64(3600) || out["jwks"] == nil {
		t.Fatalf("create provider: %d %v", code, out)
	}
	pid := out["id"].(string)
	pbase := "/v1/admin/workload-identity/providers/" + pid
	if code, out := l.admin(t, "/v1/admin/workload-identity/providers", owner, map[string]any{"name": "dup", "issuer": wifIssuer,
		"audiences": []string{"a"}}); code != 409 || out["error"] != "issuer_exists" {
		t.Fatalf("duplicate issuer: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/workload-identity/providers", nil); code != 200 || len(out["providers"].([]any)) != 1 {
		t.Fatalf("list providers: %d %v", code, out)
	}

	// サービスアカウントと結び付け。
	code, out = l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "deploy"})
	if code != 201 {
		t.Fatalf("create sa: %d %v", code, out)
	}
	sa := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmAdmin, "principal_type": "service_account",
		"principal_id": sa}); code != 201 {
		t.Fatalf("grant: %d %v", code, out)
	}
	// 交換の前に結び付けが無ければ拒む。
	if code, out := l.token(t, wifForm(plat.token(t, l.a.deps.Clock.Now(), nil)), ""); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("no binding: %d %v", code, out)
	}
	for name, conds := range map[string]any{"empty": []any{}, "two ops": []any{map[string]any{"claim": "/sub", "equals": "a", "prefix": "a"}},
		"bad pointer": []any{map[string]any{"claim": "sub", "equals": "a"}}} {
		if code, out := l.admin(t, pbase+"/bindings", owner, map[string]any{"service_account_id": sa, "conditions": conds}); code != 400 || out["error"] != "invalid_conditions" {
			t.Fatalf("%s conditions: %d %v", name, code, out)
		}
	}
	code, out = l.admin(t, pbase+"/bindings", owner, map[string]any{"service_account_id": sa, "conditions": []any{
		map[string]any{"claim": "/repository", "equals": "acme/app"}, map[string]any{"claim": "/ref", "in": []string{"refs/heads/main"}}}})
	if code != 201 || out["service_account_id"] != sa || len(out["conditions"].([]any)) != 2 {
		t.Fatalf("create binding: %d %v", code, out)
	}
	bid := out["id"].(string)

	// 交換。
	now := l.a.deps.Clock.Now()
	code, out = l.token(t, wifForm(plat.token(t, now, nil)), "")
	if code != 200 || out["token_type"] != "Bearer" || out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("exchange: %d %v", code, out)
	}
	tok := out["access_token"].(string)
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/service-accounts/"+sa, nil); code != 200 {
		t.Fatalf("use exchanged token: %d", code)
	}
	// client_id で選んでも同じ。id_token の種類も受ける。
	f := wifForm(plat.token(t, now, nil))
	f.Set("client_id", sa)
	f.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
	if code, out := l.token(t, f, ""); code != 200 {
		t.Fatalf("exchange with client_id: %d %v", code, out)
	}

	// 拒むもの。
	replayed := plat.token(t, now, nil)
	if code, _ := l.token(t, wifForm(replayed), ""); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	bad := map[string]url.Values{
		"replay":        wifForm(replayed),
		"wrong aud":     wifForm(plat.token(t, now, func(c map[string]any) { c["aud"] = "https://other.example" })),
		"wrong issuer":  wifForm(plat.token(t, now, func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"expired":       wifForm(plat.token(t, now.Add(-time.Hour), nil)),
		"unmatched ref": wifForm(plat.token(t, now, func(c map[string]any) { c["ref"] = "refs/heads/feature" })),
		"other key":     wifForm(newWIFPlatform(t).token(t, now, nil)),
		"other sa": func() url.Values {
			f := wifForm(plat.token(t, now, nil))
			f.Set("client_id", "sva_00000000000000000000000000")
			return f
		}(),
	}
	for name, f := range bad {
		if code, out := l.token(t, f, ""); code != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	for name, f := range map[string]url.Values{
		"client secret": func() url.Values {
			f := wifForm(plat.token(t, now, nil))
			f.Set("client_secret", "x")
			return f
		}(),
		"no subject token": {"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}},
		"wrong type": func() url.Values {
			f := wifForm(plat.token(t, now, nil))
			f.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return f
		}(),
		"refresh token requested": func() url.Values {
			f := wifForm(plat.token(t, now, nil))
			f.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
			return f
		}(),
		"actor token": func() url.Values {
			f := wifForm(plat.token(t, now, nil))
			f.Set("actor_token", "x")
			return f
		}(),
	} {
		if code, out := l.token(t, f, ""); code != 400 || out["error"] != "invalid_request" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if code, out := l.token(t, wifForm(plat.token(t, now, nil)), "x:y"); code != 400 || out["error"] != "invalid_request" {
		t.Fatalf("basic auth: %d %v", code, out)
	}
	f = wifForm(plat.token(t, now, nil))
	f.Set("audience", "https://api.example")
	if code, out := l.token(t, f, ""); code != 400 || out["error"] != "invalid_target" {
		t.Fatalf("audience: %d %v", code, out)
	}

	// DPoP に結び付ける。
	k := dpoptest.NewKey(t)
	w, dtok := l.form(t, l.a.AdminHandler(), "POST", adminTokenPath, wifForm(plat.token(t, now, nil)), nil,
		"DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""))
	if w.Code != 200 || dtok["token_type"] != "DPoP" {
		t.Fatalf("dpop exchange: %d %v", w.Code, dtok)
	}
	if code, _ := l.adminDo(t, "GET", dtok["access_token"].(string), "/v1/admin/service-accounts/"+sa, nil); code != 401 {
		t.Fatalf("dpop-bound token as bearer: %d", code)
	}

	// 発行者を止めると、発行済みのトークンも使えない。戻せば使える。
	put := func(disabled bool) {
		t.Helper()
		w := l.do(t, l.a.AdminHandler(), "PUT", pbase, map[string]any{"name": "GitHub", "issuer": wifIssuer, "audiences": []string{"https://iam.example"},
			"jwks": plat.jwks(t), "algorithms": []string{"ES256"}, "disabled": disabled}, "Authorization", "Bearer "+owner)
		if w.Code != 200 {
			t.Fatalf("update provider: %d %s", w.Code, w.Body)
		}
	}
	put(true)
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/service-accounts/"+sa, nil); code != 401 {
		t.Fatalf("token of a disabled provider: %d", code)
	}
	if code, out := l.token(t, wifForm(plat.token(t, now, nil)), ""); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("exchange with a disabled provider: %d %v", code, out)
	}
	put(false)
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/service-accounts/"+sa, nil); code != 200 {
		t.Fatalf("token after re-enabling: %d", code)
	}

	// 停止したサービスアカウントには替えない（監査ログに残る）。
	if code, out := l.admin(t, "/v1/admin/service-accounts/"+sa+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "test"}); code != 201 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	if code, out := l.token(t, wifForm(plat.token(t, now, nil)), ""); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("suspended account: %d %v", code, out)
	}
	if len(l.auditOf(t, "workload_identity.exchange_denied")) == 0 || len(l.auditOf(t, "workload_identity.binding.created")) != 1 {
		t.Fatal("audit events are missing")
	}

	// 結び付けを消すと、発行済みのトークンも使えない。
	if code, out := l.admin(t, pbase+"/bindings/"+bid+":delete", owner, nil); code != 204 {
		t.Fatalf("delete binding: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, pbase+"/bindings", nil); code != 200 || len(out["bindings"].([]any)) != 0 {
		t.Fatalf("list bindings: %d %v", code, out)
	}

	// 無効化：発行者・結び付け・発行したトークンを消す。
	cl := cleaners[feature.WorkloadIdentity]
	var n int
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		if n, err = cl.Count(ctx, tx); err != nil || n < 2 {
			return fmt.Errorf("count = %d, %w", n, err)
		}
		if _, err = cl.Purge(ctx, tx, l.a.deps.Clock.Now(), 100); err != nil {
			return err
		}
		n, err = cl.Count(ctx, tx)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("cleaner: %d %v", n, err)
	}
}

// 結び付けは、呼び出し側がサービスアカウントのロールの権限をすべて持つときだけ作れる（outranks）。
func TestWorkloadIdentityBindingOutranks(t *testing.T) {
	l := senderEnv(t, nil, feature.ServiceAccounts, feature.WorkloadIdentity)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "strong"})
	if code != 201 {
		t.Fatalf("create sa: %d %v", code, out)
	}
	sa := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmOwner, "principal_type": "service_account",
		"principal_id": sa}); code != 201 {
		t.Fatalf("grant: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/workload-identity/providers", owner, map[string]any{"name": "k8s", "issuer": "https://k8s.example",
		"audiences": []string{"iam"}, "jwks": newWIFPlatform(t).jwks(t)})
	if code != 201 {
		t.Fatalf("create provider: %d %v", code, out)
	}
	body := map[string]any{"service_account_id": sa, "conditions": []any{map[string]any{"claim": "/sub", "equals": "system:serviceaccount:prod:ci"}}}
	path := "/v1/admin/workload-identity/providers/" + out["id"].(string) + "/bindings"
	if code, out := l.admin(t, path, admin, body); code != 403 {
		t.Fatalf("admin binds an owner account: %d %v", code, out)
	}
	code, out = l.admin(t, path, owner, body)
	if code != 201 {
		t.Fatalf("owner binds: %d %v", code, out)
	}
	binding := out["id"].(string)
	// 強いサービスアカウントに結び付いた発行者を、admin が自分の鍵に向け直したり消したりできない。
	provider := strings.TrimSuffix(path, "/bindings")
	attacker := map[string]any{"name": "k8s", "issuer": "https://attacker.example", "audiences": []string{"iam"}, "jwks": newWIFPlatform(t).jwks(t)}
	if code, out := l.adminDo(t, "PUT", admin, provider, attacker); code != 403 {
		t.Fatalf("admin repoints an owner-bound provider: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", admin, path+"/"+binding+":delete", nil); code != 403 {
		t.Fatalf("admin deletes an owner binding: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", admin, provider+":delete", nil); code != 403 {
		t.Fatalf("admin deletes an owner-bound provider: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, provider, attacker); code != 200 {
		t.Fatalf("owner updates: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", owner, path+"/"+binding+":delete", nil); code != 204 {
		t.Fatalf("owner deletes the binding: %d %v", code, out)
	}
	// 結び付けが無くなれば admin も更新できる。
	if code, out := l.adminDo(t, "PUT", admin, provider, attacker); code != 200 {
		t.Fatalf("admin updates an unbound provider: %d %v", code, out)
	}
}

func TestWorkloadIdentityDisabled(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/workload-identity/providers", nil); code != 404 || out["error"] != "workload_identity_disabled" {
		t.Fatalf("list while off: %d %v", code, out)
	}
	if code, out := l.token(t, wifForm(newWIFPlatform(t).token(t, l.a.deps.Clock.Now(), nil)), ""); code != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("exchange while off: %d %v", code, out)
	}
}

// 交換でも resource（RFC 8707。ADR 0112）が client credentials と同じに効く。
func TestWorkloadIdentityResource(t *testing.T) {
	l := senderEnv(t, nil, feature.ServiceAccounts, feature.WorkloadIdentity, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	plat := newWIFPlatform(t)
	code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "deploy"})
	if code != 201 {
		t.Fatalf("create sa: %d %v", code, out)
	}
	sa := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/workload-identity/providers", owner, map[string]any{"name": "GitHub", "issuer": wifIssuer,
		"audiences": []string{"https://iam.example"}, "jwks": plat.jwks(t)})
	if code != 201 {
		t.Fatalf("create provider: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/workload-identity/providers/"+out["id"].(string)+"/bindings", owner, map[string]any{"service_account_id": sa,
		"conditions": []any{map[string]any{"claim": "/repository", "equals": "acme/app"}}}); code != 201 {
		t.Fatalf("create binding: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"app.orders:read", "app.orders:write"}, "service_accounts": []string{sa}}); code != 201 {
		t.Fatalf("create resource: %d %v", code, out)
	}
	now := l.a.deps.Clock.Now()
	f := wifForm(plat.token(t, now, nil))
	f.Set("resource", ordersAPI)
	f.Set("scope", "app.orders:read")
	code, out = l.token(t, f, "")
	if code != 200 || out["scope"] != "app.orders:read" {
		t.Fatalf("exchange with resource: %d %v", code, out)
	}
	// 自前の API に向けたトークンは管理 API では使えない。
	if code, _ := l.adminDo(t, "GET", out["access_token"].(string), "/v1/admin/service-accounts/"+sa, nil); code != 401 {
		t.Fatalf("resource token on the admin API: %d", code)
	}
	f = wifForm(plat.token(t, now, nil))
	f.Set("resource", "https://other.example.com/")
	if code, out := l.token(t, f, ""); code != 400 || out["error"] != "invalid_target" {
		t.Fatalf("unknown resource: %d %v", code, out)
	}
	f = wifForm(plat.token(t, now, nil))
	f.Set("resource", ordersAPI)
	f.Set("scope", "app.orders:admin")
	if code, out := l.token(t, f, ""); code != 400 || out["error"] != "invalid_scope" {
		t.Fatalf("scope: %d %v", code, out)
	}
}
