package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
)

// 汎用サービスアカウント（design.md 11.2、ADR 0074）。

func serviceAccountsEnv(t *testing.T) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		names := []string{}
		for _, f := range feature.Registered() {
			if f.DefaultEnabled || f.Name == feature.ServiceAccounts {
				names = append(names, f.Name)
			}
		}
		c.Features = &names
	}, feature.Registered())
}

// token は POST /v1/admin/token に form を送る。basic は "id:secret"（空なら付けない）。
func (l *loginEnv) token(t *testing.T, form url.Values, basic string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/admin/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != "" {
		id, secret, _ := strings.Cut(basic, ":")
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret))))
	}
	w := httptest.NewRecorder()
	l.a.AdminHandler().ServeHTTP(w, r)
	l.out.Write(w.Body.Bytes())
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code == 200 && w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token response is cacheable: %v", w.Header())
	}
	return w.Code, out
}

// signer は client assertion の署名鍵。
type signer struct {
	alg string
	jwk map[string]any
	sk  jose.SigningKey
}

func newSigner(t *testing.T, alg string) signer {
	t.Helper()
	var pub jose.JSONWebKey
	s := signer{alg: alg}
	switch alg {
	case "ES256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, s.sk = jose.JSONWebKey{Key: &k.PublicKey}, jose.SigningKey{Algorithm: jose.ES256, Key: k}
	case "EdDSA":
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		pub, s.sk = jose.JSONWebKey{Key: p}, jose.SigningKey{Algorithm: jose.EdDSA, Key: k}
	case "ML-DSA-65":
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		s.jwk = map[string]any{"kty": "AKP", "alg": alg, "pub": base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())}
		s.sk = jose.SigningKey{Algorithm: "ML-DSA-65", Key: mldsaTestSigner{k}}
		return s
	}
	b, err := pub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(b, &s.jwk)
	return s
}

func (s signer) assertion(t *testing.T, iss, aud, jti string, now time.Time, life time.Duration) string {
	t.Helper()
	sg, err := jose.NewSigner(s.sk, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	c := jwt.Claims{Issuer: iss, Subject: iss, Audience: jwt.Audience{aud}, ID: jti, IssuedAt: jwt.NewNumericDate(now),
		Expiry: jwt.NewNumericDate(now.Add(life))}
	out, err := jwt.Signed(sg).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type mldsaTestSigner struct{ k *mldsa.PrivateKey }

func (s mldsaTestSigner) Public() *jose.JSONWebKey { return nil }
func (s mldsaTestSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{"ML-DSA-65"}
}
func (s mldsaTestSigner) SignPayload(p []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	return s.k.Sign(nil, p, &mldsa.Options{})
}

// フィーチャーがオフなら管理 API とトークンのエンドポイントは 404 で、CLI は配信用だけを作れる（2.4）。
func TestServiceAccountsDisabledByDefault(t *testing.T) {
	l := newLoginEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "ci"}); code != 404 || out["error"] != "service_accounts_disabled" {
		t.Fatalf("create while off: %d %v", code, out)
	}
	if code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}}, ""); code != 404 {
		t.Fatalf("token while off: %d %v", code, out)
	}
	ctx := context.Background()
	if _, err := l.a.CreateServiceAccount(ctx, "ci", role.RealmAdmin); err == nil {
		t.Fatal("CLI created a general service account while the feature is off")
	}
	sa, err := l.a.CreateServiceAccount(ctx, "delivery", role.NotificationDelivery)
	if err != nil {
		t.Fatal(err)
	}
	// 配信用のキーで通知を取り出せる（無い通知は 404。認可は通っている）。
	if code, out := l.admin(t, "/v1/admin/notifications/ntf_00000000000000000000000000:claim", sa.APIKey, nil); code != 404 {
		t.Fatalf("delivery key: %d %v", code, out)
	}
}

func TestServiceAccountsAdminAPI(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	if code, _ := l.admin(t, "/v1/admin/service-accounts", support, map[string]any{"name": "ci"}); code != 403 {
		t.Fatalf("support creates: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": " "}); code != 400 || out["error"] != "invalid_name" {
		t.Fatalf("blank name: %d %v", code, out)
	}
	code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "ci"})
	if code != 201 || out["deleted"] != false || out["org_id"] != nil {
		t.Fatalf("create: %d %v", code, out)
	}
	sa := out["id"].(string)
	base := "/v1/admin/service-accounts/" + sa

	// API キー。権限はロールの付与で決まる。
	code, out = l.admin(t, base+"/credentials", owner, map[string]any{"type": "api_key"})
	if code != 201 || out["secret"] == nil || out["active"] != true {
		t.Fatalf("api key: %d %v", code, out)
	}
	key := out["secret"].(string)
	if code, _ := l.adminDo(t, "GET", key, "/v1/admin/service-accounts", nil); code != 403 {
		t.Fatalf("no role: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmAdmin, "principal_type": "service_account",
		"principal_id": sa}); code != 201 || out["principal_id"] != sa {
		t.Fatalf("grant: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", key, "/v1/admin/service-accounts?limit=1", nil); code != 200 || len(out["service_accounts"].([]any)) != 1 {
		t.Fatalf("list with key: %d %v", code, out)
	}

	// client_secret で client credentials。
	code, out = l.admin(t, base+"/credentials", owner, map[string]any{"type": "client_secret"})
	if code != 201 {
		t.Fatalf("client secret: %d %v", code, out)
	}
	secret, secretID := out["secret"].(string), out["id"].(string)
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret}}
	code, out = l.token(t, form, "")
	if code != 200 || out["token_type"] != "Bearer" || out["expires_in"] != float64(600) {
		t.Fatalf("token (post): %d %v", code, out)
	}
	tok := out["access_token"].(string)
	if code, _ := l.adminDo(t, "GET", tok, base, nil); code != 200 {
		t.Fatalf("use token: %d", code)
	}
	if code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}}, sa+":"+secret); code != 200 {
		t.Fatalf("token (basic): %d %v", code, out)
	}
	for name, f := range map[string]url.Values{
		"wrong secret":    {"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret[:len(secret)-2] + "AA"}},
		"other client_id": {"grant_type": {"client_credentials"}, "client_id": {"sva_00000000000000000000000000"}, "client_secret": {secret}},
		"api key":         {"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {key}},
	} {
		if code, out := l.token(t, f, ""); code != 401 || out["error"] != "invalid_client" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if code, out := l.token(t, url.Values{"grant_type": {"password"}, "client_id": {sa}, "client_secret": {secret}}, ""); code != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("grant type: %d %v", code, out)
	}
	// トークンは期限まで。
	l.advance(11 * time.Minute)
	if code, _ := l.adminDo(t, "GET", tok, base, nil); code != 401 {
		t.Fatalf("expired token: %d", code)
	}

	// private_key_jwt（ES256・EdDSA・ML-DSA-65）。
	for _, alg := range []string{"ES256", "EdDSA", "ML-DSA-65"} {
		s := newSigner(t, alg)
		code, out = l.admin(t, base+"/credentials", owner, map[string]any{"type": "private_key_jwt", "alg": alg, "public_key": s.jwk})
		if code != 201 || out["secret"] != nil || out["alg"] != alg {
			t.Fatalf("%s key: %d %v", alg, code, out)
		}
		now := l.a.deps.Clock.Now()
		af := func(a string) url.Values {
			return url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion": {a}}
		}
		a := s.assertion(t, sa, testIssuer, "j-"+alg, now, time.Minute)
		if code, out := l.token(t, af(a), ""); code != 200 {
			t.Fatalf("%s assertion: %d %v", alg, code, out)
		}
		if code, _ := l.token(t, af(a), ""); code != 401 {
			t.Fatalf("%s replay: %d", alg, code)
		}
		for name, bad := range map[string]string{
			"aud":      s.assertion(t, sa, "https://other.example", "a-"+alg, now, time.Minute),
			"lifetime": s.assertion(t, sa, testIssuer, "l-"+alg, now, time.Hour),
			"expired":  s.assertion(t, sa, testIssuer, "e-"+alg, now.Add(-10*time.Minute), 5*time.Minute),
			"signer":   newSigner(t, alg).assertion(t, sa, testIssuer, "s-"+alg, now, time.Minute),
		} {
			if code, _ := l.token(t, af(bad), ""); code != 401 {
				t.Fatalf("%s %s: %d", alg, name, code)
			}
		}
	}
	// 秘密の項目を含む鍵と、alg と合わない鍵は登録できない。
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, _ := jose.JSONWebKey{Key: ec}.MarshalJSON()
	var privJWK map[string]any
	_ = json.Unmarshal(priv, &privJWK)
	for name, body := range map[string]map[string]any{
		"private": {"type": "private_key_jwt", "alg": "ES256", "public_key": privJWK},
		"alg":     {"type": "private_key_jwt", "alg": "EdDSA", "public_key": newSigner(t, "ES256").jwk},
	} {
		if code, out := l.admin(t, base+"/credentials", owner, body); code != 400 || out["error"] != "invalid_public_key" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}

	// 停止中はキーもトークンも使えず、解除すれば戻る。
	code, out = l.token(t, form, "")
	if code != 200 {
		t.Fatalf("token: %d %v", code, out)
	}
	tok = out["access_token"].(string)
	code, out = l.admin(t, base+"/suspensions", owner, map[string]any{"category": "security_risk", "reason": "leak"})
	if code != 201 || out["target_type"] != "service_account" || out["target_id"] != sa {
		t.Fatalf("suspend: %d %v", code, out)
	}
	susp := out["id"].(string)
	for name, b := range map[string]string{"key": key, "token": tok} {
		if code, _ := l.adminDo(t, "GET", b, base, nil); code != 401 {
			t.Fatalf("suspended %s: %d", name, code)
		}
	}
	if code, _ := l.token(t, form, ""); code != 401 {
		t.Fatalf("token while suspended: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, base+"/suspensions", nil); code != 200 || len(out["suspensions"].([]any)) != 1 {
		t.Fatalf("list suspensions: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/suspensions/"+susp+":lift", owner, map[string]any{"reason": "rotated"}); code != 200 {
		t.Fatalf("lift: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", tok, base, nil); code != 200 {
		t.Fatalf("token after lift: %d", code)
	}

	// 認証情報を無効化すれば、それで発行したトークンも使えない。
	if code, out := l.admin(t, base+"/credentials/"+secretID+":revoke", owner, nil); code != 200 || out["active"] != false {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", tok, base, nil); code != 401 {
		t.Fatalf("token after revoke: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, base+"/credentials", nil); code != 200 || len(out["credentials"].([]any)) != 5 {
		t.Fatalf("credentials: %d %v", code, out)
	}

	// 削除すれば認証できず、認証情報も足せない。
	if code, out := l.admin(t, base+":delete", owner, nil); code != 200 || out["deleted"] != true {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", key, base, nil); code != 401 {
		t.Fatalf("deleted key: %d", code)
	}
	if code, out := l.admin(t, base+"/credentials", owner, map[string]any{"type": "api_key"}); code != 409 || out["error"] != "service_account_deleted" {
		t.Fatalf("credential for deleted: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/service-accounts/sva_00000000000000000000000000", nil); code != 404 {
		t.Fatalf("missing: %d", code)
	}

	// 監査ログに残り、秘密は外に出ない。
	events := l.auditTypes(t)
	all, _ := json.Marshal(events)
	for _, typ := range []string{"service_account.created", "service_account.credential_created", "service_account.token_issued",
		"service_account.suspended", "service_account.credential_revoked", "service_account.deleted"} {
		if !slices.ContainsFunc(events, func(e audit.Event) bool { return e.Type == typ }) {
			t.Errorf("audit %s missing", typ)
		}
	}
	for _, s := range []string{key, secret, tok} {
		if strings.Contains(string(all), s) || strings.Contains(l.e.logs.String(), s) {
			t.Fatal("a secret reached the audit log or the logs")
		}
	}
}

// Org に属するサービスアカウントは、Org が停止・削除されれば使えない。
func TestOrgServiceAccount(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	code, out := l.admin(t, "/v1/admin/users", owner, map[string]any{"email": "boss@acme.example"})
	if code != 201 {
		t.Fatalf("user: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/orgs", owner, map[string]any{"name": "Acme", "owner_id": out["user_id"]})
	if code != 201 {
		t.Fatalf("org: %d %v", code, out)
	}
	acme := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "x", "org_id": "org_00000000000000000000000000"}); code != 400 || out["error"] != "invalid_org" {
		t.Fatalf("unknown org: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "acme-bot", "org_id": acme})
	if code != 201 || out["org_id"] != acme {
		t.Fatalf("create: %d %v", code, out)
	}
	sa := out["id"].(string)
	_, out = l.admin(t, "/v1/admin/service-accounts/"+sa+"/credentials", owner, map[string]any{"type": "api_key"})
	key := out["secret"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmSupport, "principal_type": "service_account",
		"principal_id": sa}); code != 201 {
		t.Fatalf("grant: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", key, "/v1/admin/orgs/"+acme, nil); code != 200 {
		t.Fatalf("use: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/orgs/"+acme+"/suspensions", owner, map[string]any{"category": "billing", "reason": "unpaid"}); code != 201 {
		t.Fatalf("suspend org: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", key, "/v1/admin/orgs/"+acme, nil); code != 401 {
		t.Fatalf("org suspended: %d", code)
	}
}

// 有効期間の外のサービスアカウントは使えない。
func TestServiceAccountValidity(t *testing.T) {
	l := serviceAccountsEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	until := l.a.deps.Clock.Now().Add(time.Hour)
	code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "temp", "valid_until": until})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	sa := out["id"].(string)
	_, out = l.admin(t, "/v1/admin/service-accounts/"+sa+"/credentials", owner, map[string]any{"type": "api_key"})
	key := out["secret"].(string)
	l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmSupport, "principal_type": "service_account", "principal_id": sa})
	if code, _ := l.adminDo(t, "GET", key, "/v1/admin/service-accounts/"+sa+"/suspensions", nil); code != 200 {
		t.Fatalf("before end: %d", code)
	}
	l.advance(2 * time.Hour)
	if code, _ := l.adminDo(t, "GET", key, "/v1/admin/service-accounts/"+sa+"/suspensions", nil); code != 401 {
		t.Fatalf("after end: %d", code)
	}
}

// フィーチャーを無効にするとき、配信用は残し、汎用のサービスアカウントだけを片付ける（11.12）。
func TestDisableServiceAccountsWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, n := range []string{"a", "b"} {
		if code, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": n}); code != 201 {
			t.Fatalf("create: %d %v", code, out)
		}
	}
	disableWithData(t, l, feature.ServiceAccounts, 2)
	// 配信用のキー（newLoginEnv で作ったもの）は使い続けられる。
	if code, out := l.admin(t, "/v1/admin/notifications/ntf_00000000000000000000000000:claim", l.apiKey, nil); code != 404 {
		t.Fatalf("delivery key after disable: %d %v", code, out)
	}
}
