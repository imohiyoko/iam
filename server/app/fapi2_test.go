package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// FAPI 2.0 Security Profile（ADR 0117）と、認可応答の iss（RFC 9207）を HTTP で確かめる。

// fapi2RP は private_key_jwt（RSA 2048 の鍵。PS256 で署名する）と DPoP の FAPI 2.0 の連携先。
type fapi2RP struct {
	*rp
	key *rsa.PrivateKey
	jti int
}

func registerFAPI2(t *testing.T, l *loginEnv, owner string, extra map[string]any) *fapi2RP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Import[jwk.Key](&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub.Set(jwk.KeyIDKey, "bank-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	jwks, _ := json.Marshal(set)
	body := map[string]any{"name": "Bank", "redirect_uris": []string{"https://bank.example.com/cb"}, "token_endpoint_auth_method": "private_key_jwt",
		"jwks": json.RawMessage(jwks), "dpop_bound_access_tokens": true, "fapi2_security_profile": true}
	for k, v := range extra {
		body[k] = v
	}
	return &fapi2RP{rp: l.registerRP(t, owner, body), key: key}
}

// assertion は client_assertion（aud は issuer）。
func (p *fapi2RP) assertion(t *testing.T, alg jwa.SignatureAlgorithm) url.Values {
	t.Helper()
	p.jti++
	now := p.l.a.deps.Clock.Now()
	tk, _ := jwt.NewBuilder().Issuer(p.clientID).Subject(p.clientID).Audience([]string{testIssuer}).JwtID(p.clientID + "-" + strconv.Itoa(p.jti)).
		IssuedAt(now).Expiration(now.Add(time.Minute)).Build()
	sk, err := jwk.Import[jwk.Key](p.key)
	if err != nil {
		t.Fatal(err)
	}
	_ = sk.Set(jwk.KeyIDKey, "bank-1")
	b, err := jwt.Sign(tk, jwt.WithKey(alg, sk))
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {string(b)}}
}

func withForm(a, b url.Values) url.Values {
	out := cloneValues(a)
	for k, v := range b {
		out[k] = v
	}
	return out
}

func fapi2Env(t *testing.T, edit func(*config.Config), extra ...string) *loginEnv {
	t.Helper()
	return senderEnv(t, edit, append([]string{feature.FAPI2, feature.PAR, feature.DPoP}, extra...)...)
}

func TestFAPI2Off(t *testing.T) {
	l := senderEnv(t, nil, feature.PAR, feature.DPoP)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	d := metadataAt(t, l, "/.well-known/openid-configuration")
	if d["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", d)
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "Bank", "redirect_uris": []string{"https://bank.example.com/cb"},
		"token_endpoint_auth_method": "private_key_jwt", "jwks": json.RawMessage(ecJWKSFor(t)), "dpop_bound_access_tokens": true,
		"fapi2_security_profile": true}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("fapi2 while off: %d %v", code, out)
	}
	// 認可応答の iss（RFC 9207）はどの連携先にも付ける（成功とエラー）。
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	_, cookie := l.login(t, "alice@example.com")
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	if u.Query().Get("iss") != testIssuer || u.Query().Get("code") == "" {
		t.Fatalf("success response: %s", u)
	}
	u = location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"prompt": {"none"}}), nil, ""))
	if u.Query().Get("iss") != testIssuer || u.Query().Get("error") != "login_required" {
		t.Fatalf("error response: %s", u)
	}
	u = location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"code_challenge_method": {"plain"}}), nil, ""))
	if u.Query().Get("iss") != testIssuer || u.Query().Get("error") == "" {
		t.Fatalf("op error response: %s", u)
	}
}

func ecJWKSFor(t *testing.T) []byte {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import[jwk.Key](&sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(k)
	b, _ := json.Marshal(set)
	return b
}

// 前提（fapi2・par、dpop か mtls_client_auth）が止まっていれば、連携先にも realm にも入れられない。
func TestFAPI2Prerequisites(t *testing.T) {
	for name, features := range map[string][]string{
		"no par":           {feature.FAPI2, feature.DPoP},
		"no dpop or mtls":  {feature.FAPI2, feature.PAR},
		"no fapi2 feature": {feature.PAR, feature.DPoP},
	} {
		l := senderEnv(t, nil, features...)
		_, owner := l.operator(t, "root@example.com", role.RealmOwner)
		body := map[string]any{"name": "Bank", "redirect_uris": []string{"https://bank.example.com/cb"}, "token_endpoint_auth_method": "private_key_jwt",
			"jwks": json.RawMessage(ecJWKSFor(t)), "fapi2_security_profile": true}
		if l.a.dpop != nil {
			body["dpop_bound_access_tokens"] = true
		}
		if code, out := l.admin(t, "/v1/admin/clients", owner, body); code != 400 || out["error"] != "invalid_client_metadata" {
			t.Fatalf("%s: client: %d %v", name, code, out)
		}
	}
	l := senderEnv(t, nil, feature.MultiRealm, feature.FAPI2, feature.PAR)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/realms", owner, map[string]any{"slug": "bank", "settings": map[string]any{"fapi2_security_profile": true}}); code != 400 ||
		out["error"] != "invalid_realm_settings" {
		t.Fatalf("realm without dpop or mtls: %d %v", code, out)
	}
}

// 正常系：PAR（DPoP の証明と private_key_jwt）→ authorize → token（DPoP）→ リフレッシュ（ローテーションしない）。
// 欠けたもの（PAR・DPoP・PS256 以外の alg）を 1 つずつ拒む。
func TestFAPI2HappyPathAndRejections(t *testing.T) {
	l := fapi2Env(t, func(c *config.Config) { c.OIDC.CodeTTL = config.Duration(5 * time.Minute) })
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := registerFAPI2(t, l, owner, nil)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+p.clientID, nil); code != 200 || out["fapi2_security_profile"] != true {
		t.Fatalf("client: %d %v", code, out)
	}
	h := l.a.PublicHandler()
	k := dpoptest.NewKey(t)
	par, token := testIssuer+oidcPAR, testIssuer+oidcToken
	push := func(alg jwa.SignatureAlgorithm, proof string) (int, map[string]any) {
		var hdr []string
		if proof != "" {
			hdr = []string{"DPoP", proof}
		}
		w, out := l.form(t, h, "POST", oidcPAR, withForm(p.pushForm(nil), p.assertion(t, alg)), nil, hdr...)
		return w.Code, out
	}
	authorize := func(uri string) string {
		return oidcAuthorize + "?" + url.Values{"client_id": {p.clientID}, "request_uri": {uri}}.Encode()
	}
	exchange := func(code string, proof string) (int, map[string]any) {
		var hdr []string
		if proof != "" {
			hdr = []string{"DPoP", proof}
		}
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "code_verifier": {p.verifier}}
		w, out := l.form(t, h, "POST", oidcToken, withForm(f, p.assertion(t, jwa.PS256())), nil, hdr...)
		return w.Code, out
	}

	// PAR を通らない認可要求は戻り先に転送せずに拒む。
	if w := l.oidcDo(t, "GET", p.authorizeURL(nil), nil, ""); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("plain authorize: %d %v", w.Code, w.Header())
	}
	// RS256 の client assertion は拒む（鍵は RSA で、FAPI でなければ通る）。
	if st, out := push(jwa.RS256(), l.proof(t, k, "POST", par, "", "")); st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("RS256 assertion: %d %v", st, out)
	}
	// ES384 の DPoP の証明は拒む。
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es384 := dpoptest.Sign(t, jose.ES384, p384, dpoptest.Claims{HTM: "POST", HTU: par, IAT: l.a.deps.Clock.Now()})
	if st, out := push(jwa.PS256(), es384); st != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("ES384 proof: %d %v", st, out)
	}

	// 正常系。
	st, out := push(jwa.PS256(), l.proof(t, k, "POST", par, "", ""))
	if st != 201 {
		t.Fatalf("push: %d %v", st, out)
	}
	u := location(t, l.oidcDo(t, "GET", authorize(out["request_uri"].(string)), nil, ""))
	_, cookie := l.login(t, "alice@example.com")
	cb := location(t, l.oidcDo(t, "GET", u.Query().Get("return_to"), nil, cookie))
	if cb.Query().Get("iss") != testIssuer || cb.Query().Get("state") != p.state {
		t.Fatalf("authorization response: %s", cb)
	}
	code := cb.Query().Get("code")
	// DPoP の証明の無い交換は拒む（使った認可コードは二度と使えない）。
	if st, out := exchange(code, ""); st != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("no proof: %d %v", st, out)
	}
	_, out = push(jwa.PS256(), l.proof(t, k, "POST", par, "", ""))
	code = p.code(t, l.oidcDo(t, "GET", authorize(out["request_uri"].(string)), nil, cookie))
	st, tok := exchange(code, l.proof(t, k, "POST", token, "", ""))
	if st != 200 || tok["token_type"] != "DPoP" || tok["refresh_token"] == nil || tok["id_token"] == nil {
		t.Fatalf("token: %d %v", st, tok)
	}
	if claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256); claims["aud"] != p.clientID {
		t.Fatalf("id token: %v", claims)
	}
	// リフレッシュトークンはローテーションしない：応答に新しいものは無く、同じトークンを続けて使える。
	rt := tok["refresh_token"].(string)
	for i := range 2 {
		f := withForm(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, p.assertion(t, jwa.PS256()))
		w, out := l.form(t, h, "POST", oidcToken, f, nil, "DPoP", l.proof(t, k, "POST", token, "", ""))
		if w.Code != 200 || out["token_type"] != "DPoP" || out["refresh_token"] != nil {
			t.Fatalf("refresh %d: %d %v", i, w.Code, out)
		}
	}
	// 認可コードの寿命は設定（5 分）より短い 60 秒。
	_, out = push(jwa.PS256(), l.proof(t, k, "POST", par, "", ""))
	code = p.code(t, l.oidcDo(t, "GET", authorize(out["request_uri"].(string)), nil, cookie))
	l.advance(61 * time.Second)
	if st, out := exchange(code, l.proof(t, k, "POST", token, "", "")); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("expired code: %d %v", st, out)
	}

	// 送信者制約の設定が外れた（dpop の無効化など）FAPI 2.0 の連携先は認証できない（fail-closed）。
	err = l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Clients().GetByPublicID(ctx, l.a.realm.ID, p.clientID)
		if err != nil {
			return err
		}
		c.DPoPBoundAccessTokens = false
		return tx.Clients().Update(ctx, c)
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, out := push(jwa.PS256(), l.proof(t, k, "POST", par, "", "")); st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("no sender constraint: %d %v", st, out)
	}
}

// realm で強いると、Discovery は強いるものだけを出し、条件を満たさない連携先は登録できない。
func TestFAPI2Realm(t *testing.T) {
	l := fapi2Env(t, func(c *config.Config) { c.Realm.FAPI2SecurityProfile = true })
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	d := metadataAt(t, l, wellKnownAS)
	want := map[string]any{
		"token_endpoint_auth_methods_supported":            []any{"private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []any{"PS256", "ES256", "EdDSA"},
		"dpop_signing_alg_values_supported":                []any{"PS256", "ES256", "EdDSA"},
		"id_token_signing_alg_values_supported":            []any{"ES256"},
		"require_pushed_authorization_requests":            true,
		"authorization_response_iss_parameter_supported":   true,
	}
	for k, v := range want {
		if !reflect.DeepEqual(d[k], v) {
			t.Errorf("%s = %v, want %v", k, d[k], v)
		}
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "SPA", "redirect_uris": []string{"https://spa.example.com/cb"},
		"token_endpoint_auth_method": "none"}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("public client in a FAPI realm: %d %v", code, out)
	}
	// 連携先に書かなくても強いる。
	p := registerFAPI2(t, l, owner, map[string]any{"fapi2_security_profile": false})
	if w := l.oidcDo(t, "GET", p.authorizeURL(nil), nil, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("plain authorize: %d", w.Code)
	}
	if w, out := l.form(t, l.a.PublicHandler(), "POST", oidcPAR, withForm(p.pushForm(nil), p.assertion(t, jwa.PS256())), nil); w.Code != 201 {
		t.Fatalf("push: %d %v", w.Code, out)
	}
}

func TestDisableFAPI2WithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	registerFAPI2(t, l, owner, nil)
	disableWithData(t, l, feature.FAPI2, 1)
}
