package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 送信者制約トークン（DPoP・OAuth の mTLS。ADR 0113）を HTTP で確かめる。

const testAdminURL = "https://admin.example.test"

func senderEnv(t *testing.T, edit func(*config.Config), extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		names := []string{}
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
		c.OIDC.DPoP.AdminURL = testAdminURL
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

// form は h に form の本文の要求を送る。certs があれば TLS のクライアント証明書として付ける（mTLS の専用の待ち受け）。
func (l *loginEnv) form(t *testing.T, h http.Handler, method, path string, form url.Values, certs []*x509.Certificate, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if certs != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func (l *loginEnv) proof(t *testing.T, k *dpoptest.Key, method, u, token, nonce string) string {
	t.Helper()
	c := dpoptest.Claims{HTM: method, HTU: u, IAT: l.a.deps.Clock.Now(), Nonce: nonce}
	if token != "" {
		c.ATH = dpop.AccessTokenHash(token)
	}
	return k.Proof(t, c)
}

func (p *rp) codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "code_verifier": {p.verifier},
		"client_id": {p.clientID}}
}

func TestDPoPTokenUserInfoRefresh(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	pub := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	rs := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	k, other := dpoptest.NewKey(t), dpoptest.NewKey(t)
	h := l.a.PublicHandler()

	w, disc := l.form(t, h, "GET", "/.well-known/openid-configuration", nil, nil)
	if algs, _ := disc["dpop_signing_alg_values_supported"].([]any); w.Code != 200 || !slices.Contains(algs, any("ES256")) {
		t.Fatalf("discovery: %v", disc)
	}

	code, _ := pub.login(t, "alice@example.com", nil)
	// 署名の誤った証明・別の URL の証明は invalid_dpop_proof。
	bad := l.proof(t, k, "POST", testIssuer+oidcUserinfo, "", "")
	if w, out := l.form(t, h, "POST", oidcToken, pub.codeForm(code), nil, "DPoP", bad); w.Code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("wrong htu: %d %v", w.Code, out)
	}
	w, tok := l.form(t, h, "POST", oidcToken, pub.codeForm(code), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v", w.Code, tok)
	}
	at, rt := tok["access_token"].(string), tok["refresh_token"].(string)

	// イントロスペクションに cnf.jkt。リフレッシュトークン（公開クライアント）も結び付く。
	if in := rs.introspect(t, at); in["active"] != true || in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect access: %v", in)
	}
	if in := rs.introspect(t, rt); in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect refresh: %v", in)
	}

	// UserInfo：Bearer では通らない。DPoP の方式でも、ath の無い・別の鍵の証明は通らない。
	ui := testIssuer + oidcUserinfo
	if w, _ := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "Bearer "+at); w.Code != 401 ||
		!strings.Contains(w.Header().Values("WWW-Authenticate")[0], `DPoP error="invalid_token"`) {
		t.Fatalf("bearer use of dpop token: %d %v", w.Code, w.Header())
	}
	for name, pr := range map[string]string{"no ath": l.proof(t, k, "GET", ui, "", ""), "other key": l.proof(t, other, "GET", ui, at, ""),
		"wrong method": l.proof(t, k, "POST", ui, at, "")} {
		if w, out := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "DPoP "+at, "DPoP", pr); w.Code != 401 || out["error"] != "invalid_dpop_proof" {
			t.Fatalf("%s: %d %v", name, w.Code, out)
		}
	}
	good := l.proof(t, k, "GET", ui, at, "")
	if w, out := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "DPoP "+at, "DPoP", good); w.Code != 200 || out["sub"] == nil {
		t.Fatalf("userinfo: %d %v", w.Code, out)
	}
	// 同じ証明は2回使えない。
	if w, _ := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "DPoP "+at, "DPoP", good); w.Code != 401 {
		t.Fatalf("replayed proof: %d", w.Code)
	}

	// リフレッシュ：証明が無い・別の鍵なら invalid_grant（使用済みにしない）。同じ鍵なら通る。
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {pub.clientID}}
	if w, out := l.form(t, h, "POST", oidcToken, rf, nil); w.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh without proof: %d %v", w.Code, out)
	}
	if w, out := l.form(t, h, "POST", oidcToken, rf, nil, "DPoP", l.proof(t, other, "POST", testIssuer+oidcToken, "", "")); w.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh other key: %d %v", w.Code, out)
	}
	if w, out := l.form(t, h, "POST", oidcToken, rf, nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", "")); w.Code != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("refresh: %d %v", w.Code, out)
	}

	// 機密の連携先のリフレッシュトークンは結び付けない（アクセストークンだけ）。
	code, _ = rs.login(t, "alice@example.com", nil)
	f := rs.codeForm(code)
	f.Set("client_secret", rs.secret)
	w, tok = l.form(t, h, "POST", oidcToken, f, nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("confidential token: %d %v", w.Code, tok)
	}
	if in := rs.introspect(t, tok["refresh_token"].(string)); in["cnf"] != nil {
		t.Fatalf("confidential refresh bound: %v", in)
	}
	// 結び付けの無いトークンを DPoP の方式で示すのは誤り。証明の無い要求の Bearer はそのまま通る。
	code, _ = rs.login(t, "alice@example.com", nil)
	f = rs.codeForm(code)
	f.Set("client_secret", rs.secret)
	_, plain := l.form(t, h, "POST", oidcToken, f, nil)
	if plain["token_type"] != "Bearer" {
		t.Fatalf("bearer token: %v", plain)
	}
	pt := plain["access_token"].(string)
	if w, _ := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "DPoP "+pt, "DPoP", l.proof(t, k, "GET", ui, pt, "")); w.Code != 401 {
		t.Fatalf("unbound token with DPoP scheme: %d", w.Code)
	}
	if w, _ := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "Bearer "+pt); w.Code != 200 {
		t.Fatalf("bearer: %d", w.Code)
	}

	// dpop_jkt（RFC 9449 10）：認可コードは同じ鍵の証明でだけ交換できる。
	code, _ = pub.login(t, "alice@example.com", url.Values{"dpop_jkt": {k.JKT()}})
	if w, out := l.form(t, h, "POST", oidcToken, pub.codeForm(code), nil, "DPoP", l.proof(t, other, "POST", testIssuer+oidcToken, "", "")); w.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("dpop_jkt mismatch: %d %v", w.Code, out)
	}
	if u := location(t, l.oidcDo(t, "GET", pub.authorizeURL(url.Values{"dpop_jkt": {"not-a-thumbprint"}}), nil, "")); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("malformed dpop_jkt: %s", u)
	}
}

func TestDPoPBoundClientAndNonce(t *testing.T) {
	l := senderEnv(t, func(c *config.Config) { c.OIDC.DPoP.RequireNonce = true }, feature.DPoP)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "dpop_bound_access_tokens": true})
	k := dpoptest.NewKey(t)
	h := l.a.PublicHandler()
	code, _ := p.login(t, "alice@example.com", nil)
	// dpop_bound_access_tokens の連携先は証明が要る。
	if w, out := l.form(t, h, "POST", oidcToken, p.codeForm(code), nil); w.Code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("bound client without proof: %d %v", w.Code, out)
	}
	// nonce が要る：use_dpop_nonce と DPoP-Nonce。その nonce で通る。
	w, out := l.form(t, h, "POST", oidcToken, p.codeForm(code), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", ""))
	nonce := w.Header().Get("DPoP-Nonce")
	if w.Code != 400 || out["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("nonce challenge: %d %v %v", w.Code, out, w.Header())
	}
	if w, out := l.form(t, h, "POST", oidcToken, p.codeForm(code), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", nonce)); w.Code != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("with nonce: %d %v", w.Code, out)
	}
}

func TestDPoPFeatureOff(t *testing.T) {
	l := senderEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "x", "redirect_uris": []string{"https://rp.example.com/cb"},
		"token_endpoint_auth_method": "none", "dpop_bound_access_tokens": true}); code != 400 {
		t.Fatalf("dpop client while off: %d %v", code, out)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	h := l.a.PublicHandler()
	_, disc := l.form(t, h, "GET", "/.well-known/openid-configuration", nil, nil)
	if disc["dpop_signing_alg_values_supported"] != nil {
		t.Fatalf("discovery while off: %v", disc)
	}
	// 証明は見ずに Bearer を出す（RFC 9449 では許される）。
	k := dpoptest.NewKey(t)
	code, _ := p.login(t, "alice@example.com", nil)
	if w, out := l.form(t, h, "POST", oidcToken, p.codeForm(code), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", "")); w.Code != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("token while off: %d %v", w.Code, out)
	}
	// 結び付けたトークンは、フィーチャーが止まっていれば通さない（fail-closed）。
	r := httptest.NewRequest("GET", oidcUserinfo, nil)
	for _, scheme := range []string{"Bearer", dpop.Scheme} {
		if err := l.a.checkResourceBinding(context.Background(), r, scheme, "t", provider.Binding{JKT: k.JKT()}, []string{testIssuer + oidcUserinfo}); err == nil {
			t.Fatalf("%s: bound token accepted while dpop is off", scheme)
		}
		if err := l.a.checkResourceBinding(context.Background(), r, scheme, "t", provider.Binding{X5T: "x"}, nil); err == nil {
			t.Fatalf("%s: certificate-bound token accepted while mtls is off", scheme)
		}
	}
}

func TestDPoPServiceAccountAdminAPI(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP, feature.ServiceAccounts)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "ci"})
	sa := out["id"].(string)
	base := "/v1/admin/service-accounts/" + sa
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmAdmin, "principal_type": "service_account",
		"principal_id": sa}); code != 201 {
		t.Fatalf("grant: %d %v", code, out)
	}
	_, out = l.admin(t, base+"/credentials", owner, map[string]any{"type": "client_secret"})
	secret := out["secret"].(string)
	k := dpoptest.NewKey(t)
	h := l.a.AdminHandler()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret}}
	if w, out := l.form(t, h, "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testIssuer+adminTokenPath, "", "")); w.Code != 400 ||
		out["error"] != "invalid_dpop_proof" {
		t.Fatalf("wrong htu: %d %v", w.Code, out)
	}
	w, tok := l.form(t, h, "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v", w.Code, tok)
	}
	at := tok["access_token"].(string)
	if w, _ := l.form(t, h, "GET", base, nil, nil, "Authorization", "Bearer "+at); w.Code != 401 ||
		!strings.Contains(strings.Join(w.Header().Values("WWW-Authenticate"), ","), "DPoP") {
		t.Fatalf("bearer use: %d %v", w.Code, w.Header())
	}
	if w, _ := l.form(t, h, "GET", base, nil, nil, "Authorization", "DPoP "+at, "DPoP", l.proof(t, dpoptest.NewKey(t), "GET", testAdminURL+base, at, "")); w.Code != 401 {
		t.Fatalf("other key: %d", w.Code)
	}
	if w, out := l.form(t, h, "GET", base, nil, nil, "Authorization", "DPoP "+at, "DPoP", l.proof(t, k, "GET", testAdminURL+base, at, "")); w.Code != 200 {
		t.Fatalf("dpop use: %d %v", w.Code, out)
	}
	// 2つの DPoP ヘッダーは受けない。
	if w, _ := l.form(t, h, "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""),
		"DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", "")); w.Code != 400 {
		t.Fatalf("two proofs: %d", w.Code)
	}
	// 運営者のセッションを DPoP の方式で示しても通らない。
	if w, _ := l.form(t, h, "GET", base, nil, nil, "Authorization", "DPoP "+owner); w.Code != 401 {
		t.Fatalf("session with DPoP scheme: %d", w.Code)
	}
	// 無効化：結び付けたトークンを消す。
	cl := cleaners[feature.DPoP]
	var n int
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		if n, err = cl.Count(ctx, tx); err != nil || n != 1 {
			return fmt.Errorf("count = %d, %w", n, err)
		}
		if _, err = cl.Purge(ctx, tx, l.a.deps.Clock.Now(), 10); err != nil {
			return err
		}
		n, err = cl.Count(ctx, tx)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("cleaner: %d %v", n, err)
	}
}

// mtlsPKI は連携先の証明書の CA を書き、設定に載せる。
func mtlsEnv(t *testing.T, p testPKI, extra ...string) *loginEnv {
	t.Helper()
	cf, kf := writeServerCert(t, p)
	anchors := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(anchors, []byte(pemCert(p.root)), 0o600); err != nil {
		t.Fatal(err)
	}
	return senderEnv(t, func(c *config.Config) {
		c.Server.ClientCertificates = config.ClientCertificates{MTLSAddr: "127.0.0.1:0", CertFile: cf, KeyFile: kf}
		c.OIDC.MTLS = config.OAuthMTLS{TrustAnchors: []string{anchors}, EndpointURL: "https://mtls.example.test"}
	}, extra...)
}

func selfSigned(t *testing.T) (*x509.Certificate, map[string]any) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "self"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	b, _ := json.Marshal(jose.JSONWebKey{Key: k.Public()})
	var jwk map[string]any
	_ = json.Unmarshal(b, &jwk)
	return c, map[string]any{"keys": []any{jwk}}
}

func TestMTLSClientAuthAndBoundTokens(t *testing.T) {
	pki := newTestPKI(t)
	l := mtlsEnv(t, pki, feature.MTLSClientAuth)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_subject_dn": "CN=pat",
		"tls_client_certificate_bound_access_tokens": true})
	rs := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	leaf, other := pki.leaf(t, 10, x509.ExtKeyUsageClientAuth), pki.leaf(t, 11, x509.ExtKeyUsageServerAuth)
	pub, mtls := l.a.PublicHandler(), l.a.MTLSHandler()

	_, disc := l.form(t, pub, "GET", "/.well-known/openid-configuration", nil, nil)
	methods, _ := disc["token_endpoint_auth_methods_supported"].([]any)
	aliases, _ := disc["mtls_endpoint_aliases"].(map[string]any)
	if !slices.Contains(methods, any("tls_client_auth")) || disc["tls_client_certificate_bound_access_tokens"] != true ||
		aliases["token_endpoint"] != "https://mtls.example.test"+oidcToken {
		t.Fatalf("discovery: %v", disc)
	}

	code, _ := p.login(t, "alice@example.com", nil)
	// 証明書が無い・用途の違う証明書は invalid_client。
	if w, out := l.form(t, pub, "POST", oidcToken, p.codeForm(code), nil); w.Code != 401 || out["error"] != "invalid_client" {
		t.Fatalf("no certificate: %d %v", w.Code, out)
	}
	if w, out := l.form(t, mtls, "POST", oidcToken, p.codeForm(code), []*x509.Certificate{other}); w.Code != 401 || out["error"] != "invalid_client" {
		t.Fatalf("server-auth certificate: %d %v", w.Code, out)
	}
	w, tok := l.form(t, mtls, "POST", oidcToken, p.codeForm(code), []*x509.Certificate{leaf})
	if w.Code != 200 || tok["token_type"] != "Bearer" {
		t.Fatalf("token over mTLS: %d %v", w.Code, tok)
	}
	at := tok["access_token"].(string)
	if in := rs.introspect(t, at); in["cnf"].(map[string]any)["x5t#S256"] != provider.CertThumbprint(leaf.Raw) {
		t.Fatalf("introspect: %v", in)
	}
	// 証明書に結び付けたトークンは、同じ証明書の要求でだけ通る。
	if w, _ := l.form(t, pub, "GET", oidcUserinfo, nil, nil, "Authorization", "Bearer "+at); w.Code != 401 {
		t.Fatalf("userinfo without certificate: %d", w.Code)
	}
	if w, _ := l.form(t, mtls, "GET", oidcUserinfo, nil, []*x509.Certificate{other}, "Authorization", "Bearer "+at); w.Code != 401 {
		t.Fatalf("userinfo other certificate: %d", w.Code)
	}
	if w, out := l.form(t, mtls, "GET", oidcUserinfo, nil, []*x509.Certificate{leaf}, "Authorization", "Bearer "+at); w.Code != 200 {
		t.Fatalf("userinfo over mTLS: %d %v", w.Code, out)
	}

	// self_signed_tls_client_auth：JWKS の鍵の証明書で認証する。
	ss, jwks := selfSigned(t)
	sp := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "self_signed_tls_client_auth", "jwks": jwks})
	code, _ = sp.login(t, "alice@example.com", nil)
	if w, out := l.form(t, mtls, "POST", oidcToken, sp.codeForm(code), []*x509.Certificate{leaf}); w.Code != 401 {
		t.Fatalf("self-signed with other key: %d %v", w.Code, out)
	}
	if w, out := l.form(t, mtls, "POST", oidcToken, sp.codeForm(code), []*x509.Certificate{ss}); w.Code != 200 {
		t.Fatalf("self-signed: %d %v", w.Code, out)
	}

	// 登録の誤り：照合の項目が無い・2つ。
	for _, body := range []map[string]any{{"token_endpoint_auth_method": "tls_client_auth"},
		{"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_subject_dn": "CN=a", "tls_client_auth_san_dns": "a.example.com"},
		{"token_endpoint_auth_method": "client_secret", "tls_client_auth_subject_dn": "CN=a"}} {
		body["name"], body["redirect_uris"] = "bad", []string{"https://rp.example.com/cb"}
		if code, out := l.admin(t, "/v1/admin/clients", owner, body); code != 400 {
			t.Fatalf("invalid registration %v: %d %v", body, code, out)
		}
	}

	// 無効化：照合の項目と結び付けの設定を外し、結び付けたトークンを消す。tls_client_auth の連携先は認証できなくなる。
	cl := cleaners[feature.MTLSClientAuth]
	var n int
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		// tls_client_auth の連携先の設定 1 件と、証明書に結び付けたアクセストークン 1 件（機密の連携先のリフレッシュトークンは結び付けない）。
		if n, err = cl.Count(ctx, tx); err != nil || n != 2 {
			return fmt.Errorf("count = %d, %w", n, err)
		}
		if _, err = cl.Purge(ctx, tx, l.a.deps.Clock.Now(), 10); err != nil {
			return err
		}
		n, err = cl.Count(ctx, tx)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("cleaner: %d %v", n, err)
	}
	code, _ = p.login(t, "alice@example.com", nil)
	if w, _ := l.form(t, mtls, "POST", oidcToken, p.codeForm(code), []*x509.Certificate{leaf}); w.Code != 401 {
		t.Fatalf("tls_client_auth after purge: %d", w.Code)
	}
}

func TestMTLSFeatureOff(t *testing.T) {
	pki := newTestPKI(t)
	l := mtlsEnv(t, pki)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, body := range []map[string]any{{"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_subject_dn": "CN=pat"},
		{"token_endpoint_auth_method": "none", "tls_client_certificate_bound_access_tokens": true}} {
		body["name"], body["redirect_uris"] = "x", []string{"https://rp.example.com/cb"}
		if code, out := l.admin(t, "/v1/admin/clients", owner, body); code != 400 {
			t.Fatalf("registration while off %v: %d %v", body, code, out)
		}
	}
	// 専用の待ち受けは OAuth のエンドポイントを通さない。
	if w, _ := l.form(t, l.a.MTLSHandler(), "POST", oidcToken, url.Values{}, []*x509.Certificate{pki.leaf(t, 3, x509.ExtKeyUsageClientAuth)}); w.Code != 404 {
		t.Fatalf("mtls listener token endpoint while off: %d", w.Code)
	}
	_, disc := l.form(t, l.a.PublicHandler(), "GET", "/.well-known/openid-configuration", nil, nil)
	if disc["mtls_endpoint_aliases"] != nil || disc["tls_client_certificate_bound_access_tokens"] != nil {
		t.Fatalf("discovery while off: %v", disc)
	}
}
