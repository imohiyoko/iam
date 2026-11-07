package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	l := mtlsEnv(t, pki, feature.MTLSClientAuth, feature.PAR)
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
		aliases["token_endpoint"] != "https://mtls.example.test"+oidcToken ||
		aliases["pushed_authorization_request_endpoint"] != "https://mtls.example.test"+oidcPAR {
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

// CIBA の grant（ADR 0114）でも、DPoP の証明でトークンを鍵に結び付ける。dpop_bound_access_tokens の連携先は証明が要り、
// 証明の誤りはポーリングの間隔に数えない。
func TestDPoPCIBA(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP, feature.CIBA)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll", "dpop_bound_access_tokens": true})
	_, cookie := l.login(t, "alice@example.com")
	k := dpoptest.NewKey(t)
	h := l.a.PublicHandler()

	status, res := p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}})
	id, _ := res["auth_req_id"].(string)
	if status != 200 || id == "" {
		t.Fatalf("bc-authorize: %d %v", status, res)
	}
	code, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	reqs, _ := list["backchannel_requests"].([]any)
	if code != 200 || len(reqs) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+reqs[0].(map[string]any)["id"].(string)+":approve", nil); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	l.advance(10 * time.Second)
	form := func() url.Values {
		return url.Values{"grant_type": {provider.GrantTypeCIBA}, "auth_req_id": {id}, "client_id": {p.clientID}, "client_secret": {p.secret}}
	}
	// 証明が無い・誤った証明は invalid_dpop_proof（承認済みの要求は使われずに残る）。
	if w, out := l.form(t, h, "POST", oidcToken, form(), nil); w.Code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("no proof: %d %v", w.Code, out)
	}
	if w, out := l.form(t, h, "POST", oidcToken, form(), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcUserinfo, "", "")); w.Code != 400 ||
		out["error"] != "invalid_dpop_proof" {
		t.Fatalf("wrong htu: %d %v", w.Code, out)
	}
	w, tok := l.form(t, h, "POST", oidcToken, form(), nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v", w.Code, tok)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["active"] != true || in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect: %v", in)
	}
	// 機密の連携先のリフレッシュトークンは結び付けない（連携先の認証が守る）。
	if in := p.introspect(t, tok["refresh_token"].(string)); in["active"] != true || in["cnf"] != nil {
		t.Fatalf("introspect refresh: %v", in)
	}
	// 結び付けたアクセストークンは Bearer では UserInfo を通らない。
	if w, _ := l.form(t, h, "GET", oidcUserinfo, nil, nil, "Authorization", "Bearer "+tok["access_token"].(string)); w.Code != 401 {
		t.Fatalf("bearer use: %d", w.Code)
	}
}

// basic は連携先の client_secret_basic のヘッダー。
func (p *rp) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(p.clientID)+":"+url.QueryEscape(p.secret)))
}

// pushForm は PAR に送る認可要求（authorizeURL と同じパラメーター。PKCE は新しく作る）に extra を重ねる。
func (p *rp) pushForm(extra url.Values) url.Values {
	u, _ := url.Parse(p.authorizeURL(nil))
	q := u.Query()
	q.Del("client_id")
	for k, v := range extra {
		q[k] = v
	}
	return q
}

// PAR（ADR 0112）で預けた認可要求も DPoP の鍵に結び付く（RFC 9449 10.1）。PAR の要求の DPoP の証明の鍵か本文の dpop_jkt を
// 預け、認可コードの交換で同じ鍵の証明を求める。
func TestDPoPPAR(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP, feature.PAR)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	k, other := dpoptest.NewKey(t), dpoptest.NewKey(t)
	h := l.a.PublicHandler()
	par := testIssuer + oidcPAR
	push := func(extra url.Values, hdr ...string) (int, map[string]any) {
		w, out := l.form(t, h, "POST", oidcPAR, p.pushForm(extra), nil, append([]string{"Authorization", p.basic()}, hdr...)...)
		return w.Code, out
	}
	authorize := func(uri string) string {
		return oidcAuthorize + "?" + url.Values{"client_id": {p.clientID}, "request_uri": {uri}}.Encode()
	}
	exchange := func(code string, key *dpoptest.Key) (int, map[string]any) {
		var hdr []string
		if key != nil {
			hdr = []string{"DPoP", l.proof(t, key, "POST", testIssuer+oidcToken, "", "")}
		}
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "code_verifier": {p.verifier}}
		w, out := l.form(t, h, "POST", oidcToken, f, nil, append([]string{"Authorization", p.basic()}, hdr...)...)
		return w.Code, out
	}

	// 証明の誤り・本文の dpop_jkt と証明の鍵の違いは invalid_dpop_proof。壊れた dpop_jkt は invalid_request。
	if st, out := push(nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", "")); st != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("wrong htu: %d %v", st, out)
	}
	if st, out := push(url.Values{"dpop_jkt": {other.JKT()}}, "DPoP", l.proof(t, k, "POST", par, "", "")); st != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("dpop_jkt mismatch: %d %v", st, out)
	}
	if st, out := push(url.Values{"dpop_jkt": {"abc"}}); st != 400 || out["error"] != "invalid_request" {
		t.Fatalf("malformed dpop_jkt: %d %v", st, out)
	}

	// PAR の証明の鍵に結び付く：別の鍵・証明なしの交換は通らない。
	for name, key := range map[string]*dpoptest.Key{"other key": other, "no proof": nil} {
		st, out := push(nil, "DPoP", l.proof(t, k, "POST", par, "", ""))
		if st != 201 {
			t.Fatalf("push: %d %v", st, out)
		}
		code := p.followLogin(t, authorize(out["request_uri"].(string)), "alice@example.com")
		if st, out := exchange(code, key); st != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("%s: %d %v", name, st, out)
		}
	}
	st, out := push(nil, "DPoP", l.proof(t, k, "POST", par, "", ""))
	if st != 201 {
		t.Fatalf("push: %d %v", st, out)
	}
	code := p.followLogin(t, authorize(out["request_uri"].(string)), "alice@example.com")
	st, tok := exchange(code, k)
	if st != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v", st, tok)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect: %v", in)
	}

	// 本文の dpop_jkt だけでも（証明なし）預けた鍵に結び付く。
	st, out = push(url.Values{"dpop_jkt": {k.JKT()}})
	if st != 201 {
		t.Fatalf("push dpop_jkt: %d %v", st, out)
	}
	code = p.followLogin(t, authorize(out["request_uri"].(string)), "alice@example.com")
	if st, out := exchange(code, other); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("dpop_jkt other key: %d %v", st, out)
	}
	st, out = push(url.Values{"dpop_jkt": {k.JKT()}})
	if st != 201 {
		t.Fatalf("push dpop_jkt: %d %v", st, out)
	}
	code = p.followLogin(t, authorize(out["request_uri"].(string)), "alice@example.com")
	if st, tok := exchange(code, k); st != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("dpop_jkt token: %d %v", st, tok)
	}
}

// 自前の API に向けたトークン（RFC 8707、ADR 0112）も DPoP の鍵に結び付く：認可コードフロー・リフレッシュ（公開クライアント）・
// サービスアカウントの resource のトークン。イントロスペクションは aud と cnf.jkt を返す。
func TestDPoPResourceIndicators(t *testing.T) {
	l := senderEnv(t, nil, feature.DPoP, feature.ServiceAccounts, feature.ResourceIndicators)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	pub := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	rs := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	sa, secret := l.serviceAccountSecret(t, owner, "worker")
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": ordersAPI, "name": "Orders",
		"scopes": []string{"orders:read"}, "clients": []string{pub.clientID}, "service_accounts": []string{sa}}); code != 201 {
		t.Fatalf("resource: %d %v", code, out)
	}
	k, other := dpoptest.NewKey(t), dpoptest.NewKey(t)
	h := l.a.PublicHandler()
	tokenURL := testIssuer + oidcToken

	code, _ := pub.login(t, "alice@example.com", url.Values{"resource": {ordersAPI}, "scope": {"openid orders:read"}})
	form := pub.codeForm(code)
	form.Set("resource", ordersAPI)
	w, tok := l.form(t, h, "POST", oidcToken, form, nil, "DPoP", l.proof(t, k, "POST", tokenURL, "", ""))
	if w.Code != 200 || tok["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v", w.Code, tok)
	}
	in := rs.introspect(t, tok["access_token"].(string))
	if in["active"] != true || !slices.Equal(in["aud"].([]any), []any{ordersAPI}) || in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect: %v", in)
	}
	// リフレッシュ：同じ resource でも、別の鍵・証明なしは invalid_grant（リフレッシュトークンは使われずに残る）。
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {pub.clientID}, "resource": {ordersAPI}}
	if w, out := l.form(t, h, "POST", oidcToken, refresh, nil); w.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh without proof: %d %v", w.Code, out)
	}
	if w, out := l.form(t, h, "POST", oidcToken, refresh, nil, "DPoP", l.proof(t, other, "POST", tokenURL, "", "")); w.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh other key: %d %v", w.Code, out)
	}
	w, out := l.form(t, h, "POST", oidcToken, refresh, nil, "DPoP", l.proof(t, k, "POST", tokenURL, "", ""))
	if w.Code != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("refresh: %d %v", w.Code, out)
	}
	if in := rs.introspect(t, out["access_token"].(string)); !slices.Equal(in["aud"].([]any), []any{ordersAPI}) || in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect refreshed: %v", in)
	}

	// サービスアカウントの resource のトークン。
	sform := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret}, "resource": {ordersAPI}}
	w, st := l.form(t, l.a.AdminHandler(), "POST", adminTokenPath, sform, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""))
	if w.Code != 200 || st["token_type"] != "DPoP" || st["scope"] != "orders:read" {
		t.Fatalf("service account token: %d %v", w.Code, st)
	}
	in = rs.introspect(t, st["access_token"].(string))
	if in["active"] != true || !slices.Equal(in["aud"].([]any), []any{ordersAPI}) || in["cnf"].(map[string]any)["jkt"] != k.JKT() {
		t.Fatalf("introspect service account token: %v", in)
	}
	// Bearer のリソースのトークンには cnf が無い。
	w, st = l.form(t, l.a.AdminHandler(), "POST", adminTokenPath, sform, nil)
	if w.Code != 200 || st["token_type"] != "Bearer" {
		t.Fatalf("bearer service account token: %d %v", w.Code, st)
	}
	if in := rs.introspect(t, st["access_token"].(string)); in["active"] != true || in["cnf"] != nil {
		t.Fatalf("introspect bearer: %v", in)
	}
}

// Device Authorization Grant でも、nonce を求められた再試行が通る（承認済みの結果を use_dpop_nonce で消費しない）。
func TestDPoPDeviceNonce(t *testing.T) {
	l := senderEnv(t, func(c *config.Config) { c.OIDC.DPoP.RequireNonce = true }, feature.DPoP, feature.DeviceFlow)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	status, dev := p.startDevice(t, "openid email")
	if status != 200 {
		t.Fatalf("device authorization: %d %v", status, dev)
	}
	_, cookie := l.login(t, "alice@example.com")
	if w := l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {dev["user_code"].(string)}, "action": {"approve"}}, cookie); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	l.advance(time.Minute)
	k := dpoptest.NewKey(t)
	h := l.a.PublicHandler()
	form := url.Values{"grant_type": {provider.GrantTypeDeviceCode}, "device_code": {dev["device_code"].(string)}, "client_id": {p.clientID}}
	w, out := l.form(t, h, "POST", oidcToken, form, nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", ""))
	nonce := w.Header().Get("DPoP-Nonce")
	if w.Code != 400 || out["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("nonce challenge: %d %v %v", w.Code, out, w.Header())
	}
	if w, out := l.form(t, h, "POST", oidcToken, form, nil, "DPoP", l.proof(t, k, "POST", testIssuer+oidcToken, "", nonce)); w.Code != 200 ||
		out["token_type"] != "DPoP" {
		t.Fatalf("retry with nonce: %d %v", w.Code, out)
	}
}

// 管理 API の nonce のチャレンジにも DPoP-Nonce が付き、その nonce で続けられる。
func TestDPoPAdminNonce(t *testing.T) {
	l := senderEnv(t, func(c *config.Config) { c.OIDC.DPoP.RequireNonce = true }, feature.DPoP, feature.ServiceAccounts)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, out := l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "ci"})
	sa := out["id"].(string)
	_, out = l.admin(t, "/v1/admin/service-accounts/"+sa+"/credentials", owner, map[string]any{"type": "client_secret"})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {out["secret"].(string)}}
	k := dpoptest.NewKey(t)
	h := l.a.AdminHandler()
	w, out := l.form(t, h, "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", ""))
	nonce := w.Header().Get("DPoP-Nonce")
	if w.Code != 400 || out["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("nonce challenge: %d %v %v", w.Code, out, w.Header())
	}
	if w, out := l.form(t, h, "POST", adminTokenPath, form, nil, "DPoP", l.proof(t, k, "POST", testAdminURL+adminTokenPath, "", nonce)); w.Code != 200 ||
		out["token_type"] != "DPoP" {
		t.Fatalf("retry with nonce: %d %v", w.Code, out)
	}
}
