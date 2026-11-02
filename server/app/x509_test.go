package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"go.yaml.in/yaml/v3"
)

// X.509 のクライアント証明書のログイン（ADR 0103）を、mTLS の専用の待ち受けとプロキシのヘッダーで確かめる。

type testPKI struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * 365 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testPKI{root: c, rootKey: k}
}

func (p testPKI) leaf(t *testing.T, serial int64, eku x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "pat"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, k.Public(), p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// writeServerCert は mTLS の待ち受けのサーバー証明書と鍵をファイルに書く。
func writeServerCert(t *testing.T, p testPKI) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(98), Subject: pkix.Name{CommonName: "id.example.com"}, DNSNames: []string{"id.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, k.Public(), p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600) != nil ||
		os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600) != nil {
		t.Fatal("write server certificate")
	}
	return cf, kf
}

const proxyAddr = "192.0.2.10"

func newX509Env(t *testing.T, p testPKI, features ...string) *loginEnv {
	t.Helper()
	cf, kf := writeServerCert(t, p)
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &features
		var n map[string]yaml.Node
		src := "x509:\n  realms:\n    " + c.Realm.Slug + ":\n      revocation: {mode: none}\n      trust_anchors:\n        - |\n" +
			indent(pemCert(p.root), "          ")
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		c.Methods = n
		c.Server.ClientCertificates = config.ClientCertificates{MTLSAddr: "127.0.0.1:0", CertFile: cf, KeyFile: kf,
			Header: "X-Client-Cert", Proxies: []string{proxyAddr}}
	}, feature.Registered())
}

func indent(s, prefix string) string {
	var b strings.Builder
	for l := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix + l + "\n")
	}
	return b.String()
}

// mtls は mTLS の専用の待ち受けへの要求（クライアント証明書つき）。
func (l *loginEnv) mtls(t *testing.T, cookie, path string, body any, certs ...*x509.Certificate) (int, map[string]any, string) {
	t.Helper()
	w := l.doReq(t, l.a.MTLSHandler(), "POST", path, body, func(r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
		if cookie != "" {
			r.Header.Set("Cookie", sessionCookie+"="+cookie)
		}
	})
	return decodeResult(w.Code, w.Body.Bytes(), w.Result().Cookies())
}

func decodeResult(code int, body []byte, cookies []*http.Cookie) (int, map[string]any, string) {
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	for _, c := range cookies {
		if c.Name == sessionCookie && c.Value != "" {
			return code, out, c.Value
		}
	}
	return code, out, ""
}

func (l *loginEnv) doReq(t *testing.T, h http.Handler, method, path string, body any, edit func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (l *loginEnv) certLogin(t *testing.T, send func(path string, body any) (int, map[string]any, string)) (int, map[string]any, string) {
	t.Helper()
	status, st, _ := send("/v1/login/methods/x509:begin", map[string]any{})
	if status != 200 {
		return status, st, ""
	}
	return send("/v1/login/methods/x509:complete", map[string]any{"flow_id": st["flow_id"]})
}

func TestX509MTLSEnrollAndLogin(t *testing.T) {
	p := newTestPKI(t)
	l := newX509Env(t, p, feature.Org, feature.Warnings, feature.X509)
	cert := p.leaf(t, 10, x509.ExtKeyUsageClientAuth)
	_, full := l.login(t, "pat@example.com")

	// 登録は mTLS の待ち受けで、本人のセッションと証明書を使う。
	status, st, _ := l.mtls(t, full, "/v1/me/credentials/x509:enroll-begin", map[string]any{}, cert)
	if status != 200 || st["payload"].(map[string]any)["fingerprint"] == nil {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	status, res, _ := l.mtls(t, full, "/v1/me/credentials/x509:enroll-complete", map[string]any{"flow_id": st["flow_id"]}, cert)
	if status != 200 || res["credential"].(map[string]any)["method"] != "x509" {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	// 証明書が無ければ登録を始められない。
	if status, st, _ := l.mtls(t, full, "/v1/me/credentials/x509:enroll-begin", map[string]any{}); status != 400 || st["error"] != "client_certificate_required" {
		t.Fatalf("enroll without certificate: %d %v", status, st)
	}

	// 1要素目のログイン。
	status, login, cookie := l.certLogin(t, func(path string, body any) (int, map[string]any, string) {
		return l.mtls(t, "", path, body, cert)
	})
	if status != 200 || cookie == "" {
		t.Fatalf("x509 login: %d %v", status, login)
	}
	if status, sessions := l.me(t, cookie); status != 200 || len(sessions) == 0 {
		t.Fatalf("session after x509 login: %d %v", status, login)
	}
	// 証明書で入ったセッションには、同じ証明書を2要素目に出さない（同じ認証情報を2つの要素に数えない）。
	if login["next"] != nil {
		t.Fatalf("x509 login asks for the same credential as a second factor: %v", login)
	}
	// メールのログインの後は、証明書を2要素目に使える。
	login, restricted := l.login(t, "pat@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"x509"}) {
		t.Fatalf("email login: %v", login)
	}
	status, st, _ = l.mtls(t, restricted, "/v1/login/second-factor/x509:begin", map[string]any{}, cert)
	if status != 200 {
		t.Fatalf("second factor begin: %d %v", status, st)
	}
	if status, res, cookie := l.mtls(t, restricted, "/v1/login/second-factor/x509:complete", map[string]any{"flow_id": st["flow_id"]}, cert); status != 200 || cookie == "" {
		t.Fatalf("second factor complete: %d %v", status, res)
	}
	// 登録していない証明書・証明書なしは 401。
	other := p.leaf(t, 11, x509.ExtKeyUsageClientAuth)
	for name, certs := range map[string][]*x509.Certificate{"unenrolled": {other}, "none": nil} {
		if status, _, _ := l.certLogin(t, func(path string, body any) (int, map[string]any, string) {
			return l.mtls(t, "", path, body, certs...)
		}); status != 401 {
			t.Fatalf("%s: %d", name, status)
		}
	}
	// 専用の待ち受けは方式のパスだけを通す。TLS でない要求も通さない。
	if status, _, _ := l.mtls(t, cookie, "/v1/me/sessions", nil, cert); status != 404 {
		t.Fatalf("other path on the mTLS listener: %d", status)
	}
	w := l.doReq(t, l.a.MTLSHandler(), "POST", "/v1/login/methods/x509:begin", map[string]any{}, nil)
	if w.Code != 404 {
		t.Fatalf("plain request on the mTLS listener: %d", w.Code)
	}

	// プロキシのヘッダー：設定の proxies から直接つないだ要求でだけ読む。
	header := url.PathEscape(pemCert(cert))
	viaProxy := func(remote string) func(path string, body any) (int, map[string]any, string) {
		return func(path string, body any) (int, map[string]any, string) {
			w := l.doReq(t, l.a.PublicHandler(), "POST", path, body, func(r *http.Request) {
				r.RemoteAddr = remote + ":443"
				r.Header.Set("X-Client-Cert", header)
			})
			return decodeResult(w.Code, w.Body.Bytes(), w.Result().Cookies())
		}
	}
	if status, _, cookie := l.certLogin(t, viaProxy(proxyAddr)); status != 200 || cookie == "" {
		t.Fatalf("login via trusted proxy: %d", status)
	}
	if status, _, _ := l.certLogin(t, viaProxy("203.0.113.9")); status != 401 {
		t.Fatalf("header from an untrusted peer: %d", status)
	}
}

func TestX509FeatureOff(t *testing.T) {
	p := newTestPKI(t)
	l := newX509Env(t, p, feature.Org, feature.Warnings)
	if status, _, _ := l.mtls(t, "", "/v1/login/methods/x509:begin", map[string]any{}, p.leaf(t, 10, x509.ExtKeyUsageClientAuth)); status != 404 {
		t.Fatalf("x509 with the feature off: %d", status)
	}
}

func TestParseCertHeader(t *testing.T) {
	p := newTestPKI(t)
	c := p.leaf(t, 5, x509.ExtKeyUsageClientAuth)
	got, err := parseCertHeader(url.PathEscape(pemCert(c)+pemCert(p.root)), "pem")
	if err != nil || len(got) != 2 || !slices.Equal(got[0], c.Raw) {
		t.Fatalf("pem = %d, %v", len(got), err)
	}
	got, err = parseCertHeader(base64.StdEncoding.EncodeToString(c.Raw)+", "+base64.StdEncoding.EncodeToString(p.root.Raw), "der_base64")
	if err != nil || len(got) != 2 || !slices.Equal(got[1], p.root.Raw) {
		t.Fatalf("der_base64 = %d, %v", len(got), err)
	}
	for _, bad := range []struct{ v, f string }{
		{"", "pem"}, {"%zz", "pem"}, {url.PathEscape(pemCert(c)) + "trailing", "pem"},
		{url.PathEscape(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))), "pem"},
		{"!!", "der_base64"}, {"", "der_base64"}, {base64.StdEncoding.EncodeToString(c.Raw), "xml"},
		{strings.Repeat(base64.StdEncoding.EncodeToString(c.Raw)+",", 9), "der_base64"},
	} {
		if _, err := parseCertHeader(bad.v, bad.f); err == nil {
			t.Errorf("accepted %q (%s)", bad.v, bad.f)
		}
	}
}

func FuzzParseCertHeader(f *testing.F) {
	f.Add("-----BEGIN%20CERTIFICATE-----%0AMA%3D%3D%0A-----END%20CERTIFICATE-----%0A", "pem")
	f.Add("MAA=,MAA=", "der_base64")
	f.Fuzz(func(t *testing.T, v, format string) {
		chain, err := parseCertHeader(v, format)
		if err != nil {
			return
		}
		if len(chain) == 0 || len(chain) > maxClientCerts {
			t.Fatalf("chain length %d", len(chain))
		}
		for _, c := range chain {
			if len(c) == 0 || len(c) > maxClientCertBytes {
				t.Fatalf("certificate size %d", len(c))
			}
		}
	})
}

// 証明書で入った後、同じ証明書を2要素目に使うことはできない（ほかの2要素目を求める）。
func TestX509SameCredentialIsNotASecondFactor(t *testing.T) {
	p := newTestPKI(t)
	l := newX509Env(t, p, feature.Org, feature.Warnings, feature.X509, feature.HOTP)
	cert := p.leaf(t, 20, x509.ExtKeyUsageClientAuth)
	_, full := l.login(t, "pat@example.com")
	status, st, _ := l.mtls(t, full, "/v1/me/credentials/x509:enroll-begin", map[string]any{}, cert)
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	if status, res, _ := l.mtls(t, full, "/v1/me/credentials/x509:enroll-complete", map[string]any{"flow_id": st["flow_id"]}, cert); status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	if status, res, _ := l.enrollHOTP(t, full); status != 200 {
		t.Fatalf("hotp: %d %v", status, res)
	}
	status, login, restricted := l.certLogin(t, func(path string, body any) (int, map[string]any, string) {
		return l.mtls(t, "", path, body, cert)
	})
	if status != 200 || login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"hotp"}) {
		t.Fatalf("x509 login: %d %v", status, login)
	}
	status, st, _ = l.mtls(t, restricted, "/v1/login/second-factor/x509:begin", map[string]any{}, cert)
	if status != 200 {
		t.Fatalf("second factor begin: %d %v", status, st)
	}
	if status, res, _ := l.mtls(t, restricted, "/v1/login/second-factor/x509:complete", map[string]any{"flow_id": st["flow_id"]}, cert); status != 401 {
		t.Fatalf("same certificate as the second factor: %d %v", status, res)
	}
}
