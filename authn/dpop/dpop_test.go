package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/clock"
)

const tokenURL = "https://id.example.com/oauth2/token"

func setup(t *testing.T) (*dpop.Verifier, *clock.Fake, *dpoptest.Key) {
	t.Helper()
	k := testkit.New(t)
	return &dpop.Verifier{Clock: k.Clock, Store: k.Cache}, k.Clock, dpoptest.NewKey(t)
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	v, clk, k := setup(t)
	proof := k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: clk.Now()})
	p, err := v.Verify(ctx, []string{proof}, dpop.Expect{Method: "POST", URLs: []string{tokenURL}})
	if err != nil || p.JKT != k.JKT() {
		t.Fatalf("Verify = %+v, %v", p, err)
	}
	// 同じ証明（jti）は2回使えない。
	if _, err := v.Verify(ctx, []string{proof}, dpop.Expect{Method: "POST", URLs: []string{tokenURL}}); !errors.Is(err, dpop.ErrInvalidProof) {
		t.Fatalf("replay = %v", err)
	}
	// 既定のポートと大文字のホスト、クエリは比べない。
	proof = k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: "https://ID.example.com:443/oauth2/token?x=1", IAT: clk.Now()})
	if _, err := v.Verify(ctx, []string{proof}, dpop.Expect{Method: "POST", URLs: []string{tokenURL}}); err != nil {
		t.Fatalf("normalized htu = %v", err)
	}
	// 資源での提示：ath と jkt。
	proof = k.Proof(t, dpoptest.Claims{HTM: "GET", HTU: "https://id.example.com/oauth2/userinfo", IAT: clk.Now(), ATH: dpop.AccessTokenHash("tok")})
	if _, err := v.Verify(ctx, []string{proof}, dpop.Expect{Method: "GET", URLs: []string{"https://id.example.com/oauth2/userinfo"},
		AccessToken: "tok", JKT: k.JKT()}); err != nil {
		t.Fatalf("resource = %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()
	v, clk, k := setup(t)
	other := dpoptest.NewKey(t)
	now := clk.Now()
	base := dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: now}
	with := func(f func(*dpoptest.Claims)) string { c := base; f(&c); return k.Proof(t, c) }
	cases := []struct {
		name    string
		headers []string
		e       dpop.Expect
	}{
		{"none", nil, dpop.Expect{}},
		{"two headers", []string{k.Proof(t, base), k.Proof(t, base)}, dpop.Expect{}},
		{"wrong method", []string{with(func(c *dpoptest.Claims) { c.HTM = "GET" })}, dpop.Expect{}},
		{"wrong url", []string{with(func(c *dpoptest.Claims) { c.HTU = "https://evil.example.com/oauth2/token" })}, dpop.Expect{}},
		{"wrong path", []string{with(func(c *dpoptest.Claims) { c.HTU = "https://id.example.com/oauth2/revoke" })}, dpop.Expect{}},
		{"old iat", []string{with(func(c *dpoptest.Claims) { c.IAT = now.Add(-6 * time.Minute) })}, dpop.Expect{}},
		{"future iat", []string{with(func(c *dpoptest.Claims) { c.IAT = now.Add(time.Minute) })}, dpop.Expect{}},
		{"no jti", []string{with(func(c *dpoptest.Claims) { c.NoJTI = true })}, dpop.Expect{}},
		{"no iat", []string{with(func(c *dpoptest.Claims) { c.NoIAT = true })}, dpop.Expect{}},
		{"wrong typ", []string{with(func(c *dpoptest.Claims) { c.Typ = "JWT" })}, dpop.Expect{}},
		{"private key in header", []string{with(func(c *dpoptest.Claims) { c.EmbedPrivate = true })}, dpop.Expect{}},
		{"other key", []string{k.Proof(t, base)}, dpop.Expect{JKT: other.JKT()}},
		{"ath without token", []string{with(func(c *dpoptest.Claims) { c.ATH = dpop.AccessTokenHash("x") })}, dpop.Expect{}},
		{"missing ath", []string{k.Proof(t, base)}, dpop.Expect{AccessToken: "tok"}},
		{"wrong ath", []string{with(func(c *dpoptest.Claims) { c.ATH = dpop.AccessTokenHash("x") })}, dpop.Expect{AccessToken: "tok"}},
		{"bad signature", []string{tamper(k.Proof(t, base))}, dpop.Expect{}},
		{"alg none", []string{unsigned(base)}, dpop.Expect{}},
		{"small rsa", []string{rsaProof(t, 1024, base)}, dpop.Expect{}},
	}
	for _, tc := range cases {
		e := tc.e
		e.Method, e.URLs = "POST", []string{tokenURL}
		if _, err := v.Verify(ctx, tc.headers, e); !errors.Is(err, dpop.ErrInvalidProof) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	// 2048 bit の RSA は受ける。
	if _, err := v.Verify(ctx, []string{rsaProof(t, 2048, base)}, dpop.Expect{Method: "POST", URLs: []string{tokenURL}}); err != nil {
		t.Fatalf("rsa 2048 = %v", err)
	}
}

func TestNonce(t *testing.T) {
	ctx := context.Background()
	v, clk, k := setup(t)
	v.RequireNonce = true
	e := dpop.Expect{Method: "POST", URLs: []string{tokenURL}}
	if _, err := v.Verify(ctx, []string{k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: clk.Now()})}, e); !errors.Is(err, dpop.ErrUseNonce) {
		t.Fatalf("no nonce = %v", err)
	}
	if _, err := v.Verify(ctx, []string{k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: clk.Now(), Nonce: "made-up"})}, e); !errors.Is(err, dpop.ErrUseNonce) {
		t.Fatalf("unknown nonce = %v", err)
	}
	n, err := v.Nonce(ctx)
	if err != nil || n == "" {
		t.Fatalf("Nonce = %q, %v", n, err)
	}
	if again, _ := v.Nonce(ctx); again != n {
		t.Fatalf("nonce changed early: %q", again)
	}
	if _, err := v.Verify(ctx, []string{k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: clk.Now(), Nonce: n})}, e); err != nil {
		t.Fatalf("with nonce = %v", err)
	}
	// 寿命の半分で新しくなり、寿命を過ぎた nonce は通らない。
	clk.Advance(3 * time.Minute)
	if next, _ := v.Nonce(ctx); next == n {
		t.Fatal("nonce not rotated")
	}
	clk.Advance(3 * time.Minute)
	if _, err := v.Verify(ctx, []string{k.Proof(t, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: clk.Now(), Nonce: n})}, e); !errors.Is(err, dpop.ErrUseNonce) {
		t.Fatalf("expired nonce = %v", err)
	}
}

func TestValidJKT(t *testing.T) {
	k := dpoptest.NewKey(t)
	if !dpop.ValidJKT(k.JKT()) || dpop.ValidJKT("abc") || dpop.ValidJKT(strings.Repeat("*", 43)) {
		t.Fatal("ValidJKT")
	}
}

func tamper(s string) string {
	parts := strings.Split(s, ".")
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["htm"] = "POST"
	m["jti"] = "changed"
	b, _ = json.Marshal(m)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
}

func unsigned(c dpoptest.Claims) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := json.Marshal(jose.JSONWebKey{Key: k.Public()})
	h := `{"alg":"none","typ":"dpop+jwt","jwk":` + string(jwk) + `}`
	p, _ := json.Marshal(map[string]any{"jti": "x", "htm": c.HTM, "htu": c.HTU, "iat": c.IAT.Unix()})
	return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

func rsaProof(t *testing.T, bits int, c dpoptest.Claims) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits) // #nosec G403 -- 小さい鍵を拒むことのテスト
	if err != nil {
		t.Fatal(err)
	}
	return dpoptest.Sign(t, jose.PS256, k, c)
}

func FuzzParse(f *testing.F) {
	k := dpoptest.NewKey(f)
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	f.Add(k.Proof(f, dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: now}))
	f.Add(unsigned(dpoptest.Claims{HTM: "POST", HTU: tokenURL, IAT: now}))
	f.Add("a.b.c")
	f.Add("")
	f.Add(`eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.e30.`)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := dpop.Parse(s)
		if err != nil {
			if !errors.Is(err, dpop.ErrInvalidProof) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if !dpop.ValidJKT(p.JKT) || p.JTI == "" || p.HTM == "" || p.HTU == "" {
			t.Fatalf("accepted incomplete proof: %+v", p)
		}
	})
}
