package workloadidentity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/imohiyoko/iam/authn/workloadidentity"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

const testIssuer = "https://token.actions.example.com"

var (
	ecKey  = mustEC()
	rsaKey = mustRSA()
	other  = mustEC()
)

func mustEC() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func jwks(keys ...jose.JSONWebKey) json.RawMessage {
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		panic(err)
	}
	return b
}

func pub(k any, kid, alg string) jose.JSONWebKey {
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: alg, Use: "sig"}
	case *rsa.PrivateKey:
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: alg, Use: "sig"}
	}
	panic("key")
}

// sign は claims を署名した JWT にする。
func sign(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// claims は GitHub Actions に似たクレーム。
func claims(now time.Time) map[string]any {
	return map[string]any{"iss": testIssuer, "aud": "https://iam.example.com", "sub": "repo:acme/app:ref:refs/heads/main",
		"repository": "acme/app", "ref": "refs/heads/main", "repository_owner_id": "42", "jti": id.NewExternal(id.SAToken),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{"namespace": "prod"}}
}

type env struct {
	k   *testkit.Kit
	svc *workloadidentity.Service
	sa  port.ServiceAccount
	p   port.WorkloadIdentityProvider
}

func newEnv(t *testing.T, cfg workloadidentity.Config) *env {
	t.Helper()
	k := testkit.New(t)
	e := &env{k: k, svc: &workloadidentity.Service{Storage: k.Storage, Cache: k.Cache, Clock: k.Clock}}
	e.sa = port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: k.RealmID, Name: "ci", CreatedAt: testkit.T0}
	if cfg.Audiences == nil {
		cfg.Audiences = []string{"https://iam.example.com"}
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.ServiceAccounts().Create(ctx, e.sa); err != nil {
			return err
		}
		var err error
		e.p, err = e.svc.CreateProvider(ctx, tx, k.RealmID, workloadidentity.ProviderInput{Name: "GitHub", Issuer: testIssuer, Config: cfg},
			audit.Actor{Type: "test"}, "")
		return err
	})
	return e
}

func (e *env) bind(t *testing.T, saID, conds string) port.WorkloadIdentityBinding {
	t.Helper()
	var b port.WorkloadIdentityBinding
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		b, err = e.svc.CreateBinding(ctx, tx, e.p, saID, []byte(conds), audit.Actor{Type: "test"}, "")
		return err
	})
	return b
}

const repoMain = `[{"claim":"/repository","equals":"acme/app"},{"claim":"/ref","in":["refs/heads/main","refs/heads/release"]}]`

func (e *env) verify(token, accountID string) (workloadidentity.Identity, error) {
	return e.svc.Verify(context.Background(), e.k.RealmID, token, accountID, "")
}

func wantInvalid(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, workloadidentity.ErrInvalidGrant) {
		t.Fatalf("%s: want ErrInvalidGrant, got %v", what, err)
	}
}

func TestVerifyStaticJWKS(t *testing.T) {
	e := newEnv(t, workloadidentity.Config{JWKS: jwks(pub(ecKey, "k1", "ES256"), pub(rsaKey, "r1", "RS256"))})
	b := e.bind(t, e.sa.ID, repoMain)
	now := e.k.Clock.Now()
	for _, tc := range []struct {
		name string
		key  any
		alg  jose.SignatureAlgorithm
		kid  string
	}{{"es256", ecKey, jose.ES256, "k1"}, {"rs256", rsaKey, jose.RS256, "r1"}, {"no kid", ecKey, jose.ES256, ""}} {
		got, err := e.verify(sign(t, tc.key, tc.alg, tc.kid, claims(now)), "")
		if err != nil || got.BindingID != b.ID || got.AccountID != e.sa.ID || got.Subject != "repo:acme/app:ref:refs/heads/main" {
			t.Fatalf("%s: %+v, %v", tc.name, got, err)
		}
	}
	// client_id で選ぶ。
	if _, err := e.verify(sign(t, ecKey, jose.ES256, "k1", claims(now)), e.sa.ID); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	e := newEnv(t, workloadidentity.Config{JWKS: jwks(pub(ecKey, "k1", "ES256"), pub(rsaKey, "r1", "RS256"))})
	e.bind(t, e.sa.ID, repoMain)
	now := e.k.Clock.Now()
	mod := func(f func(c map[string]any)) map[string]any {
		c := claims(now)
		f(c)
		return c
	}
	cases := map[string]string{
		"wrong aud":           sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["aud"] = "https://other.example" })),
		"wrong issuer":        sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"issuer trailing /":   sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["iss"] = testIssuer + "/" })),
		"expired":             sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() })),
		"not yet valid":       sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() })),
		"iat in future":       sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["iat"] = now.Add(5 * time.Minute).Unix() })),
		"no exp":              sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { delete(c, "exp") })),
		"no iat":              sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { delete(c, "iat") })),
		"too long lifetime":   sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["exp"] = now.Add(2 * time.Hour).Unix() })),
		"unmatched repo":      sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["repository"] = "acme/app2" })),
		"unmatched ref":       sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["ref"] = "refs/heads/dev" })),
		"repo not a string":   sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { c["repository"] = []string{"acme/app"} })),
		"missing claim":       sign(t, ecKey, jose.ES256, "k1", mod(func(c map[string]any) { delete(c, "ref") })),
		"untrusted key":       sign(t, other, jose.ES256, "k1", claims(now)),
		"untrusted key nokid": sign(t, other, jose.ES256, "", claims(now)),
		"unknown kid":         sign(t, ecKey, jose.ES256, "k9", claims(now)),
		"alg not allowed":     sign(t, rsaKey, jose.PS256, "r1", claims(now)),
		"hs256":               sign(t, []byte(strings.Repeat("k", 32)), jose.HS256, "k1", claims(now)),
		"garbage":             "a.b.c",
		"empty":               "",
		"too large":           strings.Repeat("a", workloadidentity.MaxSubjectToken+1),
	}
	// alg none（署名なし）は解析の時点で拒む。
	hdr := `{"alg":"none","typ":"JWT"}`
	body, _ := json.Marshal(claims(now))
	cases["alg none"] = b64(hdr) + "." + b64(string(body)) + "."
	// 署名を外したもの。
	parts := strings.Split(sign(t, ecKey, jose.ES256, "k1", claims(now)), ".")
	cases["stripped signature"] = parts[0] + "." + parts[1] + "."
	// 署名のあと本文を差し替えたもの。
	evil := claims(now)
	evil["repository"] = "acme/app"
	evil["sub"] = "attacker"
	eb, _ := json.Marshal(evil)
	cases["tampered payload"] = parts[0] + "." + b64(string(eb)) + "." + parts[2]
	for name, tok := range cases {
		_, err := e.verify(tok, "")
		wantInvalid(t, name, err)
	}
	// 別のサービスアカウントを client_id に指定すると通らない。
	_, err := e.verify(sign(t, ecKey, jose.ES256, "k1", claims(now)), id.NewExternal(id.ServiceAccount))
	wantInvalid(t, "other client_id", err)
	_, err = e.verify(sign(t, ecKey, jose.ES256, "k1", claims(now)), "not-an-id")
	wantInvalid(t, "malformed client_id", err)
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestVerifyReplayAndAmbiguous(t *testing.T) {
	e := newEnv(t, workloadidentity.Config{JWKS: jwks(pub(ecKey, "k1", "ES256"))})
	e.bind(t, e.sa.ID, repoMain)
	now := e.k.Clock.Now()
	tok := sign(t, ecKey, jose.ES256, "k1", claims(now))
	if _, err := e.verify(tok, ""); err != nil {
		t.Fatal(err)
	}
	_, err := e.verify(tok, "")
	wantInvalid(t, "replay", err)
	// jti の無いトークンは繰り返し受ける。
	c := claims(now)
	delete(c, "jti")
	noJTI := sign(t, ecKey, jose.ES256, "k1", c)
	for range 2 {
		if _, err := e.verify(noJTI, ""); err != nil {
			t.Fatal(err)
		}
	}
	// 2 つのサービスアカウントに当たれば client_id が要る。
	sa2 := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: e.k.RealmID, Name: "ci2", CreatedAt: testkit.T0}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.ServiceAccounts().Create(ctx, sa2) })
	b2 := e.bind(t, sa2.ID, `[{"claim":"/sub","prefix":"repo:acme/"}]`)
	_, err = e.verify(noJTI, "")
	wantInvalid(t, "ambiguous", err)
	got, err := e.verify(noJTI, sa2.ID)
	if err != nil || got.BindingID != b2.ID {
		t.Fatalf("select by client_id = %+v, %v", got, err)
	}
	// 拒んだ交換は監査ログに残る。
	n := 0
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		evs, err := tx.Audit().ListByRealm(ctx, e.k.RealmID, 0, 100)
		for _, ev := range evs {
			if strings.Contains(string(ev.Payload), `"workload_identity.exchange_denied"`) {
				n++
			}
		}
		return err
	})
	if n != 2 {
		t.Fatalf("exchange_denied events = %d, want 2 (replay, ambiguous)", n)
	}
}

func TestVerifyDisabledAndBindingLive(t *testing.T) {
	e := newEnv(t, workloadidentity.Config{JWKS: jwks(pub(ecKey, "k1", "ES256"))})
	b := e.bind(t, e.sa.ID, repoMain)
	ctx := context.Background()
	live := func() bool {
		var ok bool
		e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			var err error
			_, ok, err = e.svc.BindingLive(ctx, tx, e.k.RealmID, b.ID)
			return err
		})
		return ok
	}
	if !live() {
		t.Fatal("binding should be live")
	}
	cfg, err := workloadidentity.ParseConfig(e.p.Config)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.svc.UpdateProvider(ctx, tx, e.p, workloadidentity.ProviderInput{Name: "GitHub", Issuer: testIssuer, Disabled: true, Config: cfg},
			audit.Actor{Type: "test"}, "")
		return err
	})
	if live() {
		t.Fatal("binding of a disabled provider should not be live")
	}
	_, err = e.svc.Verify(ctx, e.k.RealmID, sign(t, ecKey, jose.ES256, "k1", claims(e.k.Clock.Now())), "", "")
	wantInvalid(t, "disabled provider", err)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return e.svc.DeleteProvider(ctx, tx, e.p, audit.Actor{Type: "test"}, "")
	})
	if live() {
		t.Fatal("binding of a deleted provider should not be live")
	}
}

func TestRemoteJWKS(t *testing.T) {
	var discovery, keysFetched atomic.Int32
	keys := jwks(pub(ecKey, "k1", "ES256"))
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			keysFetched.Add(1)
			_, _ = w.Write(keys)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := testkit.New(t)
	svc := &workloadidentity.Service{Storage: k.Storage, Cache: k.Cache, Clock: k.Clock, HTTP: srv.Client()}
	sa := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: k.RealmID, Name: "ci", CreatedAt: testkit.T0}
	var p port.WorkloadIdentityProvider
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.ServiceAccounts().Create(ctx, sa); err != nil {
			return err
		}
		var err error
		p, err = svc.CreateProvider(ctx, tx, k.RealmID, workloadidentity.ProviderInput{Name: "k8s", Issuer: srv.URL,
			Config: workloadidentity.Config{Audiences: []string{"iam"}}}, audit.Actor{Type: "test"}, "")
		if err != nil {
			return err
		}
		_, err = svc.CreateBinding(ctx, tx, p, sa.ID, []byte(`[{"claim":"/kubernetes.io/namespace","equals":"prod"}]`), audit.Actor{Type: "test"}, "")
		return err
	})
	now := k.Clock.Now()
	c := func() map[string]any {
		c := claims(now)
		c["iss"], c["aud"] = srv.URL, []string{"x", "iam"}
		delete(c, "jti")
		return c
	}
	ctx := context.Background()
	for range 3 {
		if _, err := svc.Verify(ctx, k.RealmID, sign(t, ecKey, jose.ES256, "k1", c()), "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if discovery.Load() != 1 || keysFetched.Load() != 1 {
		t.Fatalf("fetches = %d/%d, want the JWKS cached", discovery.Load(), keysFetched.Load())
	}
	// 鍵の入れ替え：知らない kid なら取得し直す。
	keys = jwks(pub(ecKey, "k1", "ES256"), pub(rsaKey, "r2", "RS256"))
	if _, err := svc.Verify(ctx, k.RealmID, sign(t, rsaKey, jose.RS256, "r2", c()), "", ""); err != nil {
		t.Fatal(err)
	}
	if keysFetched.Load() != 2 {
		t.Fatalf("keys fetched = %d, want a refresh for the new kid", keysFetched.Load())
	}
	// 知らない kid を繰り返しても、取得は発行者ごとに 1 分に 5 回まで。
	for range 10 {
		_, err := svc.Verify(ctx, k.RealmID, sign(t, other, jose.ES256, "nope", c()), "", "")
		wantInvalid(t, "unknown kid", err)
	}
	if n := keysFetched.Load(); n > 5 {
		t.Fatalf("keys fetched = %d, want at most 5 per minute", n)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL + "/other", "jwks_uri": srv.URL + "/keys"})
	}))
	defer srv.Close()
	k := testkit.New(t)
	svc := &workloadidentity.Service{Storage: k.Storage, Cache: k.Cache, Clock: k.Clock, HTTP: srv.Client()}
	sa := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: k.RealmID, Name: "ci", CreatedAt: testkit.T0}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.ServiceAccounts().Create(ctx, sa); err != nil {
			return err
		}
		p, err := svc.CreateProvider(ctx, tx, k.RealmID, workloadidentity.ProviderInput{Name: "x", Issuer: srv.URL,
			Config: workloadidentity.Config{Audiences: []string{"iam"}}}, audit.Actor{Type: "test"}, "")
		if err != nil {
			return err
		}
		_, err = svc.CreateBinding(ctx, tx, p, sa.ID, []byte(`[{"claim":"/sub","prefix":"repo:"}]`), audit.Actor{Type: "test"}, "")
		return err
	})
	c := claims(k.Clock.Now())
	c["iss"], c["aud"] = srv.URL, "iam"
	_, err := svc.Verify(context.Background(), k.RealmID, sign(t, ecKey, jose.ES256, "k1", c), "", "")
	wantInvalid(t, "discovery issuer mismatch", err)
}

// 既定のクライアントは公開でないアドレス（ループバックのテストサーバー）につながない（SSRF）。
func TestGuardedClientRefusesPrivate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the guarded client must not reach a loopback address")
	}))
	defer srv.Close()
	k := testkit.New(t)
	svc := &workloadidentity.Service{Storage: k.Storage, Cache: k.Cache, Clock: k.Clock}
	sa := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: k.RealmID, Name: "ci", CreatedAt: testkit.T0}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.ServiceAccounts().Create(ctx, sa); err != nil {
			return err
		}
		p, err := svc.CreateProvider(ctx, tx, k.RealmID, workloadidentity.ProviderInput{Name: "x", Issuer: srv.URL,
			Config: workloadidentity.Config{Audiences: []string{"iam"}}}, audit.Actor{Type: "test"}, "")
		if err != nil {
			return err
		}
		_, err = svc.CreateBinding(ctx, tx, p, sa.ID, []byte(`[{"claim":"/sub","prefix":"repo:"}]`), audit.Actor{Type: "test"}, "")
		return err
	})
	c := claims(k.Clock.Now())
	c["iss"], c["aud"] = srv.URL, "iam"
	_, err := svc.Verify(context.Background(), k.RealmID, sign(t, ecKey, jose.ES256, "k1", c), "", "")
	wantInvalid(t, "private address", err)
}

func TestValidateProvider(t *testing.T) {
	ok := workloadidentity.ProviderInput{Name: "x", Issuer: testIssuer, Config: workloadidentity.Config{Audiences: []string{"a", "a"}}}
	got, err := workloadidentity.ValidateProvider(ok)
	if err != nil || len(got.Audiences) != 1 || got.MaxTokenLifetime != 3600 || strings.Join(got.Algorithms, ",") != "RS256,ES256" {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
	priv, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: ecKey, KeyID: "p"}}})
	sym, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "s"}}})
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	weak := jwks(jose.JSONWebKey{Key: &small.PublicKey, KeyID: "w"})
	bad := map[string]func(in *workloadidentity.ProviderInput){
		"no name":         func(in *workloadidentity.ProviderInput) { in.Name = " " },
		"http issuer":     func(in *workloadidentity.ProviderInput) { in.Issuer = "http://x.example" },
		"issuer query":    func(in *workloadidentity.ProviderInput) { in.Issuer = testIssuer + "?a=1" },
		"issuer fragment": func(in *workloadidentity.ProviderInput) { in.Issuer = testIssuer + "#a" },
		"issuer userinfo": func(in *workloadidentity.ProviderInput) { in.Issuer = "https://u:p@x.example" },
		"no audience":     func(in *workloadidentity.ProviderInput) { in.Audiences = nil },
		"empty audience":  func(in *workloadidentity.ProviderInput) { in.Audiences = []string{""} },
		"alg none":        func(in *workloadidentity.ProviderInput) { in.Algorithms = []string{"none"} },
		"alg hs256":       func(in *workloadidentity.ProviderInput) { in.Algorithms = []string{"HS256"} },
		"lifetime small":  func(in *workloadidentity.ProviderInput) { in.MaxTokenLifetime = 10 },
		"lifetime large":  func(in *workloadidentity.ProviderInput) { in.MaxTokenLifetime = 86401 },
		"both keys": func(in *workloadidentity.ProviderInput) {
			in.JWKSURI, in.JWKS = testIssuer+"/keys", jwks(pub(ecKey, "k", "ES256"))
		},
		"http jwks_uri":    func(in *workloadidentity.ProviderInput) { in.JWKSURI = "http://x.example/keys" },
		"private jwk":      func(in *workloadidentity.ProviderInput) { in.JWKS = priv },
		"symmetric jwk":    func(in *workloadidentity.ProviderInput) { in.JWKS = sym },
		"weak rsa":         func(in *workloadidentity.ProviderInput) { in.JWKS = weak },
		"empty jwks":       func(in *workloadidentity.ProviderInput) { in.JWKS = json.RawMessage(`{"keys":[]}`) },
		"not jwks":         func(in *workloadidentity.ProviderInput) { in.JWKS = json.RawMessage(`[1]`) },
		"enc jwk":          func(in *workloadidentity.ProviderInput) { k := pub(ecKey, "e", ""); k.Use = "enc"; in.JWKS = jwks(k) },
		"key alg mismatch": func(in *workloadidentity.ProviderInput) { in.JWKS = jwks(pub(ecKey, "k", "HS256")) },
	}
	for name, f := range bad {
		in := ok
		in.Config.Audiences = []string{"a"}
		f(&in)
		if _, err := workloadidentity.ValidateProvider(in); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: want invalid, got %v", name, err)
		}
	}
}

func TestProviderCRUDAndBindings(t *testing.T) {
	e := newEnv(t, workloadidentity.Config{JWKS: jwks(pub(ecKey, "k1", "ES256"))})
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.svc.CreateProvider(ctx, tx, e.k.RealmID, workloadidentity.ProviderInput{Name: "dup", Issuer: testIssuer,
			Config: workloadidentity.Config{Audiences: []string{"a"}}}, audit.Actor{Type: "test"}, "")
		if !errors.Is(err, errs.Conflict) {
			t.Errorf("duplicate issuer: %v", err)
		}
		for _, c := range []string{`[]`, `{}`, `[{"claim":"/a"}]`, `[{"claim":"a","equals":"x"}]`, `[{"claim":"/a","equals":"x","prefix":"y"}]`,
			`[{"claim":"/a","equals":""}]`, `[{"claim":"/a","in":[]}]`, `[{"claim":"/a","prefix":""}]`, `[{"claim":"/a","regex":"x"}]`,
			`[{"claim":"/a~2","equals":"x"}]`, `[{"claim":"//a","equals":"x"}]`, `[{"claim":"/a","equals":"x"}] []`} {
			if _, err := e.svc.CreateBinding(ctx, tx, e.p, e.sa.ID, []byte(c), audit.Actor{Type: "test"}, ""); !errors.Is(err, errs.Invalid) {
				t.Errorf("conditions %s: want invalid, got %v", c, err)
			}
		}
		for range workloadidentity.MaxBindings {
			if _, err := e.svc.CreateBinding(ctx, tx, e.p, e.sa.ID, []byte(`[{"claim":"/sub","equals":"x"}]`), audit.Actor{Type: "test"}, ""); err != nil {
				return err
			}
		}
		_, err = e.svc.CreateBinding(ctx, tx, e.p, e.sa.ID, []byte(`[{"claim":"/sub","equals":"x"}]`), audit.Actor{Type: "test"}, "")
		if !errors.Is(err, errs.Conflict) {
			t.Errorf("too many bindings: %v", err)
		}
		return nil
	})
}
