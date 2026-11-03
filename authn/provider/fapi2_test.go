package provider_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"

	"github.com/imohiyoko/iam/shared/port"
)

// FAPI 2.0 Security Profile の連携先の条件（ADR 0117）。

func jwksOf(t *testing.T, pub any, alg string) []byte {
	t.Helper()
	k, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "" {
		if err := k.Set(jwk.AlgorithmKey, alg); err != nil {
			t.Fatal(err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(k); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fapi2Input は条件を満たす FAPI 2.0 の連携先（private_key_jwt・DPoP）。
func fapi2Input(t *testing.T) provider.ClientInput {
	return provider.ClientInput{Name: "Bank", RedirectURIs: []string{"https://bank.example.com/cb"}, AuthMethod: port.ClientAuthPrivateKeyJWT,
		JWKS: ecJWKS(t, false), DPoPBoundAccessTokens: true, FAPI2: true}
}

func TestFAPI2ClientRegistration(t *testing.T) {
	k := testkit.New(t)
	actor := audit.Actor{Type: "user", ID: "usr_op"}
	on := func() *provider.Clients {
		return &provider.Clients{Clock: k.Clock, FAPI2: true, PAR: true, DPoP: true, MTLS: true, DeviceFlow: true}
	}
	create := func(c *provider.Clients, in provider.ClientInput) (port.Client, error) {
		var cl port.Client
		err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			var err error
			cl, _, err = c.Create(ctx, tx, k.RealmID, in, actor, "req")
			return err
		})
		return cl, err
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 前提のフィーチャーが止まっていれば、プロファイルを入れられない。
	for name, c := range map[string]*provider.Clients{
		"fapi2 off":         {Clock: k.Clock, PAR: true, DPoP: true, MTLS: true},
		"par off":           {Clock: k.Clock, FAPI2: true, DPoP: true, MTLS: true},
		"dpop and mtls off": {Clock: k.Clock, FAPI2: true, PAR: true},
	} {
		if _, err := create(c, fapi2Input(t)); !errors.Is(err, provider.ErrInvalidClient) || !strings.Contains(err.Error(), "feature") {
			t.Errorf("%s: %v", name, err)
		}
	}

	// 条件のどれかが欠ければ拒む。
	for name, edit := range map[string]func(*provider.ClientInput){
		"client_secret": func(in *provider.ClientInput) { in.AuthMethod, in.JWKS = port.ClientAuthSecret, nil },
		"public client": func(in *provider.ClientInput) { in.AuthMethod, in.JWKS = port.ClientAuthNone, nil },
		"no sender constraint": func(in *provider.ClientInput) {
			in.DPoPBoundAccessTokens = false
		},
		"ML-DSA id token":    func(in *provider.ClientInput) { in.IDTokenAlg = port.AlgMLDSA65 },
		"loopback http":      func(in *provider.ClientInput) { in.RedirectURIs = []string{"http://localhost:8080/cb"} },
		"device grant":       func(in *provider.ClientInput) { in.DeviceGrant = true },
		"RSA with RS256":     func(in *provider.ClientInput) { in.JWKS = jwksOf(t, &rsa2048.PublicKey, "RS256") },
		"P-384":              func(in *provider.ClientInput) { in.JWKS = jwksOf(t, &p384.PublicKey, "") },
		"P-256 with ES384":   func(in *provider.ClientInput) { in.JWKS = jwksOf(t, &p256.PublicKey, "ES384") },
		"Ed25519 with ES256": func(in *provider.ClientInput) { in.JWKS = jwksOf(t, edPub, "ES256") },
	} {
		in := fapi2Input(t)
		edit(&in)
		_, err := create(on(), in)
		if !errors.Is(err, provider.ErrInvalidClient) || !strings.Contains(err.Error(), "fapi2_security_profile") {
			t.Errorf("%s: %v", name, err)
		}
	}

	// 満たすもの：private_key_jwt（EC P-256・RSA 2048 の PS256・Ed25519）と DPoP、tls_client_auth と証明書に結び付けたトークン。
	for name, edit := range map[string]func(*provider.ClientInput){
		"ES256":    func(*provider.ClientInput) {},
		"PS256":    func(in *provider.ClientInput) { in.JWKS = jwksOf(t, &rsa2048.PublicKey, "PS256") },
		"EdDSA":    func(in *provider.ClientInput) { in.JWKS = jwksOf(t, edPub, "") },
		"RSA bare": func(in *provider.ClientInput) { in.JWKS = jwksOf(t, &rsa2048.PublicKey, "") },
		"tls_client_auth": func(in *provider.ClientInput) {
			in.AuthMethod, in.JWKS, in.TLSAuthField, in.TLSAuthValue = port.ClientAuthTLS, nil, port.TLSAuthSANDNS, "bank.example.com"
			in.DPoPBoundAccessTokens, in.TLSBoundAccessTokens = false, true
		},
	} {
		in := fapi2Input(t)
		edit(&in)
		cl, err := create(on(), in)
		if err != nil || !cl.FAPI2 {
			t.Errorf("%s: %+v %v", name, cl, err)
		}
	}

	// 登録済みの FAPI 2.0 の連携先は、フィーチャーが止まっても今の値のままなら変えられ、外せる。条件を崩す変更は拒む。
	cl, err := create(on(), fapi2Input(t))
	if err != nil {
		t.Fatal(err)
	}
	update := func(c *provider.Clients, in provider.ClientInput) error {
		return k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			_, _, err := c.Update(ctx, tx, cl, in, actor, "req")
			return err
		})
	}
	in := fapi2Input(t)
	in.Name = "Bank 2"
	if err := update(&provider.Clients{Clock: k.Clock, DPoP: true}, in); err != nil {
		t.Fatalf("keep while off: %v", err)
	}
	in.DPoPBoundAccessTokens = false
	if err := update(on(), in); !errors.Is(err, provider.ErrInvalidClient) {
		t.Fatalf("drop sender constraint: %v", err)
	}
	in.FAPI2 = false
	if err := update(&provider.Clients{Clock: k.Clock, DPoP: true}, in); err != nil {
		t.Fatalf("remove profile: %v", err)
	}

	// realm で強いると、プロファイルを書かない連携先にも条件を求める。
	realm := on()
	realm.RealmFAPI2 = true
	plain := provider.ClientInput{Name: "SPA", RedirectURIs: []string{"https://spa.example.com/cb"}, AuthMethod: port.ClientAuthNone}
	if _, err := create(realm, plain); !errors.Is(err, provider.ErrInvalidClient) {
		t.Fatalf("realm profile, public client: %v", err)
	}
	in = fapi2Input(t)
	in.FAPI2 = false
	if _, err := create(realm, in); err != nil {
		t.Fatalf("realm profile, conforming client: %v", err)
	}
}

func TestFAPI2Assertion(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(alg jwa.SignatureAlgorithm, key any) string {
		tk, _ := jwt.NewBuilder().Issuer("cli").Subject("cli").Expiration(time.Now().Add(time.Minute)).Build()
		b, err := jwt.Sign(tk, jwt.WithKey(alg, key))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for name, c := range map[string]struct {
		assertion string
		ok        bool
	}{
		"ES256":   {sign(jwa.ES256(), ec), true},
		"PS256":   {sign(jwa.PS256(), rk), true},
		"RS256":   {sign(jwa.RS256(), rk), false},
		"garbage": {"a.b.c", false},
	} {
		if provider.FAPI2Assertion(c.assertion) != c.ok {
			t.Errorf("%s: want %v", name, c.ok)
		}
	}
}
