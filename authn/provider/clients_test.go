package provider_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func ecJWKS(t *testing.T, private bool) []byte {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var raw any = &sk.PublicKey
	if private {
		raw = sk
	}
	k, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatal(err)
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

func TestValidRedirectURI(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://app.example.com/cb":      true,
		"http://localhost:8080/cb":        true,
		"http://127.0.0.1/cb":             true,
		"http://app.example.com/cb":       false,
		"https://app.example.com/cb#x":    false,
		"https://u:p@app.example.com/cb":  false,
		"/cb":                             false,
		"javascript:alert(1)":             false,
		"com.example.app:/oauth2redirect": false,
	} {
		if provider.ValidRedirectURI(u) != ok {
			t.Errorf("ValidRedirectURI(%q) != %v", u, ok)
		}
	}
}

func TestClientsLifecycle(t *testing.T) {
	k := testkit.New(t)
	c := &provider.Clients{Clock: k.Clock}
	actor := audit.Actor{Type: "user", ID: "usr_op"}
	in := provider.ClientInput{Name: " App ", RedirectURIs: []string{"https://app.example.com/cb"}, AuthMethod: port.ClientAuthSecret}
	var cl port.Client
	var secret string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		cl, secret, err = c.Create(ctx, tx, k.RealmID, in, actor, "req")
		return err
	})
	if cl.Name != "App" || cl.IDTokenAlg != port.AlgES256 || secret == "" || len(cl.SecretHash) != 32 {
		t.Fatalf("created = %+v, secret %q", cl, secret)
	}
	auth := func(secret string) error {
		return k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			_, err := provider.AuthenticateSecret(ctx, tx, k.RealmID, cl.PublicID, secret)
			return err
		})
	}
	if err := auth(secret); err != nil {
		t.Fatal(err)
	}
	if err := auth(secret + "x"); !errors.Is(err, provider.ErrClientAuth) {
		t.Fatalf("wrong secret: %v", err)
	}
	var rotated string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Clients().Get(ctx, k.RealmID, cl.ID)
		if err != nil {
			return err
		}
		rotated, err = c.RotateSecret(ctx, tx, cur, actor, "req")
		return err
	})
	if err := auth(secret); err == nil {
		t.Fatal("old secret still works")
	}
	if err := auth(rotated); err != nil {
		t.Fatal(err)
	}

	// private_key_jwt には公開鍵だけの JWKS が要る。
	for name, in := range map[string]provider.ClientInput{
		"private jwk":   {Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: port.ClientAuthPrivateKeyJWT, JWKS: ecJWKS(t, true)},
		"no jwks":       {Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: port.ClientAuthPrivateKeyJWT},
		"jwks w/secret": {Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: port.ClientAuthSecret, JWKS: ecJWKS(t, false)},
		"no redirect":   {Name: "x", AuthMethod: port.ClientAuthNone},
		"bad redirect":  {Name: "x", RedirectURIs: []string{"http://a.example/cb"}, AuthMethod: port.ClientAuthNone},
		"bad alg":       {Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: port.ClientAuthNone, IDTokenAlg: "RS256"},
		"bad method":    {Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: "tls_client_auth"},
		"empty name":    {Name: " ", RedirectURIs: []string{"https://a.example/cb"}, AuthMethod: port.ClientAuthNone},
	} {
		err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			_, _, err := c.Create(ctx, tx, k.RealmID, in, actor, "req")
			return err
		})
		if !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Clients().Get(ctx, k.RealmID, cl.ID)
		if err != nil {
			return err
		}
		up, newSecret, err := c.Update(ctx, tx, cur, provider.ClientInput{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"},
			AuthMethod: port.ClientAuthPrivateKeyJWT, JWKS: ecJWKS(t, false), IDTokenAlg: port.AlgMLDSA65}, actor, "req")
		if err != nil {
			return err
		}
		if up.SecretHash != nil || newSecret != "" || up.IDTokenAlg != port.AlgMLDSA65 {
			t.Fatalf("updated = %+v", up)
		}
		return c.Delete(ctx, tx, up, actor, "req")
	})
	if err := auth(rotated); !errors.Is(err, provider.ErrClientAuth) {
		t.Fatalf("deleted client auth: %v", err)
	}
}
