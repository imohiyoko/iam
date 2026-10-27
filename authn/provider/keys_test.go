package provider_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/port"
)

func TestKeysSignVerifyAndRotate(t *testing.T) {
	k := testkit.New(t)
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	ctx := context.Background()
	jwks := func() []map[string]any {
		var doc struct {
			Keys []map[string]any `json:"keys"`
		}
		k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			b, err := keys.JWKS(ctx, tx, k.RealmID)
			if err != nil {
				return err
			}
			return json.Unmarshal(b, &doc)
		})
		return doc.Keys
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return keys.Ensure(ctx, tx, k.RealmID) })
	ks := jwks()
	if len(ks) != 2 {
		t.Fatalf("jwks = %v", ks)
	}
	types := map[string]bool{}
	for _, x := range ks {
		types[x["kty"].(string)] = true
		if _, ok := x["d"]; ok {
			t.Fatal("private key in JWKS")
		}
		if _, ok := x["priv"]; ok {
			t.Fatal("private key in JWKS")
		}
	}
	if !types["AKP"] || !types["EC"] {
		t.Fatalf("kty = %v", types)
	}

	tokens := map[string]string{}
	for _, alg := range provider.Algs {
		k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			jws, err := keys.Sign(ctx, tx, k.RealmID, alg, "JWT", []byte(`{"sub":"x"}`))
			tokens[alg] = jws
			return err
		})
	}
	verify := func(jws string) error {
		return k.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			b, err := keys.Verify(ctx, tx, k.RealmID, jws)
			if err == nil && string(b) != `{"sub":"x"}` {
				t.Fatalf("payload = %s", b)
			}
			return err
		})
	}
	for alg, jws := range tokens {
		if err := verify(jws); err != nil {
			t.Fatalf("%s verify: %v", alg, err)
		}
		parts := strings.Split(jws, ".")
		if err := verify(parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"); err == nil {
			t.Fatalf("%s tampered verified", alg)
		}
	}

	// ローテーションの後も古い鍵の署名は RetiredKeyTTL の間検証でき、その後は JWKS から消える。
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := keys.Rotate(ctx, tx, k.RealmID, port.AlgMLDSA65)
		return err
	})
	if n := len(jwks()); n != 3 {
		t.Fatalf("jwks after rotate = %d keys", n)
	}
	if err := verify(tokens[port.AlgMLDSA65]); err != nil {
		t.Fatalf("old key verify: %v", err)
	}
	k.Clock.Advance(24 * time.Hour)
	if n := len(jwks()); n != 2 {
		t.Fatalf("jwks after ttl = %d keys", n)
	}
	if err := verify(tokens[port.AlgMLDSA65]); err == nil {
		t.Fatal("expired key still verifies")
	}
}
