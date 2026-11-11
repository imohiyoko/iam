package provider_test

import (
	"context"
	"encoding/json"
	"slices"
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

// TestKeysVerifyType は typ の違う JWS（Logout Token）を ID トークンとして受け付けないことを確かめる（Token Exchange。ADR 0099）。
func TestKeysVerifyType(t *testing.T) {
	k := testkit.New(t)
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for _, alg := range provider.Algs {
			logout, err := keys.Sign(ctx, tx, k.RealmID, alg, "logout+jwt", []byte(`{"sub":"x"}`))
			if err != nil {
				return err
			}
			if _, err := keys.VerifyType(ctx, tx, k.RealmID, logout, "JWT"); err == nil {
				t.Fatalf("%s: logout token accepted as JWT", alg)
			}
			idt, err := keys.Sign(ctx, tx, k.RealmID, alg, "JWT", []byte(`{"sub":"x"}`))
			if err != nil {
				return err
			}
			if b, err := keys.VerifyType(ctx, tx, k.RealmID, idt, "JWT"); err != nil || !strings.Contains(string(b), `"sub"`) {
				t.Fatalf("%s: id token = %s, %v", alg, b, err)
			}
		}
		return nil
	})
}

// TestKeysRS256 はフィーチャー rs256 の鍵（ADR 0122）を確かめる：オフなら用意せず、オンなら JWKS に RSA を alg 付きで出し、
// 署名と検証が通り、書き換えた署名は通らない。
func TestKeysRS256(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	off := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	if slices.Contains(off.Algs(), port.AlgRS256) {
		t.Fatalf("algs while off: %v", off.Algs())
	}
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour, RS256: true}
	var jws string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := keys.Ensure(ctx, tx, k.RealmID); err != nil {
			return err
		}
		b, err := keys.JWKS(ctx, tx, k.RealmID)
		if err != nil {
			return err
		}
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(b, &set); err != nil {
			return err
		}
		found := false
		for _, x := range set.Keys {
			if x["kty"] == "RSA" {
				found = x["alg"] == "RS256" && x["d"] == nil
			}
		}
		if !found || len(set.Keys) != 3 {
			t.Fatalf("jwks = %s", b)
		}
		jws, err = keys.Sign(ctx, tx, k.RealmID, port.AlgRS256, "JWT", []byte(`{"sub":"x"}`))
		return err
	})
	err := k.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if b, err := keys.VerifyType(ctx, tx, k.RealmID, jws, "JWT"); err != nil || string(b) != `{"sub":"x"}` {
			t.Fatalf("verify = %s, %v", b, err)
		}
		parts := strings.Split(jws, ".")
		if _, err := keys.Verify(ctx, tx, k.RealmID, parts[0]+"."+parts[1]+"."+parts[2][:len(parts[2])-4]+"AAAA"); err == nil {
			t.Fatal("tampered verified")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
