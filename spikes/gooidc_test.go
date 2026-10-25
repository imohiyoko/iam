package spikes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// 広く使われる Go の RP ライブラリ（coreos/go-oidc、zitadel/oidc の rp）で、AKP が混ざった JWKS のときに
// ES256 の ID トークンを検証できるか（ADR 0041）。どちらも未知の kty を読み飛ばす。
func TestSpikeRPLibrariesWithMixedJWKS(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: ec, KeyID: "es256-1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.Sign(idTokenClaims(), signer)
	if err != nil {
		t.Fatal(err)
	}
	mixed := buildJWKS(t, newKey(t).PublicKey(), &ec.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mixed)
	}))
	defer srv.Close()

	t.Run("coreos/go-oidc", func(t *testing.T) {
		ks := oidc.NewRemoteKeySet(context.Background(), srv.URL)
		if _, err := ks.VerifySignature(context.Background(), token); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("zitadel/oidc rp", func(t *testing.T) {
		ks := rp.NewRemoteKeySet(srv.Client(), srv.URL)
		jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ks.VerifySignature(context.Background(), jws); err != nil {
			t.Fatal(err)
		}
	})
}
