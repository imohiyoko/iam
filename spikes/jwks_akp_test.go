package spikes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// buildJWKS は ML-DSA-65 と ES256 の公開鍵を含む JWKS を jwx で組み立てる（design.md 9.3）。
func buildJWKS(t *testing.T, ml *mldsa.PublicKey, ec *ecdsa.PublicKey) []byte {
	t.Helper()
	set := jwk.NewSet()
	mk, err := jwk.Import[jwk.Key](ml)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := jwk.Import[jwk.Key](ec)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range []struct {
		k   jwk.Key
		kid string
		alg string
	}{{mk, "mldsa-1", ""}, {ek, "es256-1", "ES256"}} {
		if err := kv.k.Set(jwk.KeyIDKey, kv.kid); err != nil {
			t.Fatal(err)
		}
		if err := kv.k.Set(jwk.KeyUsageKey, "sig"); err != nil {
			t.Fatal(err)
		}
		if kv.alg != "" {
			if err := kv.k.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
				t.Fatal(err)
			}
		}
		if err := set.AddKey(kv.k); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signMLDSA(t *testing.T, key *mldsa.PrivateKey) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: AlgMLDSA65, Key: mldsaSigner{key}},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "mldsa-1"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.Sign(idTokenClaims(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// スパイク2：jwx で AKP 鍵を含む JWKS を出力し、ほかの実装で読めるか。
func TestSpikeJWKSWithAKP(t *testing.T) {
	ml := newKey(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := buildJWKS(t, ml.PublicKey(), &ec.PublicKey)
	t.Logf("JWKS size: %d bytes", len(raw))

	// 1. 形式が RFC 9964 / 9802 どおりか（kty=AKP, alg=ML-DSA-65, pub=base64url の公開鍵）。
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var akp map[string]any
	for _, k := range doc.Keys {
		if k["kid"] == "mldsa-1" {
			akp = k
		}
	}
	if akp["kty"] != "AKP" || akp["alg"] != "ML-DSA-65" || akp["use"] != "sig" {
		t.Fatalf("AKP JWK = %v", akp)
	}
	if _, hasPriv := akp["priv"]; hasPriv {
		t.Fatal("private key leaked into JWKS")
	}

	// 2. ほかの実装（ライブラリを使わない素の JSON + crypto/mldsa）で読み、go-jose で作った ID トークンを検証できる。
	pub, err := base64.RawURLEncoding.DecodeString(akp["pub"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
	if err != nil {
		t.Fatal(err)
	}
	token := signMLDSA(t, ml)
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := mldsa.Verify(pk, []byte(parts[0]+"."+parts[1]), sig, nil); err != nil {
		t.Fatalf("verify with key from JWKS: %v", err)
	}

	// 3. jwx 自身で JWKS を読み直し、go-jose で作ったトークンを検証できる（相互運用）。
	set, err := jwk.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify([]byte(token), jws.WithKeySet(set)); err != nil {
		t.Fatalf("jwx verify: %v", err)
	}

	// 4. go-jose（zitadel/oidc の RP が使う）で、AKP を含む JWKS を読めるか。
	//    ES256 だけを使う既存の RP が、JWKS に AKP が混ざっても壊れないことが重要。
	//    結果：go-jose v4.1.6 は未知の kty を含む JWKS 全体の読み込みを失敗させる。
	//    この結果が変わったら ADR 0041 を見直す。
	var gj jose.JSONWebKeySet
	err = json.Unmarshal(raw, &gj)
	t.Logf("go-jose JSONWebKeySet unmarshal: err=%v", err)
	if err == nil {
		t.Fatal("go-jose now accepts JWKS with AKP keys; revisit ADR 0041")
	}

	// 5. ES256 だけの JWKS なら go-jose で読める（分けて配る回避策の確認）。
	esOnly := buildJWKSOnly(t, &ec.PublicKey)
	if err := json.Unmarshal(esOnly, &gj); err != nil || len(gj.Key("es256-1")) != 1 {
		t.Fatalf("ES256-only JWKS: %v", err)
	}
}

func buildJWKSOnly(t *testing.T, ec *ecdsa.PublicKey) []byte {
	t.Helper()
	set := jwk.NewSet()
	k, err := jwk.Import[jwk.Key](ec)
	if err != nil {
		t.Fatal(err)
	}
	k.Set(jwk.KeyIDKey, "es256-1")
	k.Set(jwk.AlgorithmKey, jwa.ES256())
	set.AddKey(k)
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
