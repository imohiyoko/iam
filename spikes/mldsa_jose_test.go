// Package spikes は M0 の前提の検証（スパイク）。結果は ADR 0040、0041 に記録する。
// 本体のモジュールには依存を持ち込まないため、別の Go モジュールにしている。
package spikes

import (
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// AlgMLDSA65 は JOSE のアルゴリズム名（draft-ietf-cose-dilithium / RFC 9964）。
const AlgMLDSA65 jose.SignatureAlgorithm = "ML-DSA-65"

// mldsaSigner は go-jose の OpaqueSigner に crypto/mldsa を差し込む。
type mldsaSigner struct {
	key *mldsa.PrivateKey
}

// Public は nil を返す。go-jose は JSONWebKey.IsPublic が ECDSA / RSA / Ed25519 しか認めないため、
// ML-DSA の公開鍵を JSONWebKey として返すと ErrNotPublic になる（スパイクで判明）。
func (s mldsaSigner) Public() *jose.JSONWebKey        { return nil }
func (s mldsaSigner) Algs() []jose.SignatureAlgorithm { return []jose.SignatureAlgorithm{AlgMLDSA65} }

func (s mldsaSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != AlgMLDSA65 {
		return nil, jose.ErrUnsupportedAlgorithm
	}
	// JOSE の ML-DSA は「純粋な」ML-DSA（事前ハッシュなし、空のコンテキスト）。
	return s.key.Sign(nil, payload, &mldsa.Options{})
}

// mldsaVerifier は go-jose の OpaqueVerifier。
type mldsaVerifier struct{ pub *mldsa.PublicKey }

func (v mldsaVerifier) VerifyPayload(payload, sig []byte, alg jose.SignatureAlgorithm) error {
	if alg != AlgMLDSA65 {
		return jose.ErrUnsupportedAlgorithm
	}
	return mldsa.Verify(v.pub, payload, sig, &mldsa.Options{})
}

func newKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func idTokenClaims() *oidc.IDTokenClaims {
	now := time.Now()
	return oidc.NewIDTokenClaims("https://iam.example", "usr_01JTEST", []string{"cli_01JTEST"},
		now.Add(5*time.Minute), now, "", "", []string{"pwd"}, "cli_01JTEST", 0)
}

func header(t *testing.T, compact string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.SplitN(compact, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// スパイク1：go-jose の OpaqueSigner で ML-DSA-65 の ID トークンを署名・検証できるか。
func TestSpikeMLDSAWithGoJoseOpaqueSigner(t *testing.T) {
	key := newKey(t)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: AlgMLDSA65, Key: mldsaSigner{key}},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "mldsa-1"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.Sign(idTokenClaims(), signer)
	if err != nil {
		t.Fatal(err)
	}
	h := header(t, token)
	if h["alg"] != "ML-DSA-65" || h["kid"] != "mldsa-1" || h["typ"] != "JWT" {
		t.Fatalf("header = %v", h)
	}

	// go-jose で検証（OpaqueVerifier）。
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{AlgMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(mldsaVerifier{key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	var claims oidc.IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject != "usr_01JTEST" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}

	// go-jose を使わず、crypto/mldsa だけで検証（JWS の署名入力は "header.payload"）。
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := mldsa.Verify(key.PublicKey(), []byte(parts[0]+"."+parts[1]), sig, nil); err != nil {
		t.Fatalf("raw verify: %v", err)
	}
	if len(sig) != 3309 {
		t.Fatalf("ML-DSA-65 signature length = %d, want 3309", len(sig))
	}

	// 改ざんを検出する。
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"usr_evil"}`)) + "." + parts[2]
	jws, _ = jose.ParseSigned(tampered, []jose.SignatureAlgorithm{AlgMLDSA65})
	if _, err := jws.Verify(mldsaVerifier{key.PublicKey()}); err == nil {
		t.Fatal("tampered token verified")
	}
}

// zitadel/oidc の OP が使う経路（op.SignerFromKey）でも署名できるか。
// SigningKey.Key() に OpaqueSigner を返すと署名はできるが、kid ヘッダーが付かない。
type opSigningKey struct{ s mldsaSigner }

func (k opSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return AlgMLDSA65 }
func (k opSigningKey) Key() any                                    { return k.s }
func (k opSigningKey) ID() string                                  { return "mldsa-1" }

func TestSpikeMLDSAThroughZitadelSignerFromKey(t *testing.T) {
	key := newKey(t)
	signer, err := op.SignerFromKey(opSigningKey{mldsaSigner{key}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.Sign(idTokenClaims(), signer)
	if err != nil {
		t.Fatal(err)
	}
	h := header(t, token)
	if h["alg"] != "ML-DSA-65" {
		t.Fatalf("alg = %v", h["alg"])
	}
	if _, ok := h["kid"]; ok {
		t.Fatalf("kid unexpectedly present; ADR 0040 の回避策が不要になった可能性: %v", h)
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{AlgMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(mldsaVerifier{key.PublicKey()}); err != nil {
		t.Fatal(err)
	}
}

// OpaqueSigner.Public() に ML-DSA の公開鍵を入れた JSONWebKey を返すと拒否される。
type mldsaSignerWithPublic struct{ mldsaSigner }

func (s mldsaSignerWithPublic) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: s.key.PublicKey(), KeyID: "mldsa-1", Algorithm: string(AlgMLDSA65)}
}

func TestSpikeGoJoseRejectsNonClassicPublicKey(t *testing.T) {
	_, err := jose.NewSigner(jose.SigningKey{Algorithm: AlgMLDSA65, Key: mldsaSignerWithPublic{mldsaSigner{newKey(t)}}}, nil)
	if !errors.Is(err, jose.ErrNotPublic) {
		t.Fatalf("want ErrNotPublic, got %v", err)
	}
}
