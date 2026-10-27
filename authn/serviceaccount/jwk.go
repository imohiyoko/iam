package serviceaccount

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/shared/errs"
)

// client assertion の署名方式（ADR 0074）。
const (
	AlgES256   = "ES256"
	AlgEdDSA   = "EdDSA"
	AlgMLDSA65 = "ML-DSA-65"
	maxJWK     = 8 << 10
)

// Algs は private_key_jwt で受け付ける署名方式。
var Algs = []string{AlgES256, AlgEdDSA, AlgMLDSA65}

// ErrInvalidKey は公開鍵が正しくない（秘密の項目を含む、alg と鍵の種類が合わないなど）。
var ErrInvalidKey = errs.WithCode(errs.KindInvalid, "invalid_public_key", "invalid public key")

// publicKey は登録した公開鍵。verifier は go-jose の検証に渡す鍵。
type publicKey struct {
	raw      []byte
	verifier any
}

// ParsePublicKey は private_key_jwt の公開鍵（JWK 1つ）を alg に合わせて確かめる。ES256 は EC の P-256、EdDSA は OKP の Ed25519、
// ML-DSA-65 は AKP（draft-ietf-cose-dilithium）。秘密の項目を持つ鍵は受け付けない。
func ParsePublicKey(b []byte, alg string) (publicKey, error) {
	if len(b) == 0 || len(b) > maxJWK {
		return publicKey{}, ErrInvalidKey
	}
	var head struct {
		Kty, Alg, Pub string
		Priv          *string
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return publicKey{}, ErrInvalidKey
	}
	if head.Alg != "" && head.Alg != alg {
		return publicKey{}, ErrInvalidKey
	}
	var v any
	switch alg {
	case AlgMLDSA65:
		if head.Kty != "AKP" || head.Priv != nil {
			return publicKey{}, ErrInvalidKey
		}
		raw, err := base64.RawURLEncoding.DecodeString(head.Pub)
		if err != nil {
			return publicKey{}, ErrInvalidKey
		}
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
		if err != nil {
			return publicKey{}, ErrInvalidKey
		}
		v = mldsaVerifier{pk}
	case AlgES256, AlgEdDSA:
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(b); err != nil || !k.IsPublic() || !k.Valid() {
			return publicKey{}, ErrInvalidKey
		}
		switch pk := k.Key.(type) {
		case *ecdsa.PublicKey:
			if alg != AlgES256 || pk.Curve != elliptic.P256() {
				return publicKey{}, ErrInvalidKey
			}
		case ed25519.PublicKey:
			if alg != AlgEdDSA {
				return publicKey{}, ErrInvalidKey
			}
		default:
			return publicKey{}, ErrInvalidKey
		}
		v = k.Key
	default:
		return publicKey{}, ErrInvalidKey
	}
	return publicKey{raw: b, verifier: v}, nil
}

// mldsaVerifier は go-jose の OpaqueVerifier に crypto/mldsa を差し込む（ADR 0040。authn/provider と同じ）。
type mldsaVerifier struct{ pub *mldsa.PublicKey }

func (v mldsaVerifier) VerifyPayload(payload, sig []byte, alg jose.SignatureAlgorithm) error {
	if alg != AlgMLDSA65 {
		return jose.ErrUnsupportedAlgorithm
	}
	// JOSE の ML-DSA は純粋な ML-DSA（事前ハッシュなし、空のコンテキスト）。
	if err := mldsa.Verify(v.pub, payload, sig, &mldsa.Options{}); err != nil {
		return errors.New("ml-dsa: invalid signature")
	}
	return nil
}
