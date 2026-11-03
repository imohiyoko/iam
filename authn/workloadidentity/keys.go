package workloadidentity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
)

// 発行者の鍵（JWKS）の読み取りと選び方（ADR 0116）。

// Algorithms は受け付ける署名の方式。none・HS*（対称鍵）は含めない。
var Algorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}

// DefaultAlgorithms は発行者の algorithms を省いたときの方式。
var DefaultAlgorithms = []string{string(jose.RS256), string(jose.ES256)}

// 鍵の上限。
const (
	maxKeys       = 100
	minRSAKeyBits = 2048
)

// allowedAlg は alg が受け付ける方式かを返す。
func allowedAlg(alg string) bool {
	return slices.Contains(Algorithms, jose.SignatureAlgorithm(alg))
}

// parseKeySet は JWKS を読み、署名の検証に使える公開鍵だけを返す。strict（登録する固定の JWKS）なら、読めない鍵・秘密鍵・
// 対称鍵・使えない鍵があれば誤りにする。そうでなければ（取得した JWKS）、使えないものを飛ばす。
func parseKeySet(b []byte, strict bool) ([]jose.JSONWebKey, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, invalidProvider("jwks must be a JSON Web Key Set")
	}
	if len(raw.Keys) > maxKeys {
		return nil, invalidProvider("jwks has too many keys")
	}
	var out []jose.JSONWebKey
	for _, r := range raw.Keys {
		var k jose.JSONWebKey
		if err := json.Unmarshal(r, &k); err != nil {
			if strict {
				return nil, invalidProvider("jwks has a key that cannot be read")
			}
			continue
		}
		if !k.IsPublic() {
			if strict {
				return nil, invalidProvider("jwks must contain only public keys")
			}
			if _, ok := k.Key.([]byte); ok {
				continue
			}
			k = k.Public()
		}
		if !k.Valid() || (k.Use != "" && k.Use != "sig") || !usableKey(k) {
			if strict {
				return nil, invalidProvider("jwks has a key that cannot verify signatures (RSA of 2048 bits or more, EC P-256/384/521, Ed25519)")
			}
			continue
		}
		if k.Algorithm != "" && !allowedAlg(k.Algorithm) {
			if strict {
				return nil, invalidProvider("jwks has a key with an unsupported alg")
			}
			continue
		}
		out = append(out, k)
	}
	if len(out) == 0 && strict {
		return nil, invalidProvider("jwks has no usable keys")
	}
	return out, nil
}

// usableKey は鍵の種類と大きさが署名の検証に使えるか（どれかの alg に合うか）を返す。
func usableKey(k jose.JSONWebKey) bool {
	switch pk := k.Key.(type) {
	case *rsa.PublicKey:
		return pk.N != nil && pk.N.BitLen() >= minRSAKeyBits
	case *ecdsa.PublicKey:
		return pk.Curve == elliptic.P256() || pk.Curve == elliptic.P384() || pk.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return len(pk) == ed25519.PublicKeySize
	}
	return false
}

// keyFits は鍵が alg で使えるかを返す（鍵の alg があれば一致、種類と曲線が alg に合う）。
func keyFits(k jose.JSONWebKey, alg string) bool {
	if k.Algorithm != "" && k.Algorithm != alg {
		return false
	}
	switch pk := k.Key.(type) {
	case *rsa.PublicKey:
		switch jose.SignatureAlgorithm(alg) {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return pk.N != nil && pk.N.BitLen() >= minRSAKeyBits
		}
	case *ecdsa.PublicKey:
		switch jose.SignatureAlgorithm(alg) {
		case jose.ES256:
			return pk.Curve == elliptic.P256()
		case jose.ES384:
			return pk.Curve == elliptic.P384()
		case jose.ES512:
			return pk.Curve == elliptic.P521()
		}
	case ed25519.PublicKey:
		return jose.SignatureAlgorithm(alg) == jose.EdDSA
	}
	return false
}

// candidates は kid と alg に合う鍵を返す。kid が空なら alg に合う全ての鍵。
func candidates(keys []jose.JSONWebKey, kid, alg string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, k := range keys {
		if (kid == "" || k.KeyID == kid) && keyFits(k, alg) {
			out = append(out, k)
		}
	}
	return out
}
