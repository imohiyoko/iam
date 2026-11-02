package push

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// 端末の鍵の種類。
const (
	AlgES256   = "es256"
	AlgEd25519 = "ed25519"
)

// maxKeySize は公開鍵（SubjectPublicKeyInfo の DER）の大きさの上限。
const maxKeySize = 256

// maxSignatureSize は署名（base64url を解いたもの）の大きさの上限。
const maxSignatureSize = 128

var errKey = errors.New("push: unsupported or malformed public key")

// field は署名する文字列の項目に使える形（`|` を含まない）。
var field = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ParsePublicKey は base64url の SubjectPublicKeyInfo（DER）を読み、ECDSA P-256 か Ed25519 だけを受ける。
func ParsePublicKey(b64 string) (any, string, error) {
	if len(b64) > base64.RawURLEncoding.EncodedLen(maxKeySize) {
		return nil, "", errKey
	}
	der, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(der) == 0 {
		return nil, "", errKey
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", errKey
	}
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, "", errKey
		}
		return k, AlgES256, nil
	case ed25519.PublicKey:
		return k, AlgEd25519, nil
	}
	return nil, "", errKey
}

// Message は署名する文字列（iam-push-v1|<種類>|<項目>…）。項目が形に合わなければ ok=false。
func Message(kind string, fields ...string) (string, bool) {
	for _, f := range fields {
		if !field.MatchString(f) {
			return "", false
		}
	}
	return "iam-push-v1|" + kind + "|" + strings.Join(fields, "|"), true
}

// Verify は msg への base64url の署名を確かめる。ES256 は ASN.1 DER の署名（SHA-256）、Ed25519 は 64 バイト。
func Verify(key any, msg, sigB64 string) bool {
	if len(sigB64) > base64.RawURLEncoding.EncodedLen(maxSignatureSize) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) == 0 {
		return false
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256([]byte(msg))
		return ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k, []byte(msg), sig)
	}
	return false
}

// TokenHash は端末の宛先の SHA-256（16 進）。署名する文字列に宛先そのものを入れないために使う。
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
