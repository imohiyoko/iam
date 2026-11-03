package vci_test

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/shared/errs"
)

const issuer = "https://id.example/realms/acme"

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// proofJWT はウォレットの proof を作る。header と claims は既定に重ねる（値が nil なら消す）。
func proofJWT(t testing.TB, key any, alg jose.SignatureAlgorithm, header map[jose.HeaderKey]any, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(vci.ProofType)
	embed := true
	for k, v := range header {
		if k == "jwk" && v == nil {
			embed = false
			continue
		}
		opts.WithHeader(k, v)
	}
	if embed {
		opts.EmbedJWK = true
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{"aud": issuer, "iat": now.Unix(), "nonce": "n-1"}
	for k, v := range claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	b, _ := json.Marshal(c)
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func opts() vci.ProofOptions { return vci.ProofOptions{Audience: issuer, Now: now} }

func TestVerifyProof(t *testing.T) {
	k := newKey(t)
	p, err := vci.VerifyProof(proofJWT(t, k, jose.ES256, nil, nil), opts())
	if err != nil {
		t.Fatal(err)
	}
	if p.Nonce != "n-1" || p.Thumbprint == "" || !p.Key.IsPublic() {
		t.Fatalf("proof = %+v", p)
	}
	// aud は配列でもよく、iss は連携先と一致すればよい。
	o := opts()
	o.ClientID = "wallet"
	if _, err := vci.VerifyProof(proofJWT(t, k, jose.ES256, nil, map[string]any{"aud": []string{"x", issuer}, "iss": "wallet"}), o); err != nil {
		t.Fatal(err)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := vci.VerifyProof(proofJWT(t, ed, jose.EdDSA, nil, nil), opts()); err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
}

func TestVerifyProofRejects(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	o := opts()
	o.ClientID = "wallet"
	hs, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType(vci.ProofType))
	hsObj, _ := hs.Sign([]byte(`{"aud":"` + issuer + `","iat":` + jsonNum(now.Unix()) + `,"nonce":"n"}`))
	hsJWT, _ := hsObj.CompactSerialize()
	good := proofJWT(t, k, jose.ES256, nil, nil)
	parts := strings.Split(good, ".")
	// 別の鍵の署名に、k の jwk を付け替えたもの。
	forged := proofJWT(t, other, jose.ES256, nil, nil)
	fparts := strings.Split(forged, ".")
	swapped := parts[0] + "." + parts[1] + "." + fparts[2]
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, tc := range map[string]struct {
		jwt  string
		o    vci.ProofOptions
		code string
	}{
		"wrong aud":         {proofJWT(t, k, jose.ES256, nil, map[string]any{"aud": "https://evil.example"}), opts(), vci.CodeInvalidProof},
		"no aud":            {proofJWT(t, k, jose.ES256, nil, map[string]any{"aud": nil}), opts(), vci.CodeInvalidProof},
		"old iat":           {proofJWT(t, k, jose.ES256, nil, map[string]any{"iat": now.Add(-10 * time.Minute).Unix()}), opts(), vci.CodeInvalidProof},
		"future iat":        {proofJWT(t, k, jose.ES256, nil, map[string]any{"iat": now.Add(5 * time.Minute).Unix()}), opts(), vci.CodeInvalidProof},
		"no iat":            {proofJWT(t, k, jose.ES256, nil, map[string]any{"iat": nil}), opts(), vci.CodeInvalidProof},
		"string iat":        {proofJWT(t, k, jose.ES256, nil, map[string]any{"iat": "now"}), opts(), vci.CodeInvalidProof},
		"no nonce":          {proofJWT(t, k, jose.ES256, nil, map[string]any{"nonce": nil}), opts(), vci.CodeInvalidNonce},
		"wrong iss":         {proofJWT(t, k, jose.ES256, nil, map[string]any{"iss": "other"}), o, vci.CodeInvalidProof},
		"numeric iss":       {proofJWT(t, k, jose.ES256, nil, map[string]any{"iss": 1}), opts(), vci.CodeInvalidProof},
		"wrong typ":         {proofJWT(t, k, jose.ES256, map[jose.HeaderKey]any{"typ": "JWT"}, nil), opts(), vci.CodeInvalidProof},
		"no jwk":            {proofJWT(t, k, jose.ES256, map[jose.HeaderKey]any{"jwk": nil}, nil), opts(), vci.CodeInvalidProof},
		"kid":               {proofJWT(t, k, jose.ES256, map[jose.HeaderKey]any{"kid": "did:example:1#k"}, nil), opts(), vci.CodeInvalidProof},
		"x5c":               {proofJWT(t, k, jose.ES256, map[jose.HeaderKey]any{"x5c": []string{"AA=="}}, nil), opts(), vci.CodeInvalidProof},
		"hmac":              {hsJWT, opts(), vci.CodeInvalidProof},
		"signature swapped": {swapped, opts(), vci.CodeInvalidProof},
		"alg curve":         {mismatchedAlg(t, p384), opts(), vci.CodeInvalidProof},
		"two parts":         {parts[0] + "." + parts[1], opts(), vci.CodeInvalidProof},
		"too large":         {strings.Repeat("a", vci.MaxProofSize+1), opts(), vci.CodeInvalidProof},
		"empty":             {"", opts(), vci.CodeInvalidProof},
		"private jwk":       {privateJWK(t, k), opts(), vci.CodeInvalidProof},
	} {
		_, err := vci.VerifyProof(tc.jwt, tc.o)
		if code, _ := vci.CodeOf(err); code != tc.code {
			t.Errorf("%s: code = %q (%v), want %s", name, code, err, tc.code)
		}
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

// mismatchedAlg は P-384 の鍵の jwk で、ヘッダーの alg を ES256 と書いた proof（署名は P-384 の鍵）。
func mismatchedAlg(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	good := proofJWT(t, k, jose.ES384, nil, nil)
	parts := strings.Split(good, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	h := strings.Replace(string(hb), `"ES384"`, `"ES256"`, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + parts[1] + "." + parts[2]
}

// privateJWK はヘッダーの jwk に秘密鍵（d）を入れた proof。
func privateJWK(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	priv, _ := json.Marshal(jose.JSONWebKey{Key: k})
	h := `{"alg":"ES256","typ":"` + vci.ProofType + `","jwk":` + string(priv) + `}`
	good := proofJWT(t, k, jose.ES256, nil, nil)
	parts := strings.Split(good, ".")
	return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + parts[1] + "." + parts[2]
}

func TestParseCredentialRequest(t *testing.T) {
	r, err := vci.ParseCredentialRequest([]byte(`{"credential_configuration_id":"employee","proofs":{"jwt":["a.b.c"]}}`))
	if err != nil || r.ConfigurationID != "employee" || r.Proof != "a.b.c" {
		t.Fatalf("parse = %+v, %v", r, err)
	}
	for body, code := range map[string]string{
		`{"proofs":{"jwt":["a.b.c"]}}`: vci.CodeInvalidCredentialRequest,
		`{"credential_configuration_id":"e","proof":{"proof_type":"jwt","jwt":"a.b.c"}}`:                           vci.CodeInvalidCredentialRequest,
		`{"credential_configuration_id":"e"}`:                                                                      vci.CodeInvalidProof,
		`{"credential_configuration_id":"e","proofs":{"jwt":[]}}`:                                                  vci.CodeInvalidProof,
		`{"credential_configuration_id":"e","proofs":{"jwt":["a","b"]}}`:                                           vci.CodeInvalidProof,
		`{"credential_configuration_id":"e","proofs":{"ldp_vp":[{}]}}`:                                             vci.CodeInvalidProof,
		`{"credential_configuration_id":"e","proofs":{"jwt":[1]}}`:                                                 vci.CodeInvalidProof,
		`{"credential_identifier":"x","proofs":{"jwt":["a.b.c"]}}`:                                                 vci.CodeUnknownCredentialIdentifier,
		`{"credential_configuration_id":"e","proofs":{"jwt":["a.b.c"]},"credential_response_encryption":{}}`:       vci.CodeInvalidEncryptionParameters,
		`{"credential_configuration_id":"e","credential_configuration_id":"f","proofs":{"jwt":["a.b.c"]}}`:         vci.CodeInvalidCredentialRequest,
		`[]`:   vci.CodeInvalidCredentialRequest,
		`{`:    vci.CodeInvalidCredentialRequest,
		`null`: vci.CodeInvalidCredentialRequest,
	} {
		_, err := vci.ParseCredentialRequest([]byte(body))
		if got, _ := vci.CodeOf(err); got != code {
			t.Errorf("%s: code = %q, want %s", body, got, code)
		}
	}
}

func TestEncodeStatusList(t *testing.T) {
	lst, err := vci.EncodeStatusList([]int{0, 9, vci.StatusListSize - 1})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	bits, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if len(bits) != vci.StatusListSize/8 || bits[0] != 0x01 || bits[1] != 0x02 || bits[len(bits)-1] != 0x80 {
		t.Fatalf("bits = %x %x %x (len %d)", bits[0], bits[1], bits[len(bits)-1], len(bits))
	}
	for _, i := range []int{-1, vci.StatusListSize} {
		if _, err := vci.EncodeStatusList([]int{i}); err == nil {
			t.Errorf("index %d accepted", i)
		}
	}
}

// Token Status List の仕様の例（4.1 の 1 bit の例）と同じ並びになること：番号 0,3,4,5,7,8,9,13,15 が 1。
func TestStatusListBitOrder(t *testing.T) {
	lst, _ := vci.EncodeStatusList([]int{0, 3, 4, 5, 7, 8, 9, 13, 15})
	raw, _ := base64.RawURLEncoding.DecodeString(lst)
	zr, _ := zlib.NewReader(bytes.NewReader(raw))
	bits, _ := io.ReadAll(zr)
	if bits[0] != 0xB9 || bits[1] != 0xA3 {
		t.Fatalf("bits = %x %x, want b9 a3", bits[0], bits[1])
	}
}

func TestCodeOf(t *testing.T) {
	if c, _ := vci.CodeOf(errors.New("x")); c != "" {
		t.Fatal(c)
	}
	if c, _ := vci.CodeOf(errs.New(errs.KindInvalid, "x")); c != "" {
		t.Fatal(c)
	}
}
