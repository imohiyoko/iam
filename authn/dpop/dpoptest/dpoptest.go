// Package dpoptest は DPoP の証明を作るテスト用の道具（ADR 0113）。
package dpoptest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Key は連携先の DPoP の鍵（ES256）。
type Key struct{ priv *ecdsa.PrivateKey }

// NewKey は鍵を作る。
func NewKey(t testing.TB) *Key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Key{priv: k}
}

// JKT は鍵の JWK SHA-256 Thumbprint。
func (k *Key) JKT() string {
	tp, err := (&jose.JSONWebKey{Key: k.priv.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// Claims は証明の中身と、壊し方。
type Claims struct {
	HTM, HTU   string
	IAT        time.Time
	ATH, Nonce string
	JTI        string // 空なら乱数
	// Typ が空なら dpop+jwt。
	Typ string
	// NoJTI・NoIAT は項目を省く。EmbedPrivate はヘッダーの jwk に秘密鍵を入れる。
	NoJTI, NoIAT, EmbedPrivate bool
}

// Proof は証明を作る。
func (k *Key) Proof(t testing.TB, c Claims) string {
	t.Helper()
	return Sign(t, jose.ES256, k.priv, c)
}

// Sign は任意の鍵で証明を作る。
func Sign(t testing.TB, alg jose.SignatureAlgorithm, priv crypto.Signer, c Claims) string {
	t.Helper()
	typ := c.Typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	embed := jose.JSONWebKey{Key: priv.Public()}
	if c.EmbedPrivate {
		embed = jose.JSONWebKey{Key: priv}
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("jwk", embed)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{"htm": c.HTM, "htu": c.HTU}
	if !c.NoIAT {
		m["iat"] = c.IAT.Unix()
	}
	if !c.NoJTI {
		jti := c.JTI
		if jti == "" {
			b := make([]byte, 12)
			_, _ = rand.Read(b)
			jti = base64.RawURLEncoding.EncodeToString(b)
		}
		m["jti"] = jti
	}
	if c.ATH != "" {
		m["ath"] = c.ATH
	}
	if c.Nonce != "" {
		m["nonce"] = c.Nonce
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
