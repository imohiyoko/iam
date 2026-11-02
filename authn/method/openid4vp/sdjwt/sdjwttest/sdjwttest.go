// Package sdjwttest はテスト用に SD-JWT VC を発行し、ウォレットとして key binding 付きで提示する（ADR 0108）。
package sdjwttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
)

// Issuer は発行者（ES256 の鍵）。
type Issuer struct {
	ISS string
	KID string
	Key *ecdsa.PrivateKey
	// Chain は x5c に入れる証明書（先頭が鍵の証明書）。空なら x5c を入れない。
	Chain []*x509.Certificate
	// Typ は typ（空なら dc+sd-jwt）。
	Typ string
}

// NewIssuer は鍵を作る。
func NewIssuer(iss, kid string) *Issuer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Issuer{ISS: iss, KID: kid, Key: k}
}

// JWKS は公開鍵の JWKS（JSON）。
func (i *Issuer) JWKS() string {
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: i.Key.Public(), KeyID: i.KID, Algorithm: string(jose.ES256), Use: "sig"}}})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Holder はウォレットの鍵。
type Holder struct{ Key *ecdsa.PrivateKey }

// NewHolder は鍵を作る。
func NewHolder() *Holder {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Holder{Key: k}
}

// JWK は公開鍵の JWK（cnf.jwk に入れる値）。
func (h *Holder) JWK() map[string]any {
	b, err := json.Marshal(jose.JSONWebKey{Key: h.Key.Public()})
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}

// Disclosure は開示を作る。name が空なら配列の要素の開示。
func Disclosure(name string, value any) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	a := []any{base64.RawURLEncoding.EncodeToString(salt)}
	if name != "" {
		a = append(a, name)
	}
	b, err := json.Marshal(append(a, value))
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sign は payload に署名した JWT を返す。
func Sign(key any, typ string, extra map[jose.HeaderKey]any, payload any) string {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	for k, v := range extra {
		opts.WithHeader(k, v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		panic(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

// Credential は発行した SD-JWT（開示は全部）。
type Credential struct {
	JWT         string
	Disclosures map[string]string // 名前 → 開示
}

// Issue は vct の資格情報を発行する。sd の値は選択的に開示する値（最上位）、clear は平文の値。cnf.jwk は holder の鍵。
func (i *Issuer) Issue(vct string, holder *Holder, clear, sd map[string]any, now time.Time) Credential {
	payload := map[string]any{"iss": i.ISS, "vct": vct, "iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix(), "_sd_alg": "sha-256"}
	if holder != nil {
		payload["cnf"] = map[string]any{"jwk": holder.JWK()}
	}
	for k, v := range clear {
		payload[k] = v
	}
	c := Credential{Disclosures: map[string]string{}}
	var digests []any
	for k, v := range sd {
		d := Disclosure(k, v)
		c.Disclosures[k] = d
		digests = append(digests, sdjwt.Digest(d))
	}
	// デコイを1つ入れる。
	digests = append(digests, sdjwt.Digest(Disclosure("decoy", "x")))
	payload["_sd"] = digests
	extra := map[jose.HeaderKey]any{}
	if i.KID != "" {
		extra["kid"] = i.KID
	}
	if len(i.Chain) > 0 {
		var x5c []string
		for _, c := range i.Chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
		}
		extra["x5c"] = x5c
	}
	typ := i.Typ
	if typ == "" {
		typ = sdjwt.TypeVC
	}
	c.JWT = Sign(i.Key, typ, extra, payload)
	return c
}

// Present は開示 names（空なら全部）を付け、key binding の JWT を付けた提示を作る。
func (h *Holder) Present(c Credential, aud, nonce string, iat time.Time, names ...string) string {
	if len(names) == 0 {
		for n := range c.Disclosures {
			names = append(names, n)
		}
	}
	parts := []string{c.JWT}
	for _, n := range names {
		parts = append(parts, c.Disclosures[n])
	}
	signed := strings.Join(parts, "~") + "~"
	kb := Sign(h.Key, sdjwt.TypeKB, nil, map[string]any{"aud": aud, "nonce": nonce, "iat": iat.Unix(), "sd_hash": sdjwt.SDHash(signed)})
	return signed + kb
}
