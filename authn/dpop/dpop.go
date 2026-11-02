// Package dpop は DPoP（RFC 9449）の証明（proof）を確かめる（ADR 0113）。
//
// 証明は連携先が要求ごとに作る JWT で、ヘッダーの jwk（公開鍵）で署名する。iam は token エンドポイントで証明の鍵の
// JWK SHA-256 Thumbprint（jkt。RFC 7638）をトークンに結び付け、そのトークンを受ける自分の資源（UserInfo、管理 API）で、
// 同じ鍵の証明と ath（トークンのハッシュ）を求める。
//
// 確かめること（RFC 9449 4.3）：DPoP ヘッダーが1つ、JWS のコンパクト形式、typ が dpop+jwt、alg が非対称の許したもの、
// jwk が公開鍵だけ、署名、htm・htu・iat・jti、要るときは nonce と ath。jti は EphemeralStore で1回だけにする（再送の防止）。
// どれかが欠ければ拒む（fail-closed）。
package dpop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
)

// Feature は DPoP のフィーチャー（既定オフ）。
var Feature = feature.Feature{Name: feature.DPoP, DataVersion: 1}

// HTTP の名前（RFC 9449 4.1、7.1、8）。
const (
	Header      = "DPoP"
	NonceHeader = "DPoP-Nonce"
	// Scheme は Authorization ヘッダーの方式（DPoP に結び付けたアクセストークン）。
	Scheme = "DPoP"
	// TokenType は token エンドポイントの応答の token_type。
	TokenType = "DPoP"
)

// 上限と既定。
const (
	// MaxProofBytes は証明の大きさの上限。
	MaxProofBytes = 8 << 10
	maxJTILength  = 256
	maxNonceLen   = 256
	// DefaultMaxAge は iat の古さの上限（RFC 9449 11.1）。jti はこの間だけ覚える。
	DefaultMaxAge = 5 * time.Minute
	// futureSkew は iat が今より先でも許すずれ。
	futureSkew = 30 * time.Second
	// DefaultNonceTTL は iam が出す nonce の寿命。
	DefaultNonceTTL = 5 * time.Minute
	minRSABits      = 2048
)

// Algs は証明の署名に受けるアルゴリズム（Discovery の dpop_signing_alg_values_supported）。RSA は連携先の鍵を確かめるだけ
// （ADR 0005 の対象外。private_key_jwt と同じ）。
var Algs = []string{"ES256", "ES384", "EdDSA", "PS256", "RS256"}

var joseAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.EdDSA, jose.PS256, jose.RS256}

// エラー。理由の細部は返さない。
var (
	// ErrInvalidProof は証明が無い・形が違う・署名や項目が合わない（RFC 9449 の invalid_dpop_proof）。
	ErrInvalidProof = errs.WithCode(errs.KindInvalid, "invalid_dpop_proof", "invalid DPoP proof")
	// ErrUseNonce は iam の nonce を求める（RFC 9449 8 の use_dpop_nonce。応答に DPoP-Nonce を付ける）。
	ErrUseNonce = errs.WithCode(errs.KindInvalid, "use_dpop_nonce", "a DPoP nonce is required")
)

// Proof は確かめた証明。
type Proof struct {
	// JKT は証明の鍵の JWK SHA-256 Thumbprint（base64url）。
	JKT   string
	JTI   string
	HTM   string
	HTU   string
	IAT   time.Time
	ATH   string
	Nonce string
}

type claims struct {
	JTI   *string  `json:"jti"`
	HTM   *string  `json:"htm"`
	HTU   *string  `json:"htu"`
	IAT   *float64 `json:"iat"`
	ATH   *string  `json:"ath"`
	Nonce *string  `json:"nonce"`
}

// Parse は証明の形と署名を確かめる（htm・htu・時刻・nonce・再送は Verifier が確かめる）。ファジングの対象。
func Parse(raw string) (Proof, error) {
	if raw == "" || len(raw) > MaxProofBytes || strings.Count(raw, ".") != 2 {
		return Proof{}, ErrInvalidProof
	}
	sig, err := jose.ParseSignedCompact(raw, joseAlgs)
	if err != nil || len(sig.Signatures) != 1 {
		return Proof{}, ErrInvalidProof
	}
	h := sig.Signatures[0].Protected
	if typ, ok := h.ExtraHeaders[jose.HeaderType].(string); !ok || typ != "dpop+jwt" {
		return Proof{}, ErrInvalidProof
	}
	// 署名の検証より前に鍵を確かめる：公開鍵だけ、alg と合う種類、RSA は 2048 bit 以上。
	k := h.JSONWebKey
	if k == nil || !k.Valid() || !k.IsPublic() || k.Algorithm != "" && k.Algorithm != h.Algorithm {
		return Proof{}, ErrInvalidProof
	}
	if !keyMatchesAlg(k.Key, h.Algorithm) {
		return Proof{}, ErrInvalidProof
	}
	payload, err := sig.Verify(k)
	if err != nil {
		return Proof{}, ErrInvalidProof
	}
	var c claims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Proof{}, ErrInvalidProof
	}
	if c.JTI == nil || *c.JTI == "" || len(*c.JTI) > maxJTILength || c.HTM == nil || *c.HTM == "" || c.HTU == nil || *c.HTU == "" ||
		c.IAT == nil || math.IsNaN(*c.IAT) || math.IsInf(*c.IAT, 0) || *c.IAT < 0 || *c.IAT > 1e11 {
		return Proof{}, ErrInvalidProof
	}
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return Proof{}, ErrInvalidProof
	}
	p := Proof{JKT: base64.RawURLEncoding.EncodeToString(tp), JTI: *c.JTI, HTM: *c.HTM, HTU: *c.HTU,
		IAT: time.Unix(int64(*c.IAT), 0)}
	if c.ATH != nil {
		p.ATH = *c.ATH
	}
	if c.Nonce != nil {
		if *c.Nonce == "" || len(*c.Nonce) > maxNonceLen {
			return Proof{}, ErrInvalidProof
		}
		p.Nonce = *c.Nonce
	}
	return p, nil
}

// keyMatchesAlg は鍵の種類が alg と合うか（RSA は 2048 bit 以上）。
func keyMatchesAlg(k any, alg string) bool {
	switch alg {
	case "PS256", "RS256":
		rk, ok := k.(*rsa.PublicKey)
		return ok && rk.N.BitLen() >= minRSABits
	}
	return true // EC・Ed25519 の種類とアルゴリズムの組は go-jose が署名の検証で確かめる
}

// ValidJKT は s が jkt の形（SHA-256 の base64url。認可要求の dpop_jkt など）かを返す。
func ValidJKT(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// AccessTokenHash は ath（アクセストークンの SHA-256 の base64url。RFC 9449 4.2）。
func AccessTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Store は jti と nonce を覚える EphemeralStore（port.EphemeralStore の一部）。
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// Verifier は証明を確かめる。
type Verifier struct {
	Clock clock.Clock
	Store Store
	// RequireNonce なら iam が出した nonce を求める（RFC 9449 8）。
	RequireNonce bool
	// MaxAge は iat の古さの上限（0 なら DefaultMaxAge）。NonceTTL は nonce の寿命（0 なら DefaultNonceTTL）。
	MaxAge, NonceTTL time.Duration

	mu        sync.Mutex
	nonce     string
	nonceFrom time.Time
}

// Expect は要求に合わせて確かめること。
type Expect struct {
	// Method は HTTP のメソッド、URLs は受け付ける htu（iam の外から見た URL。クエリとフラグメントを除く）。
	Method string
	URLs   []string
	// AccessToken があれば ath を求める（資源での提示）。
	AccessToken string
	// JKT があれば証明の鍵がそれであることを求める（結び付けたトークン）。
	JKT string
}

func (v *Verifier) maxAge() time.Duration {
	if v.MaxAge > 0 {
		return v.MaxAge
	}
	return DefaultMaxAge
}

func (v *Verifier) nonceTTL() time.Duration {
	if v.NonceTTL > 0 {
		return v.NonceTTL
	}
	return DefaultNonceTTL
}

// Verify は DPoP ヘッダーの値（要求の全部。1つだけを受ける）を確かめる。nonce が要るのに無い・古いときは ErrUseNonce、
// ほかは ErrInvalidProof。ストレージの障害はそれ以外のエラー。
func (v *Verifier) Verify(ctx context.Context, headers []string, e Expect) (Proof, error) {
	if len(headers) != 1 {
		return Proof{}, ErrInvalidProof
	}
	p, err := Parse(strings.TrimSpace(headers[0]))
	if err != nil {
		return Proof{}, err
	}
	if p.HTM != e.Method || !matchURL(p.HTU, e.URLs) {
		return Proof{}, ErrInvalidProof
	}
	now := v.Clock.Now()
	if p.IAT.After(now.Add(futureSkew)) || now.Sub(p.IAT) > v.maxAge() {
		return Proof{}, ErrInvalidProof
	}
	if e.JKT != "" && subtle.ConstantTimeCompare([]byte(p.JKT), []byte(e.JKT)) != 1 {
		return Proof{}, ErrInvalidProof
	}
	if e.AccessToken != "" && subtle.ConstantTimeCompare([]byte(p.ATH), []byte(AccessTokenHash(e.AccessToken))) != 1 {
		return Proof{}, ErrInvalidProof
	}
	if e.AccessToken == "" && p.ATH != "" {
		return Proof{}, ErrInvalidProof
	}
	if v.RequireNonce {
		if p.Nonce == "" {
			return Proof{}, ErrUseNonce
		}
		_, ok, err := v.Store.Get(ctx, nonceKey(p.Nonce))
		if err != nil {
			return Proof{}, errs.Wrap(errs.KindUnavailable, err, "dpop: nonce")
		}
		if !ok {
			return Proof{}, ErrUseNonce
		}
	}
	// 再送の防止：鍵と jti の組を iat の許す幅の間だけ覚える。
	h := sha256.Sum256([]byte(p.JKT + "\x00" + p.JTI))
	n, err := v.Store.Incr(ctx, "dpop:jti:v1:"+base64.RawURLEncoding.EncodeToString(h[:]), v.maxAge()+futureSkew+time.Minute)
	if err != nil {
		return Proof{}, errs.Wrap(errs.KindUnavailable, err, "dpop: replay")
	}
	if n != 1 {
		return Proof{}, ErrInvalidProof
	}
	return p, nil
}

func nonceKey(n string) string {
	h := sha256.Sum256([]byte(n))
	return "dpop:nonce:v1:" + base64.RawURLEncoding.EncodeToString(h[:])
}

// Nonce は今の nonce を返す（RequireNonce のときに応答の DPoP-Nonce に付ける）。寿命の半分を過ぎたら新しくする。
// nonce は EphemeralStore に寿命付きで置くので、複数のインスタンスのどれが出したものでも通る。
func (v *Verifier) Nonce(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.Clock.Now()
	if v.nonce != "" && now.Sub(v.nonceFrom) < v.nonceTTL()/2 {
		return v.nonce, nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	if err := v.Store.Set(ctx, nonceKey(n), []byte{1}, v.nonceTTL()); err != nil {
		return "", errs.Wrap(errs.KindUnavailable, err, "dpop: nonce")
	}
	v.nonce, v.nonceFrom = n, now
	return n, nil
}

// matchURL は htu が urls のどれかと同じか（scheme とホストの大文字小文字と既定のポートを揃え、クエリとフラグメントを除いて比べる。
// RFC 9449 4.3 の 9）。
func matchURL(htu string, urls []string) bool {
	got, ok := normalizeURL(htu)
	if !ok {
		return false
	}
	for _, u := range urls {
		if want, ok := normalizeURL(u); ok && want == got {
			return true
		}
	}
	return false
}

func normalizeURL(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}
