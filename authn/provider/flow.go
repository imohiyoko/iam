package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可コードフローの途中の状態（design.md 5.1、ADR 0066）。ログイン画面で待つ間の認可要求と、発行した認可コードは
// EphemeralStore に封をして置く。どちらもキーは秘密の値の SHA-256 で、値そのものは置かない。

// 既定の期限。
const (
	DefaultRequestTTL = 10 * time.Minute
	DefaultCodeTTL    = time.Minute
)

var (
	// ErrInvalidGrant は認可コードが使えない（期限切れ・使用済み・別の連携先・戻り先や PKCE の不一致。理由は返さない）。
	ErrInvalidGrant = errs.WithCode(errs.KindInvalid, "invalid_grant", "invalid authorization code")
	// ErrRequestExpired はログイン画面で待つ間の認可要求が無い（期限切れ・完了済み）。
	ErrRequestExpired = errs.WithCode(errs.KindNotFound, "request_expired", "authorization request expired")
)

// Flow は認可要求と認可コードを預かる。
type Flow struct {
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	// RequestTTL はログイン画面で待つ間の認可要求の期限（既定 10 分）。CodeTTL は認可コードの期限（既定 1 分）。
	RequestTTL time.Duration
	CodeTTL    time.Duration
}

// AuthRequest は検証済みの認可要求。
type AuthRequest struct {
	RealmID string `json:"realm_id"`
	// ClientID は client_id（外部 ID）。
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	CodeChallenge string   `json:"code_challenge"` // S256 だけ
	ResponseMode  string   `json:"response_mode,omitempty"`
	// MaxAge は max_age（秒）。nil なら求めない。
	MaxAge *uint `json:"max_age,omitempty"`
	// LoginAfter は prompt=login のとき、この時刻より後の本人確認を求める。
	LoginAfter *time.Time `json:"login_after,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

const maxMaxAge = uint(100 * 365 * 24 * 60 * 60)

// Fresh は authAt の本人確認が、この要求の max_age と prompt=login を満たすかを返す。
func (r AuthRequest) Fresh(authAt, now time.Time) bool {
	if r.LoginAfter != nil && authAt.Before(*r.LoginAfter) {
		return false
	}
	if r.MaxAge != nil {
		// 100 年を超える max_age は制限なしと同じ（Duration のあふれを防ぐ）。
		age := min(*r.MaxAge, maxMaxAge)
		if now.Sub(authAt) > time.Duration(age)*time.Second { // #nosec G115 -- age は maxMaxAge 以下
			return false
		}
	}
	return true
}

// Code は認可コードに結び付けた内容。
type Code struct {
	AuthRequest
	UserID string `json:"user_id"` // 内部 ID
	OrgID  string `json:"org_id,omitempty"`
	SID    string `json:"sid"`
	// AuthTime はセッションで最後に本人確認した時刻。
	AuthTime time.Time `json:"auth_time"`
	AMR      []string  `json:"amr"`
}

const (
	requestPurpose = "flow.oidc_request"
	codePurpose    = "flow.oidc_code"
)

func digestKey(prefix, secret string) string {
	h := sha256.Sum256([]byte(secret))
	return prefix + base64.RawURLEncoding.EncodeToString(h[:])
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ttlOr(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (f *Flow) put(ctx context.Context, key, purpose string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := f.Crypter.Seal(ctx, purpose, b)
	if err != nil {
		return err
	}
	return f.Cache.Set(ctx, key, sealed, ttl)
}

func (f *Flow) open(ctx context.Context, purpose string, sealed []byte, v any) error {
	b, err := f.Crypter.Open(ctx, purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Hold はログイン画面で待つ間、認可要求を預かり、その ID（秘密）を返す。
func (f *Flow) Hold(ctx context.Context, r AuthRequest) (string, error) {
	rid, err := randomString()
	if err != nil {
		return "", err
	}
	ttl := ttlOr(f.RequestTTL, DefaultRequestTTL)
	r.ExpiresAt = f.Clock.Now().Add(ttl)
	return rid, f.put(ctx, digestKey("oidc:request:v1:", rid), requestPurpose, r, ttl)
}

// Resume は預かった認可要求を返す（消さない。ログインをやり直せるように）。無ければ ErrRequestExpired。
func (f *Flow) Resume(ctx context.Context, realmID, rid string) (AuthRequest, error) {
	if rid == "" {
		return AuthRequest{}, ErrRequestExpired
	}
	b, ok, err := f.Cache.Get(ctx, digestKey("oidc:request:v1:", rid))
	if err != nil {
		return AuthRequest{}, err
	}
	var r AuthRequest
	if !ok || f.open(ctx, requestPurpose, b, &r) != nil || r.RealmID != realmID || !f.Clock.Now().Before(r.ExpiresAt) {
		return AuthRequest{}, ErrRequestExpired
	}
	return r, nil
}

// Drop は預かった認可要求を消す（認可コードを発行した後）。
func (f *Flow) Drop(ctx context.Context, rid string) error {
	return f.Cache.Delete(ctx, digestKey("oidc:request:v1:", rid))
}

// IssueCode は認可コードを発行する。
func (f *Flow) IssueCode(ctx context.Context, c Code) (string, error) {
	code, err := randomString()
	if err != nil {
		return "", err
	}
	ttl := ttlOr(f.CodeTTL, DefaultCodeTTL)
	c.ExpiresAt = f.Clock.Now().Add(ttl)
	return code, f.put(ctx, digestKey("oidc:code:v1:", code), codePurpose, c, ttl)
}

// Redeem は認可コードを1回だけ取り出し、連携先・戻り先・PKCE の code_verifier を確かめる（RFC 6749 4.1.3、RFC 7636）。
// 取り出したコードは、確かめに失敗しても二度と使えない。
func (f *Flow) Redeem(ctx context.Context, realmID, clientID, code, redirectURI, verifier string) (Code, error) {
	if code == "" {
		return Code{}, ErrInvalidGrant
	}
	b, ok, err := f.Cache.Take(ctx, digestKey("oidc:code:v1:", code))
	if err != nil {
		return Code{}, err
	}
	var c Code
	if !ok {
		return Code{}, ErrInvalidGrant
	}
	if f.open(ctx, codePurpose, b, &c) != nil || c.RealmID != realmID || c.ClientID != clientID || c.RedirectURI != redirectURI || !f.Clock.Now().Before(c.ExpiresAt) ||
		!VerifyPKCE(c.CodeChallenge, verifier) {
		return Code{}, ErrInvalidGrant
	}
	return c, nil
}

// ValidPKCEValue は code_verifier と code_challenge の形（43〜128 文字の unreserved。RFC 7636 4.1）かを返す。
func ValidPKCEValue(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// VerifyPKCE は S256 の code_challenge に code_verifier が合うかを返す。
func VerifyPKCE(challenge, verifier string) bool {
	if !ValidPKCEValue(verifier) {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
