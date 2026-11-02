package serviceaccount

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// client credentials（RFC 6749 4.4）と client assertion（RFC 7523）。

const (
	GrantClientCredentials = "client_credentials"
	AssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- RFC 7523 の識別子で、秘密ではない
	// MaxAssertionLifetime は client assertion の exp の上限（今からの長さ）。jti はこの間だけ覚える。
	MaxAssertionLifetime = 5 * time.Minute
	assertionLeeway      = 30 * time.Second
)

var (
	// ErrInvalidClient はクライアントの認証の失敗（RFC 6749 5.2）。理由は返さない。
	ErrInvalidClient = errs.WithCode(errs.KindUnauthenticated, "invalid_client", "client authentication failed")
	// ErrUnsupportedGrant は client_credentials 以外の grant_type。
	ErrUnsupportedGrant = errs.WithCode(errs.KindInvalid, "unsupported_grant_type", "unsupported grant_type")
	// ErrInvalidRequest は認証の方法が無いか、複数ある。
	ErrInvalidRequest = errs.WithCode(errs.KindInvalid, "invalid_request", "exactly one client authentication method is required")
	// ErrInvalidTarget は resource が使えない（RFC 8707 2。登録されていない・許されていない・2 つ以上・フィーチャーが止まっている）。
	ErrInvalidTarget = errs.WithCode(errs.KindInvalid, "invalid_target", "invalid resource")
	// ErrInvalidScope は resource のスコープとして許されていないスコープ（RFC 6749 5.2）。
	ErrInvalidScope = errs.WithCode(errs.KindInvalid, "invalid_scope", "invalid scope")
)

// maxScopeParam は scope の長さの上限。
const maxScopeParam = 4096

// AssertionReplay は client assertion の jti を覚える（1回だけ使える。RFC 7523 3）。
type AssertionReplay interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// TokenRequest はトークンの要求。ClientSecret（client_secret_basic・client_secret_post）か Assertion のどちらか1つ。
type TokenRequest struct {
	GrantType     string
	ClientID      string
	ClientSecret  string
	AssertionType string
	Assertion     string
	// JKT はトークンを結び付ける DPoP の鍵（呼び出し側が証明を確かめたもの。ADR 0113）。空なら Bearer。
	JKT string
	// Resources は resource（RFC 8707）。指定するなら 1 つだけ。Scope は resource のスコープ（空白区切り）。resource が無ければ使わない。
	Resources []string
	Scope     string
}

// Issued は発行したアクセストークン。Token は1回だけ返す。
type Issued struct {
	Token     string
	ExpiresIn time.Duration
	Account   port.ServiceAccount
	// Audience と Scopes は自前の API に向けたトークンの aud とスコープ（ADR 0112）。管理 API 向けなら空。
	Audience string
	Scopes   []string
}

// Token はクライアントを認証し、アクセストークンを発行する。認証の失敗は ErrInvalidClient、ストレージの障害はそれ以外のエラー。
func (s *Service) Token(ctx context.Context, tx port.Tx, realmID string, req TokenRequest, requestID string) (Issued, error) {
	if req.GrantType != GrantClientCredentials {
		return Issued{}, ErrUnsupportedGrant
	}
	if (req.ClientSecret == "") == (req.Assertion == "") || (req.Assertion != "" && req.AssertionType != AssertionTypeJWTBearer) {
		return Issued{}, ErrInvalidRequest
	}
	now := s.Clock.Now()
	var c port.ServiceAccountCredential
	var err error
	if req.ClientSecret != "" {
		c, err = checkSecret(ctx, tx, realmID, req.ClientSecret, TypeClientSecret, now)
		if err == nil && req.ClientID != c.ServiceAccountID {
			err = ErrInvalid
		}
	} else {
		c, err = s.checkAssertion(ctx, tx, realmID, req.ClientID, req.Assertion, now)
	}
	if err != nil {
		return Issued{}, clientErr(err)
	}
	a, err := tx.ServiceAccounts().Get(ctx, realmID, c.ServiceAccountID)
	if err != nil {
		return Issued{}, clientErr(invalidOr(err))
	}
	if err := s.usable(ctx, tx, a, now); err != nil {
		return Issued{}, clientErr(err)
	}
	audience, scopes, err := s.target(ctx, tx, realmID, a.ID, req)
	if err != nil {
		return Issued{}, err
	}
	secret, h, err := newSecret()
	if err != nil {
		return Issued{}, err
	}
	t := port.ServiceAccountToken{ID: id.NewExternal(id.SAToken), RealmID: realmID, ServiceAccountID: a.ID, CredentialID: c.ID,
		Hash: h, CreatedAt: now, ExpiresAt: now.Add(s.TokenTTL), Audience: audience, Scopes: scopes,
		JKT: req.JKT}
	if err := tx.ServiceAccounts().CreateToken(ctx, t); err != nil {
		return Issued{}, err
	}
	actor := audit.Actor{Type: "service_account", ID: a.ID}
	details := map[string]any{"service_account_id": a.ID, "credential_id": c.ID, "token_id": t.ID}
	if t.JKT != "" {
		details["dpop_jkt"] = t.JKT
	}
	if audience != "" {
		details["resource"], details["scopes"] = audience, scopes
	}
	if err := s.record(ctx, tx, realmID, "service_account.token_issued", actor, requestID, details); err != nil {
		return Issued{}, err
	}
	return Issued{Token: t.ID + "." + secret, ExpiresIn: s.TokenTTL, Account: a, Audience: audience, Scopes: scopes}, nil
}

// target は resource と scope から、自前の API に向けたトークンの aud とスコープを決める（RFC 8707、ADR 0112）。resource が
// 無ければ管理 API 向け（空）。フィーチャーが止まっているときの resource は、管理 API 向けのトークンを渡さないよう invalid_target。
func (s *Service) target(ctx context.Context, tx port.Tx, realmID, accountID string, req TokenRequest) (string, []string, error) {
	if len(req.Resources) == 0 {
		return "", nil, nil
	}
	if s.Resource == nil || len(req.Resources) != 1 {
		return "", nil, ErrInvalidTarget
	}
	x, err := s.Resource(ctx, tx, realmID, req.Resources[0], accountID)
	if errors.Is(err, errs.Invalid) {
		return "", nil, ErrInvalidTarget
	}
	if err != nil {
		return "", nil, err
	}
	if len(req.Scope) > maxScopeParam {
		return "", nil, ErrInvalidScope
	}
	requested := strings.Fields(req.Scope)
	if len(requested) == 0 {
		return x.URI, slices.Clone(x.Scopes), nil
	}
	for _, sc := range requested {
		if !slices.Contains(x.Scopes, sc) {
			return "", nil, ErrInvalidScope
		}
	}
	slices.Sort(requested)
	return x.URI, slices.Compact(requested), nil
}

// clientErr は認証の失敗を ErrInvalidClient にする（ストレージの障害はそのまま）。
func clientErr(err error) error {
	if errors.Is(err, ErrInvalid) {
		return ErrInvalidClient
	}
	return err
}

// checkAssertion は client assertion を確かめ、署名を検証できた認証情報を返す。iss と sub は client_id、aud は Audience、
// exp は今から MaxAssertionLifetime 以内、jti は未使用であること。
func (s *Service) checkAssertion(ctx context.Context, tx port.Tx, realmID, clientID, assertion string, now time.Time) (port.ServiceAccountCredential, error) {
	if s.Audience == "" {
		return port.ServiceAccountCredential{}, ErrInvalid
	}
	tok, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA, AlgMLDSA65})
	if err != nil || len(tok.Headers) != 1 {
		return port.ServiceAccountCredential{}, ErrInvalid
	}
	if clientID == "" {
		// client_id を省いたときは、署名の検証の前に iss を読む（検証の後で iss・sub と照合する）。
		var c jwt.Claims
		if err := tok.UnsafeClaimsWithoutVerification(&c); err != nil {
			return port.ServiceAccountCredential{}, ErrInvalid
		}
		clientID = c.Issuer
	}
	if !id.Valid(id.ServiceAccount, clientID) {
		return port.ServiceAccountCredential{}, ErrInvalid
	}
	cs, err := tx.ServiceAccounts().ListCredentials(ctx, realmID, clientID)
	if err != nil {
		return port.ServiceAccountCredential{}, invalidOr(err)
	}
	h := tok.Headers[0]
	for _, c := range cs {
		if c.Type != TypePrivateKeyJWT || c.Alg != h.Algorithm || !live(c, now) || (h.KeyID != "" && h.KeyID != c.ID) {
			continue
		}
		k, err := ParsePublicKey(c.PublicKey, c.Alg)
		if err != nil {
			continue
		}
		var claims jwt.Claims
		if err := tok.Claims(k.verifier, &claims); err != nil {
			continue
		}
		if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: clientID, Subject: clientID, AnyAudience: jwt.Audience{s.Audience}, Time: now},
			assertionLeeway); err != nil || claims.Expiry == nil || claims.ID == "" || claims.Expiry.Time().Sub(now) > MaxAssertionLifetime {
			return port.ServiceAccountCredential{}, ErrInvalid
		}
		if err := s.consume(ctx, clientID, claims.ID); err != nil {
			return port.ServiceAccountCredential{}, err
		}
		return c, nil
	}
	return port.ServiceAccountCredential{}, ErrInvalid
}

// consume は jti を使用済みにする。2回目なら ErrInvalid。
func (s *Service) consume(ctx context.Context, clientID, jti string) error {
	h := sha256.Sum256([]byte(clientID + "\x00" + jti))
	n, err := s.Replay.Incr(ctx, "sa:assertion:v1:"+base64.RawURLEncoding.EncodeToString(h[:]), MaxAssertionLifetime+time.Minute)
	if err != nil {
		return errs.Wrap(errs.KindUnavailable, err, "service account: assertion replay")
	}
	if n != 1 {
		return ErrInvalid
	}
	return nil
}
