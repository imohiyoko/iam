package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 連携先への認可とトークン（design.md 5.1、5.3、ADR 0066）。
//
// 認可コードを交換するたびに認可（Grant）を作り、不透明なアクセストークンと ID トークン（JWT）を返す。認可はログインの系列
// （sid）に結び付き、系列の今のセッションが使えなくなれば（ログアウト・失効・停止・認証情報の無効化・期限）トークンも使えない。

// 対応するスコープ。
const (
	ScopeOpenID = "openid"
	ScopeEmail  = "email"
)

// Scopes は対応するスコープ（Discovery の scopes_supported）。
var Scopes = []string{ScopeOpenID, ScopeEmail}

// 既定の寿命。
const (
	DefaultAccessTokenTTL = 10 * time.Minute
	DefaultIDTokenTTL     = time.Hour
	DefaultRefreshTTL     = 30 * 24 * time.Hour
)

// ErrInvalidToken はアクセストークンが使えない（理由は返さない）。
var ErrInvalidToken = errs.WithCode(errs.KindUnauthenticated, "invalid_token", "invalid access token")

// Tokens は認可とトークンを発行・検証する。
type Tokens struct {
	Clock    clock.Clock
	Keys     *Keys
	Sessions *session.Manager
	Accounts *account.Service
	// Orgs は Org の可否と結び付けたメール。フィーチャー org が動いていなければ nil。
	Orgs *org.Service
	// Issuer は iss（server.public_url）。
	Issuer                               string
	AccessTokenTTL, IDTokenTTL, GrantTTL time.Duration
}

// Issued は token エンドポイントの応答の中身。
type Issued struct {
	AccessToken string
	ExpiresIn   time.Duration
	IDToken     string
	Scopes      []string
	Grant       port.Grant
}

func newOpaque(prefix id.Prefix) (tokenID, token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	tokenID = id.NewExternal(prefix)
	h := sha256.Sum256([]byte(secret))
	return tokenID, tokenID + "." + secret, h[:], nil
}

func splitOpaque(token string) (string, []byte, bool) {
	tid, secret, ok := strings.Cut(token, ".")
	if !ok || tid == "" || secret == "" {
		return "", nil, false
	}
	h := sha256.Sum256([]byte(secret))
	return tid, h[:], true
}

// Exchange は検証済みの認可コードから認可を作り、トークンを発行する。ログインの系列がもう使えなければ ErrInvalidGrant。
func (t *Tokens) Exchange(ctx context.Context, tx port.Tx, cl port.Client, c Code, requestID string) (Issued, error) {
	now := t.Clock.Now()
	if err := t.alive(ctx, tx, c.RealmID, c.SID, c.UserID, c.OrgID, now); err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return Issued{}, ErrInvalidGrant
		}
		return Issued{}, err
	}
	g := port.Grant{ID: id.New(id.Grant), RealmID: c.RealmID, ClientID: cl.ID, UserID: c.UserID, OrgID: c.OrgID, SID: c.SID,
		Scopes: c.Scopes, AuthMethods: c.AMR, AuthTime: c.AuthTime, CreatedAt: now, ExpiresAt: now.Add(ttlOr(t.GrantTTL, DefaultRefreshTTL))}
	if err := tx.Grants().Create(ctx, g); err != nil {
		return Issued{}, err
	}
	out, err := t.issue(ctx, tx, cl, g, c.Nonce, now)
	if err != nil {
		return Issued{}, err
	}
	u, err := tx.Users().Get(ctx, c.RealmID, c.UserID)
	if err != nil {
		return Issued{}, err
	}
	orgPublicID, err := t.orgPublicID(ctx, tx, c.RealmID, c.OrgID)
	if err != nil {
		return Issued{}, err
	}
	_, err = eventlog.Record(ctx, tx, t.Clock, audit.Event{
		Type: "oidc.authorized", Result: audit.ResultSuccess, RealmID: c.RealmID, OrgID: orgPublicID,
		Actor: audit.Actor{Type: "user", ID: u.PublicID}, SessionID: c.SID, RequestID: requestID,
		Details: map[string]any{"client_id": cl.PublicID, "scopes": c.Scopes},
	})
	return out, err
}

// issue はアクセストークンと ID トークンを発行する。
func (t *Tokens) issue(ctx context.Context, tx port.Tx, cl port.Client, g port.Grant, nonce string, now time.Time) (Issued, error) {
	ttl := ttlOr(t.AccessTokenTTL, DefaultAccessTokenTTL)
	tid, token, hash, err := newOpaque(id.AccessToken)
	if err != nil {
		return Issued{}, err
	}
	if err := tx.OIDCTokens().Create(ctx, port.OIDCToken{ID: tid, RealmID: g.RealmID, GrantID: g.ID, Kind: port.TokenAccess, Hash: hash,
		CreatedAt: now, ExpiresAt: now.Add(ttl)}); err != nil {
		return Issued{}, err
	}
	claims, err := t.userClaims(ctx, tx, g)
	if err != nil {
		return Issued{}, err
	}
	claims["iss"], claims["aud"], claims["azp"] = t.Issuer, cl.PublicID, cl.PublicID
	claims["iat"], claims["exp"] = now.Unix(), now.Add(ttlOr(t.IDTokenTTL, DefaultIDTokenTTL)).Unix()
	claims["auth_time"], claims["amr"], claims["sid"] = g.AuthTime.Unix(), g.AuthMethods, g.SID
	if nonce != "" {
		claims["nonce"] = nonce
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return Issued{}, err
	}
	idToken, err := t.Keys.Sign(ctx, tx, g.RealmID, cl.IDTokenAlg, "JWT", b)
	if err != nil {
		return Issued{}, err
	}
	return Issued{AccessToken: token, ExpiresIn: ttl, IDToken: idToken, Scopes: g.Scopes, Grant: g}, nil
}

// userClaims は sub と、スコープで許したユーザーのクレーム（org_id、email）を返す。ID トークンと UserInfo で共通。
// メールは Org の文脈で見せてよいもの（Membership に結び付けたメール。4.4）だけ。
func (t *Tokens) userClaims(ctx context.Context, tx port.Tx, g port.Grant) (map[string]any, error) {
	u, err := tx.Users().Get(ctx, g.RealmID, g.UserID)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{"sub": u.PublicID}
	orgPublicID, err := t.orgPublicID(ctx, tx, g.RealmID, g.OrgID)
	if err != nil {
		return nil, err
	}
	if orgPublicID != "" {
		claims["org_id"] = orgPublicID
	}
	if !slices.Contains(g.Scopes, ScopeEmail) {
		return claims, nil
	}
	e, ok, err := t.email(ctx, tx, g)
	// アドレスを保存しない構成（index_only）では出さない。
	if err != nil || !ok || len(e.Ciphertext) == 0 {
		return claims, err
	}
	addr, err := t.Accounts.EmailAddress(ctx, tx, e)
	if errors.Is(err, pii.ErrShredded) {
		return claims, nil
	}
	if err != nil {
		return nil, err
	}
	claims["email"], claims["email_verified"] = addr, e.VerifiedAt != nil
	return claims, nil
}

func (t *Tokens) email(ctx context.Context, tx port.Tx, g port.Grant) (port.UserEmail, bool, error) {
	if g.OrgID != "" {
		m, err := tx.Memberships().GetByUserOrg(ctx, g.RealmID, g.UserID, g.OrgID)
		if errors.Is(err, errs.NotFound) {
			return port.UserEmail{}, false, nil
		}
		if err != nil {
			return port.UserEmail{}, false, err
		}
		e, err := org.BoundEmail(ctx, tx, m)
		if errors.Is(err, errs.NotFound) {
			return port.UserEmail{}, false, nil
		}
		return e, err == nil, err
	}
	es, err := tx.Emails().ListByUser(ctx, g.RealmID, g.UserID)
	if err != nil {
		return port.UserEmail{}, false, err
	}
	for _, e := range es {
		if e.IsPrimary {
			return e, true, nil
		}
	}
	return port.UserEmail{}, false, nil
}

func (t *Tokens) orgPublicID(ctx context.Context, tx port.Tx, realmID, orgID string) (string, error) {
	if orgID == "" {
		return "", nil
	}
	o, err := tx.Orgs().Get(ctx, realmID, orgID)
	if err != nil {
		return "", err
	}
	return o.PublicID, nil
}

// alive は認可の元になったログインの系列と、認可した Org がまだ使えるかを確かめる。使えなければ ErrInvalidToken。
// 次に状態が変わる時刻（キャッシュの期限に使う）を返す。
func (t *Tokens) alive(ctx context.Context, tx port.Tx, realmID, sid, userID, orgID string, now time.Time) error {
	_, err := t.aliveUntil(ctx, tx, realmID, sid, userID, orgID, now)
	return err
}

func (t *Tokens) aliveUntil(ctx context.Context, tx port.Tx, realmID, sid, userID, orgID string, now time.Time) (time.Time, error) {
	s, next, err := t.Sessions.CheckLineage(ctx, tx, realmID, sid, now)
	if errors.Is(err, session.ErrInvalid) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	if s.PrincipalID != userID {
		return time.Time{}, ErrInvalidToken
	}
	if orgID != "" && t.Orgs != nil {
		at, err := t.Orgs.CheckActive(ctx, tx, realmID, userID, orgID, now)
		if _, ok := errors.AsType[errs.Denial](err); ok || errors.Is(err, errs.PermissionDenied) || errors.Is(err, errs.NotFound) {
			return time.Time{}, ErrInvalidToken
		}
		if err != nil {
			return time.Time{}, err
		}
		if at != nil && at.Before(next) {
			next = *at
		}
	}
	return next, nil
}

// Access は検証したアクセストークン。
type Access struct {
	Token  port.OIDCToken
	Grant  port.Grant
	Client port.Client
	// Next は検証の結果が変わりうる次の時刻（トークンの期限、系列・Org の状態の変わり目）。
	Next time.Time
}

// Validate はアクセストークンを検証する。使えないトークンは ErrInvalidToken（理由は返さない）。
func (t *Tokens) Validate(ctx context.Context, tx port.Tx, realmID, token string) (Access, error) {
	tid, hash, ok := splitOpaque(token)
	if !ok {
		return Access{}, ErrInvalidToken
	}
	now := t.Clock.Now()
	tok, err := tx.OIDCTokens().Get(ctx, realmID, tid)
	if errors.Is(err, errs.NotFound) {
		return Access{}, ErrInvalidToken
	}
	if err != nil {
		return Access{}, err
	}
	if tok.Kind != port.TokenAccess || subtle.ConstantTimeCompare(tok.Hash, hash) != 1 || !now.Before(tok.ExpiresAt) {
		return Access{}, ErrInvalidToken
	}
	g, err := tx.Grants().Get(ctx, realmID, tok.GrantID)
	if errors.Is(err, errs.NotFound) {
		return Access{}, ErrInvalidToken
	}
	if err != nil {
		return Access{}, err
	}
	if (g.RevokedAt != nil && !now.Before(*g.RevokedAt)) || !now.Before(g.ExpiresAt) {
		return Access{}, ErrInvalidToken
	}
	cl, err := tx.Clients().Get(ctx, realmID, g.ClientID)
	if errors.Is(err, errs.NotFound) {
		return Access{}, ErrInvalidToken
	}
	if err != nil {
		return Access{}, err
	}
	next, err := t.aliveUntil(ctx, tx, realmID, g.SID, g.UserID, g.OrgID, now)
	if err != nil {
		return Access{}, err
	}
	for _, at := range []time.Time{tok.ExpiresAt, g.ExpiresAt} {
		if at.Before(next) {
			next = at
		}
	}
	if g.RevokedAt != nil && g.RevokedAt.Before(next) {
		next = *g.RevokedAt
	}
	return Access{Token: tok, Grant: g, Client: cl, Next: next}, nil
}

// UserInfo はアクセストークンの認可で見せてよいユーザーのクレームを返す（OIDC Core 5.3）。
func (t *Tokens) UserInfo(ctx context.Context, tx port.Tx, a Access) (map[string]any, error) {
	return t.userClaims(ctx, tx, a.Grant)
}
