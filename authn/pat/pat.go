// Package pat は本人の Personal Access Token を扱う（フィーチャー personal_access_tokens。ADR 0109）。
//
// トークンは "iampat_<ID>_<秘密><検査>"（token.go）。DB には秘密の SHA-256 だけを置き、定数時間で照合する。スコープは
// 権限の名前で、判定（authz/check）が本人の権限をスコープに絞る（AuthContext.Scoped）。このパッケージはトークンと本人と
// realm のポリシーを確かめるだけで、権限は見ない。
package pat

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature は本人の Personal Access Token（既定オフ）。
var Feature = feature.Feature{Name: feature.PersonalAccessTokens, DataVersion: 1}

const (
	// AMR は PAT で認証した主体の amr（判定の文脈。ADR 0084）。
	AMR = "pat"
	// TokenType はイントロスペクションの token_type。
	TokenType = "personal_access_token"
)

// 監査ログの種類。
const (
	EventCreated       = "personal_access_token.created"
	EventRevoked       = "personal_access_token.revoked"
	EventPolicyUpdated = "personal_access_token.policy_updated"
)

// 取り消しの理由。
const (
	ReasonUser      = "user"
	ReasonOperator  = "operator"
	ReasonRevokeAll = "revoke_all"
	ReasonMerged    = "merged"
)

// 上限。
const (
	MaxScopes        = 20
	MaxNameLength    = 100
	MaxAllowedScopes = 100
	// touchInterval は最後に使った時刻を書き直す間隔（毎回は書かない）。
	touchInterval = time.Minute
)

var (
	// ErrInvalid はトークンが使えない（形・秘密・取り消し・期限・本人の状態・ポリシー）。理由は返さない。
	ErrInvalid = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "personal access token invalid")
	// ErrNotFound は本人のトークンに無い ID。
	ErrNotFound = errs.WithCode(errs.KindNotFound, "not_found", "personal access token not found")

	errInvalidName    = errs.WithCode(errs.KindInvalid, "invalid_name", "name must be 1 to 100 printable characters")
	errInvalidScope   = errs.WithCode(errs.KindInvalid, "invalid_scope", "scopes must be 1 to 20 permission names")
	errScopeForbidden = errs.WithCode(errs.KindInvalid, "scope_not_allowed", "a scope is not allowed by the realm policy")
	errInvalidExpiry  = errs.WithCode(errs.KindInvalid, "invalid_expiry", "expires_at must be in the future and within the maximum lifetime")
	errExpiryRequired = errs.WithCode(errs.KindInvalid, "expiry_required", "the realm policy requires an expiry")
	errTokenLimit     = errs.WithCode(errs.KindConflict, "token_limit", "too many active personal access tokens")
	errInvalidPolicy  = errs.WithCode(errs.KindInvalid, "invalid_policy", "invalid personal access token policy")
)

// Config はホスト先の設定（設定ファイルの personal_access_tokens）。
type Config struct {
	// MaxPerUser はユーザーごとの有効なトークンの上限。
	MaxPerUser int
	// MaxLifetime は寿命の上限（0 なら上限なし）。realm のポリシーはこれより長くできない。
	MaxLifetime time.Duration
}

// ScopeRules はスコープ（権限の名前）の形と照合。authn は authz を import しないので、組み立てる側が authz/role のものを渡す。
type ScopeRules struct {
	// Valid は権限の名前の形か（role.ValidPermission）。
	Valid func(scope string) bool
	// Covered は want が granted のどれかに含まれるか（role.Covered。`x:*` は `x:` のすべて）。
	Covered func(granted []string, want string) bool
}

// Service は PAT の作成・一覧・取り消し・検証と realm のポリシー。
type Service struct {
	Clock  clock.Clock
	Config Config
	Scopes ScopeRules
}

// Policy は realm のポリシー。
type Policy struct {
	// MaxLifetime は realm の寿命の上限（0 なら realm では決めない）。
	MaxLifetime time.Duration
	// AllowedScopes は作れるスコープ（権限の名前。`x:*` も可）。空なら形だけを確かめる。
	AllowedScopes []string
	// RequireExpiry なら期限の無いトークンを作れない・使えない。
	RequireExpiry bool
	// UpdatedAt は最後に変えた時刻（置いていなければ nil）。
	UpdatedAt *time.Time
}

// EffectiveMaxLifetime は効く寿命の上限（realm とホスト先の短い方。どちらも無ければ 0）。
func (s *Service) EffectiveMaxLifetime(p Policy) time.Duration {
	h, r := s.Config.MaxLifetime, p.MaxLifetime
	switch {
	case h <= 0:
		return max(r, 0)
	case r <= 0:
		return h
	}
	return min(h, r)
}

// Policy は realm のポリシーを返す（置いていなければ零値）。
func (s *Service) Policy(ctx context.Context, tx port.Tx, realmID string) (Policy, error) {
	row, err := tx.PersonalAccessTokens().GetPolicy(ctx, realmID)
	if errors.Is(err, errs.NotFound) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	at := row.UpdatedAt
	return Policy{MaxLifetime: time.Duration(row.MaxLifetimeSeconds) * time.Second, AllowedScopes: row.AllowedScopes,
		RequireExpiry: row.RequireExpiry, UpdatedAt: &at}, nil
}

// SetPolicy は realm のポリシーを置き換え、監査ログに残す。寿命は秒の単位で、ホスト先の上限を超えられない。
func (s *Service) SetPolicy(ctx context.Context, tx port.Tx, realmID string, p Policy, r Request) (Policy, error) {
	if p.MaxLifetime < 0 || p.MaxLifetime%time.Second != 0 || (s.Config.MaxLifetime > 0 && p.MaxLifetime > s.Config.MaxLifetime) {
		return Policy{}, errInvalidPolicy
	}
	scopes, ok := s.normalizeScopes(p.AllowedScopes, MaxAllowedScopes)
	if !ok {
		return Policy{}, errInvalidPolicy
	}
	now := s.Clock.Now()
	row := port.PersonalAccessTokenPolicy{RealmID: realmID, MaxLifetimeSeconds: int64(p.MaxLifetime / time.Second), AllowedScopes: scopes,
		RequireExpiry: p.RequireExpiry, UpdatedAt: now}
	if err := tx.PersonalAccessTokens().PutPolicy(ctx, row); err != nil {
		return Policy{}, err
	}
	if scopes == nil {
		scopes = []string{}
	}
	if err := s.record(ctx, tx, realmID, EventPolicyUpdated, r, map[string]any{"max_lifetime_seconds": row.MaxLifetimeSeconds,
		"allowed_scopes": scopes, "require_expiry": p.RequireExpiry}); err != nil {
		return Policy{}, err
	}
	return Policy{MaxLifetime: p.MaxLifetime, AllowedScopes: row.AllowedScopes, RequireExpiry: p.RequireExpiry, UpdatedAt: &now}, nil
}

// normalizeScopes は権限の名前の一覧を確かめ、重複を除いて並べる。0 件なら nil。max を超えるか形が違えば ok は false。
func (s *Service) normalizeScopes(in []string, maxN int) ([]string, bool) {
	if len(in) > maxN {
		return nil, false
	}
	for _, sc := range in {
		if !s.Scopes.Valid(sc) {
			return nil, false
		}
	}
	if len(in) == 0 {
		return nil, true
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out), true
}

// allowedScopes はポリシーが許すスコープだけを残す（AllowedScopes が空なら全部）。
func (s *Service) allowedScopes(scopes []string, p Policy) []string {
	if len(p.AllowedScopes) == 0 {
		return slices.Clone(scopes)
	}
	var out []string
	for _, sc := range scopes {
		if s.Scopes.Covered(p.AllowedScopes, sc) {
			out = append(out, sc)
		}
	}
	return out
}

// Request は操作の行為者と接続元（監査ログに残す）。
type Request struct {
	Actor                    audit.Actor
	IP, UserAgent, RequestID string
}

func (s *Service) record(ctx context.Context, tx port.Tx, realmID, typ string, r Request, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: r.Actor,
		IP: r.IP, UserAgent: r.UserAgent, RequestID: r.RequestID, Details: details})
	return err
}

// CreateInput は作るトークン。
type CreateInput struct {
	RealmID string
	User    port.User
	Name    string
	Scopes  []string
	// ExpiresAt は期限。nil なら、上限があれば上限の期限を付け、無ければ期限なし（ポリシーが許すとき）。
	ExpiresAt *time.Time
	Request   Request
}

// Created は作ったトークン。Token は1回だけ返す。
type Created struct {
	Token string
	PAT   port.PersonalAccessToken
}

// validName は名前が 1〜MaxNameLength 文字の、制御文字を含まない UTF-8 か。
func validName(s string) bool {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > MaxNameLength || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// Create はトークンを作る。名前・スコープ・期限をポリシーで確かめ、ユーザーごとの上限を数える。
func (s *Service) Create(ctx context.Context, tx port.Tx, in CreateInput) (Created, error) {
	if !validName(in.Name) {
		return Created{}, errInvalidName
	}
	scopes, ok := s.normalizeScopes(in.Scopes, MaxScopes)
	if !ok || len(scopes) == 0 {
		return Created{}, errInvalidScope
	}
	p, err := s.Policy(ctx, tx, in.RealmID)
	if err != nil {
		return Created{}, err
	}
	if len(s.allowedScopes(scopes, p)) != len(scopes) {
		return Created{}, errScopeForbidden
	}
	now := s.Clock.Now()
	limit := s.EffectiveMaxLifetime(p)
	var exp *time.Time
	switch {
	case in.ExpiresAt != nil:
		e := in.ExpiresAt.UTC()
		if !e.After(now) || (limit > 0 && e.After(now.Add(limit))) {
			return Created{}, errInvalidExpiry
		}
		exp = &e
	case limit > 0:
		e := now.Add(limit)
		exp = &e
	case p.RequireExpiry:
		return Created{}, errExpiryRequired
	}
	ts, err := tx.PersonalAccessTokens().ListByUser(ctx, in.RealmID, in.User.ID)
	if err != nil {
		return Created{}, err
	}
	active := 0
	for _, t := range ts {
		if t.RevokedAt == nil && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt)) {
			active++
		}
	}
	if active >= max(s.Config.MaxPerUser, 1) {
		return Created{}, errTokenLimit
	}
	secret, err := newSecret()
	if err != nil {
		return Created{}, err
	}
	t := port.PersonalAccessToken{ID: id.NewExternal(id.PAT), RealmID: in.RealmID, UserID: in.User.ID, Name: in.Name, Scopes: scopes,
		Hash: hashSecret(secret), CreatedAt: now, ExpiresAt: exp}
	if err := tx.PersonalAccessTokens().Create(ctx, t); err != nil {
		return Created{}, err
	}
	details := map[string]any{"token_id": t.ID, "user_id": in.User.PublicID, "scopes": scopes}
	if exp != nil {
		details["expires_at"] = exp.Format(time.RFC3339)
	}
	if err := s.record(ctx, tx, in.RealmID, EventCreated, in.Request, details); err != nil {
		return Created{}, err
	}
	return Created{Token: format(t.ID, secret), PAT: t}, nil
}

// List はユーザーのトークンを作成時刻の順に返す（取り消した・期限切れも含む）。
func (s *Service) List(ctx context.Context, tx port.Tx, realmID, userID string) ([]port.PersonalAccessToken, error) {
	return tx.PersonalAccessTokens().ListByUser(ctx, realmID, userID)
}

// Revoke はユーザー（本人か運営者が指した人）のトークンを取り消す。ほかの人のトークンと無い ID は ErrNotFound。もう取り消して
// いれば何もしない。
func (s *Service) Revoke(ctx context.Context, tx port.Tx, realmID string, u port.User, tokenID, reason string, r Request) error {
	if !id.Valid(id.PAT, tokenID) {
		return ErrNotFound
	}
	t, err := tx.PersonalAccessTokens().Get(ctx, realmID, tokenID)
	if errors.Is(err, errs.NotFound) || (err == nil && t.UserID != u.ID) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	revoked, err := tx.PersonalAccessTokens().Revoke(ctx, realmID, tokenID, s.Clock.Now(), reason)
	if err != nil || !revoked {
		return err
	}
	return s.record(ctx, tx, realmID, EventRevoked, r, map[string]any{"token_id": tokenID, "user_id": u.PublicID, "reason": reason})
}

// RevokeAll はユーザーの取り消していないトークンをすべて取り消し、数を返す（侵害時の初動・統合）。1 件以上なら監査ログに残す。
func (s *Service) RevokeAll(ctx context.Context, tx port.Tx, realmID string, u port.User, reason string, r Request) (int, error) {
	n, err := tx.PersonalAccessTokens().RevokeByUser(ctx, realmID, u.ID, s.Clock.Now(), reason)
	if err != nil || n == 0 {
		return n, err
	}
	return n, s.record(ctx, tx, realmID, EventRevoked, r, map[string]any{"user_id": u.PublicID, "reason": reason, "count": n})
}

// Authenticated は確かめたトークンと本人。
type Authenticated struct {
	Token port.PersonalAccessToken
	User  port.User
	// Scopes は今効くスコープ（realm のポリシーで外したものを除く。1 個以上）。
	Scopes []string
	// ExpiresAt は今効く期限（トークンの期限と、ポリシーの寿命の上限の早い方。無ければ nil）。
	ExpiresAt *time.Time
}

// Authenticate はトークンを確かめる。使えなければ ErrInvalid（理由は返さない）、ストレージの障害はそれ以外のエラー
// （呼び出し側は認証の失敗として扱わない）。最後に使った時刻を、前の記録から touchInterval 以上たっていれば書く。
func (s *Service) Authenticate(ctx context.Context, tx port.Tx, realmID, token string) (Authenticated, error) {
	tokenID, secret, ok := Parse(token)
	if !ok {
		return Authenticated{}, ErrInvalid
	}
	t, err := tx.PersonalAccessTokens().Get(ctx, realmID, tokenID)
	if err != nil {
		return Authenticated{}, invalidOr(err)
	}
	if subtle.ConstantTimeCompare(t.Hash, hashSecret(secret)) != 1 || t.RevokedAt != nil {
		return Authenticated{}, ErrInvalid
	}
	p, err := s.Policy(ctx, tx, realmID)
	if err != nil {
		return Authenticated{}, errs.Wrap(errs.KindUnavailable, err, "personal access token: policy")
	}
	now := s.Clock.Now()
	exp := t.ExpiresAt
	if limit := s.EffectiveMaxLifetime(p); limit > 0 {
		if end := t.CreatedAt.Add(limit); exp == nil || end.Before(*exp) {
			exp = &end
		}
	}
	if (exp != nil && !now.Before(*exp)) || (p.RequireExpiry && t.ExpiresAt == nil && exp == nil) {
		return Authenticated{}, ErrInvalid
	}
	scopes := s.allowedScopes(t.Scopes, p)
	if len(scopes) == 0 {
		return Authenticated{}, ErrInvalid
	}
	u, err := tx.Users().Get(ctx, realmID, t.UserID)
	if err != nil {
		return Authenticated{}, invalidOr(err)
	}
	// 作成から今までに停止があれば、解いた後も使えない（セッションと同じ。4.7）。
	if _, err := account.Check(ctx, tx, u, t.CreatedAt, now); err != nil {
		if _, ok := errors.AsType[*account.UnavailableError](err); ok || errors.Is(err, account.ErrInactive) {
			return Authenticated{}, ErrInvalid
		}
		return Authenticated{}, errs.Wrap(errs.KindUnavailable, err, "personal access token: account")
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= touchInterval {
		if err := tx.PersonalAccessTokens().Touch(ctx, realmID, t.ID, now); err != nil {
			return Authenticated{}, invalidOr(err)
		}
		t.LastUsedAt = &now
	}
	return Authenticated{Token: t, User: u, Scopes: scopes, ExpiresAt: exp}, nil
}

// invalidOr は見つからなければ ErrInvalid、それ以外はストレージの障害として返す。
func invalidOr(err error) error {
	if errors.Is(err, errs.NotFound) {
		return ErrInvalid
	}
	return errs.Wrap(errs.KindUnavailable, err, "personal access token: authenticate")
}
