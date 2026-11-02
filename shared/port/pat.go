package port

import (
	"context"
	"time"
)

// PersonalAccessToken は authn_personal_access_tokens の1行（ADR 0109）。ID は外部 ID（pat_…）で、トークンの文字列の一部。
// 秘密は SHA-256（Hash）だけを持つ。Scopes は権限の名前（重複なし、順に並べたもの）。
type PersonalAccessToken struct {
	ID           string
	RealmID      string
	UserID       string // 内部 ID
	Name         string
	Scopes       []string
	Hash         []byte
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// PersonalAccessTokenPolicy は realm の PAT のポリシー（authn_personal_access_token_policies の1行。ADR 0109）。
// MaxLifetimeSeconds が 0 なら上限なし。AllowedScopes が空なら形だけを確かめる。
type PersonalAccessTokenPolicy struct {
	RealmID            string
	MaxLifetimeSeconds int64
	AllowedScopes      []string
	RequireExpiry      bool
	UpdatedAt          time.Time
}

// PersonalAccessTokenRepo は authn_personal_access_tokens と authn_personal_access_token_policies の Repository。
type PersonalAccessTokenRepo interface {
	// Create は (realm, ID) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, t PersonalAccessToken) error
	// Get は無ければ（別の realm も）errs.NotFound。
	Get(ctx context.Context, realmID, id string) (PersonalAccessToken, error)
	// ListByUser はユーザーのトークンを作成時刻の順（同時刻は ID の順）に返す（取り消したものも含む）。
	ListByUser(ctx context.Context, realmID, userID string) ([]PersonalAccessToken, error)
	// Touch は最後に使った時刻を書く。無ければ errs.NotFound。
	Touch(ctx context.Context, realmID, id string, at time.Time) error
	// Revoke は取り消していないトークンを取り消し、取り消したかを返す（もう取り消していれば false）。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) (bool, error)
	// RevokeByUser はユーザーの取り消していないトークンをすべて取り消し、取り消した数を返す。
	RevokeByUser(ctx context.Context, realmID, userID string, at time.Time, reason string) (int, error)
	// DeleteByUser はユーザーのトークンをすべて消し、消した数を返す（消去。4.10）。
	DeleteByUser(ctx context.Context, realmID, userID string) (int, error)
	// GetPolicy は realm のポリシーを返す。置いていなければ errs.NotFound。
	GetPolicy(ctx context.Context, realmID string) (PersonalAccessTokenPolicy, error)
	// PutPolicy は realm のポリシーを置き換える（無ければ作る）。
	PutPolicy(ctx context.Context, p PersonalAccessTokenPolicy) error
	// Count は全 realm のトークンとポリシーの数（フィーチャーの無効化。11.12）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm からトークン、続けてポリシーを最大 limit 件消し、消した件数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
