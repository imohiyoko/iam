package port

import (
	"context"
	"time"
)

// 自前の API（リソースサーバー）の登録（Resource Indicators、RFC 8707。フィーチャー resource_indicators。ADR 0112）。

// OAuthResource は authn_oauth_resources の1行。連携先とサービスアカウントは、ここで許されたリソースだけを resource に指定でき、
// 発行するアクセストークンの aud は URI、スコープは Scopes の中から選ぶ。
type OAuthResource struct {
	ID      string // 外部 ID（管理 API で使う）
	RealmID string
	// URI は resource の値（絶対 URI、フラグメントなし）。realm の中で一意。
	URI  string
	Name string
	// Scopes はこのリソースで使えるスコープ。
	Scopes []string
	// Clients は認可コードフローで resource に指定してよい連携先（client_id）。
	Clients []string
	// ServiceAccounts は client credentials で resource に指定してよいサービスアカウント（ID）。
	ServiceAccounts []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// OAuthResourceRepo は authn_oauth_resources の Repository。
type OAuthResourceRepo interface {
	// Create は ID・(realm, URI) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, r OAuthResource) error
	// Get は ID で引く。無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (OAuthResource, error)
	// GetByURI は URI（完全一致）で引く。無ければ errs.NotFound。
	GetByURI(ctx context.Context, realmID, uri string) (OAuthResource, error)
	// List は realm のリソースを作成時刻の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]OAuthResource, error)
	// Update は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound、URI が重複すれば errs.Conflict。
	Update(ctx context.Context, r OAuthResource) error
	// Delete はリソースを消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
	// Count は全 realm のリソースの数（フィーチャーの無効化）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm のリソースを最大 limit 件消し、その数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
