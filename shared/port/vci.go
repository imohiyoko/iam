package port

import (
	"context"
	"time"
)

// OpenID4VCI の発行者（フィーチャー openid4vci。ADR 0119）の Repository。

// VCICredentialConfiguration は vci_credential_configurations の1行（発行する資格情報の定義）。
type VCICredentialConfiguration struct {
	ID      string // 外部 ID（管理 API で使う）
	RealmID string
	// ConfigurationID はメタデータの credential_configurations_supported のキー。realm の中で一意。
	ConfigurationID string
	// Scope は Authorization Code Flow で要求するスコープ（空なら無し）。一意かは authn/vci が確かめる。
	Scope string
	// Config は残りの設定（JSON。形は authn/vci の Config）。
	Config    []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// VCIIssuedCredential は vci_issued_credentials の1行（発行した資格情報の記録）。クレームの値は持たない。
type VCIIssuedCredential struct {
	ID      string // 外部 ID
	RealmID string
	UserID  string // 内部 ID
	// ConfigurationID は発行したときの定義の configuration_id。
	ConfigurationID string
	// StatusIndex は status list の番号。realm の中で一意。
	StatusIndex int
	// HolderJKT は資格情報を結び付けた鍵の JWK Thumbprint（RFC 7638。base64url）。
	HolderJKT string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// RevokedAt は失効させた時刻（nil なら有効）。
	RevokedAt *time.Time
}

// VCIRepo は資格情報の定義と発行の記録の Repository。
type VCIRepo interface {
	// CreateConfiguration は ID・(realm, ConfigurationID) が重複すれば errs.Conflict を返す。
	CreateConfiguration(ctx context.Context, c VCICredentialConfiguration) error
	// GetConfiguration は ID で引く。無ければ errs.NotFound。
	GetConfiguration(ctx context.Context, realmID, id string) (VCICredentialConfiguration, error)
	// GetConfigurationByConfigurationID は configuration_id（完全一致）で引く。無ければ errs.NotFound。
	GetConfigurationByConfigurationID(ctx context.Context, realmID, configurationID string) (VCICredentialConfiguration, error)
	// ListConfigurations は realm の定義を作成時刻の順（同時刻は ID の順）に返す。
	ListConfigurations(ctx context.Context, realmID string) ([]VCICredentialConfiguration, error)
	// UpdateConfiguration は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound、ConfigurationID が重複すれば errs.Conflict。
	UpdateConfiguration(ctx context.Context, c VCICredentialConfiguration) error
	// DeleteConfiguration は定義を消す（発行の記録は残す）。無ければ errs.NotFound。
	DeleteConfiguration(ctx context.Context, realmID, id string) error

	// CreateCredential は ID・(realm, StatusIndex) が重複すれば errs.Conflict を返す。
	CreateCredential(ctx context.Context, c VCIIssuedCredential) error
	// GetCredential は ID で引く。無ければ errs.NotFound。
	GetCredential(ctx context.Context, realmID, id string) (VCIIssuedCredential, error)
	// ListCredentialsByUser は本人の記録を発行の新しい順（同時刻は ID の逆順）に返す。
	ListCredentialsByUser(ctx context.Context, realmID, userID string) ([]VCIIssuedCredential, error)
	// RevokeCredential は失効させた時刻を記録する。無ければ errs.NotFound。失効済みなら何もしない。
	RevokeCredential(ctx context.Context, realmID, id string, at time.Time) error
	// RevokeCredentialsByUser は本人のまだ失効していない記録を全部失効させる（アカウントの消去）。
	RevokeCredentialsByUser(ctx context.Context, realmID, userID string, at time.Time) error
	// ListRevokedIndexes は realm の、失効させていて期限が now より後の記録の status の番号を返す（順は問わない）。
	ListRevokedIndexes(ctx context.Context, realmID string, now time.Time) ([]int, error)
	// DeleteExpiredCredentials は realm の、期限が now 以前の記録を最大 limit 件消し、その数を返す。
	DeleteExpiredCredentials(ctx context.Context, realmID string, now time.Time, limit int) (int, error)

	// Count は全 realm の定義と発行の記録の数（フィーチャーの無効化）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm の定義と発行の記録を最大 limit 件消し、その数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
