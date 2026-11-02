package port

import (
	"context"
	"time"
)

// KnownDevice は authn_known_devices の1行（ADR 0105）。本人がログインした端末を、端末の Cookie の乱数のブラインドインデックス
// （Lookup）で覚える。Data は端末の詳細（User-Agent・IP・場所など。形は authn/device）で、ユーザーのデータ鍵で暗号化する。
// ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type KnownDevice struct {
	ID         string
	PublicID   string
	RealmID    string
	UserID     string
	Lookup     []byte
	Data       []byte
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// KnownDeviceRepo は authn_known_devices の Repository。
type KnownDeviceRepo interface {
	// Create は (realm, PublicID) か (realm, UserID, Lookup) が重複すれば errs.Conflict を返す（原子的に判定する）。
	Create(ctx context.Context, d KnownDevice) error
	// ListByUser はユーザーの端末を作成時刻の順（同時刻は ID の順）に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]KnownDevice, error)
	// Seen はデータと最終の利用時刻を置き換える。無ければ errs.NotFound。
	Seen(ctx context.Context, realmID, id string, data []byte, at time.Time) error
	// Delete は端末を消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
	// DeleteByUser はユーザーの端末をすべて消し、消した数を返す（統合。11.6）。
	DeleteByUser(ctx context.Context, realmID, userID string) (int, error)
	// Count は全 realm の端末の数（フィーチャーの無効化。11.12）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm から最大 limit 件消し、消した件数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
