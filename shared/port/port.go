// Package port は外部依存とつなぐポート（Go のインターフェース）を定義する（design.md 2.4、ADR 0003）。
//
// コア（authn、authz、shared）はこのインターフェースだけに依存し、adapters/ を import しない。
// Clock ポートは shared/clock にある。
package port

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
)

// ---------------------------------------------------------------------------
// Storage（唯一の必須のポート）

// Storage は永続データのポート。正（source of truth）はここだけ。
//
// コアが前提にするのは、トランザクション（Unit of Work）、一意性、ID・範囲での取得だけ。
// 中身は DB ごとに最適化してよい（ADR 0004）。振る舞いの一致は storagetest で保証する。
type Storage interface {
	// Tx は fn を1つのトランザクションで実行する。fn がエラーを返せばロールバックする。
	// 書き込みを含むトランザクションは直列化される（件数の確認と追加を同じ Tx で行ってよい）。
	Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// Ping は接続を確かめる（ヘルスチェック用）。
	Ping(ctx context.Context) error
	// Now は DB 側の現在時刻を返す（時刻のずれの監視用。design.md 2.7）。
	Now(ctx context.Context) (time.Time, error)
	Close() error
}

// Tx はトランザクション内で使える Repository の集まり。
// Repository はドメインの言葉で定義する。フェーズが進むごとに増える。
type Tx interface {
	Realms() RealmRepo
	Features() FeatureLedger
	DataKeys() DataKeyRepo
	// AuditKeys は監査ログの IP と User-Agent を暗号化する、realm と日ごとの鍵（UserID に持ち主の名前。design.md 9.6、ADR 0063）。
	AuditKeys() DataKeyRepo
	Audit() AuditRepo
	Outbox() OutboxRepo

	Users() UserRepo
	Emails() EmailRepo
	Identities() IdentityRepo
	Passkeys() PasskeyRepo
	TOTP() TOTPRepo
	Passwords() PasswordRepo
	RecoveryCodes() RecoveryCodeRepo
	Suspensions() SuspensionRepo
	ScheduledEvents() ScheduledEventRepo
	Connections() ConnectionRepo
	Sessions() SessionRepo
	Orgs() OrgRepo
	Memberships() MembershipRepo
	Invitations() InvitationRepo
	ServiceAccounts() ServiceAccountRepo
	RoleBindings() RoleBindingRepo
}

// Realm はユーザー集合の単位（design.md 3.1）。
type Realm struct {
	ID        string
	Slug      string
	Settings  []byte // JSON。タイムゾーン、寿命、メールの保持モードなど
	CreatedAt time.Time
}

// RealmRepo は realms の Repository。
type RealmRepo interface {
	Create(ctx context.Context, r Realm) error // slug が重複すれば errs.Conflict
	Get(ctx context.Context, id string) (Realm, error)
	GetBySlug(ctx context.Context, slug string) (Realm, error)
	List(ctx context.Context) ([]Realm, error)
}

// FeatureState はフィーチャー台帳の状態（design.md 11.12）。
type FeatureState string

const (
	FeatureEnabling  FeatureState = "enabling"
	FeatureActive    FeatureState = "active"
	FeatureDisabling FeatureState = "disabling"
)

// FeatureRecord は台帳（installed_features）の1行。
type FeatureRecord struct {
	Feature     string
	State       FeatureState
	DataVersion int
	UpdatedAt   time.Time
}

// FeatureLedger は installed_features の Repository。
type FeatureLedger interface {
	List(ctx context.Context) ([]FeatureRecord, error)
	Put(ctx context.Context, r FeatureRecord) error // 追加または更新
	Delete(ctx context.Context, feature string) error
}

// DataKey はユーザーごとのデータ鍵（マスター鍵で包んだもの。design.md 9.5）。
type DataKey struct {
	UserID     string
	WrappedKey []byte
	KeyID      string // 包んだマスター鍵の ID
	CreatedAt  time.Time
}

// DataKeyRepo は user_data_keys の Repository。
type DataKeyRepo interface {
	Create(ctx context.Context, k DataKey) error // 既にあれば errs.Conflict
	Get(ctx context.Context, userID string) (DataKey, error)
	// Delete はデータ鍵を消す（crypto-shredding）。無ければ何もしない。
	Delete(ctx context.Context, userID string) error
}

// AuditRepo は監査ログ（ハッシュチェーン）の Repository。
//
// 追記は audit.Next で計算したレコードを Append で書く。Last と Append は同じ Tx で行い、
// Tx の直列化によってチェーンが分岐しないことを保証する。
type AuditRepo interface {
	Last(ctx context.Context) (*audit.Record, error) // 空なら nil
	Append(ctx context.Context, r audit.Record) error
	// Scan は seq の昇順に fromSeq 以降を最大 limit 件返す（全 realm。検証用）。
	// 返すレコードには RealmID の列の値も入れる。
	Scan(ctx context.Context, fromSeq int64, limit int) ([]audit.Record, error)
	// ListByRealm は realm のイベントを seq の昇順に返す。
	ListByRealm(ctx context.Context, realmID string, fromSeq int64, limit int) ([]audit.Record, error)
}

// OutboxMessage は外部に送る出来事（少なくとも1回。ID で重複排除する）。
type OutboxMessage struct {
	ID          string
	Topic       string // audit / notification
	Payload     []byte
	CreatedAt   time.Time
	DeliveredAt *time.Time
}

// OutboxRepo は outbox の Repository。
type OutboxRepo interface {
	Add(ctx context.Context, m OutboxMessage) error
	// Pending は未配送のメッセージを作成順（同じ時刻なら追加した順）に最大 limit 件返す。
	// ID は乱数（外部 ID）なので、ID の順には頼らない。
	Pending(ctx context.Context, topic string, limit int) ([]OutboxMessage, error)
	MarkDelivered(ctx context.Context, ids []string, at time.Time) error
}

// ---------------------------------------------------------------------------
// EphemeralStore

// EphemeralStore は短命データ・キャッシュ・カウンタのポート。正にしない。
// TTL は必ず付ける（0 以下はエラー）。
type EphemeralStore interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	// Take は値を返して同時に消す（原子的。1回限りの取り出しに使う）。
	Take(ctx context.Context, key string) ([]byte, bool, error)
	// Incr はカウンタを1増やして新しい値を返す。キーが無ければ ttl 付きで 1 から始める。
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// Shared は複数インスタンスで共有できるかを返す（起動時の構成の検査に使う）。
	Shared() bool
}

// ---------------------------------------------------------------------------
// Notifier

// Notification は通知すべき出来事（design.md 2.4）。秘密と宛先は入れない。
type Notification struct {
	ID        string     `json:"notification_id"`
	Type      string     `json:"type"`
	RealmID   string     `json:"realm_id"`
	UserID    string     `json:"user_id,omitempty"` // 公開 ID（ADR 0045）
	OrgID     string     `json:"org_id,omitempty"`
	Locale    string     `json:"locale,omitempty"`
	Category  string     `json:"category,omitempty"` // suspended の種別
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	HasSecret bool       `json:"has_secret"`
}

// Notifier は出来事を外部に渡す。文面・URL・配送は外部が行う（ADR 0031）。
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// BreachChecker は漏洩済みパスワードの確認（design.md 4.1）。パスワードそのものは渡さない。
// 外部に問い合わせるアダプタは k-匿名（SHA-1 の先頭 5 文字）で問い合わせ、残りを手元で照合する。
type BreachChecker interface {
	// Breached は SHA-1（大文字の16進 40 文字）のパスワードが漏洩済みかを返す。
	Breached(ctx context.Context, sha1Hex string) (bool, error)
}

// ---------------------------------------------------------------------------
// KeyStore

// KeyStore は鍵の保管のポート。鍵は ID（kid）で管理し、コード変更なしで切り替えられる。
// マスター鍵（データ鍵を包む）とインデックス鍵（ブラインドインデックス）は別の鍵にする。
type KeyStore interface {
	MasterKey(ctx context.Context, keyID string) ([]byte, error)
	CurrentMasterKeyID(ctx context.Context) (string, error)
	IndexKey(ctx context.Context, keyID string) ([]byte, error)
	CurrentIndexKeyID(ctx context.Context) (string, error)
}

// ---------------------------------------------------------------------------
// EventSink

// EventSink は監査ログなどの外部出力（design.md 6.3）。
// 受け取るイベントは audit.External で個人情報を外したもの。
type EventSink interface {
	Emit(ctx context.Context, events []audit.Event) error
}
