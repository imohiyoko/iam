// Package port は外部依存とつなぐポート（Go のインターフェース）を定義する（design.md 2.4、ADR 0003）。
//
// コア（authn、authz、shared）はこのインターフェースだけに依存し、adapters/ を import しない。
// Clock ポートは shared/clock にある。
package port

import (
	"context"
	"errors"
	"io"
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
	// EventSubscriptions はイベントの Webhook の購読（フィーチャー event_subscriptions。ADR 0100）。
	EventSubscriptions() EventSubscriptionRepo

	Users() UserRepo
	Emails() EmailRepo
	Identities() IdentityRepo
	// Credentials は認証方式のプラグインの汎用の認証情報（ADR 0090、0092）。
	Credentials() CredentialRepo
	// KnownDevices は本人がログインした端末（フィーチャー device_recognition。ADR 0105）。
	KnownDevices() KnownDeviceRepo
	RecoveryCodes() RecoveryCodeRepo
	Suspensions() SuspensionRepo
	ScheduledEvents() ScheduledEventRepo
	Connections() ConnectionRepo
	// DirectoryGroups はディレクトリの同期が管理する Group の対応（フィーチャー ldap。ADR 0102）。
	DirectoryGroups() DirectoryGroupRepo
	Sessions() SessionRepo
	Orgs() OrgRepo
	Memberships() MembershipRepo
	Invitations() InvitationRepo
	QuotaGrants() QuotaGrantRepo
	OrgDomains() OrgDomainRepo
	ServiceAccounts() ServiceAccountRepo
	RoleBindings() RoleBindingRepo
	Roles() RoleRepo
	Groups() GroupRepo
	Attributes() AttributeRepo
	RiskTypes() RiskTypeRepo
	ActionNamespaces() ActionNamespaceRepo
	// PersonalAccessTokens は本人の Personal Access Token と realm のポリシー（フィーチャー personal_access_tokens。ADR 0109）。
	PersonalAccessTokens() PersonalAccessTokenRepo
	Clients() ClientRepo
	SigningKeys() SigningKeyRepo
	Grants() GrantRepo
	OIDCTokens() OIDCTokenRepo
	// WSFed は WS-Federation の RP と署名の証明書（フィーチャー wsfed。ADR 0110）。
	WSFed() WSFedRepo
	// SAMLIdP は SAML の SP の登録と IdP の署名の証明書（フィーチャー saml_idp。ADR 0115）。
	SAMLIdP() SAMLIdPRepo
	// OAuthResources は自前の API（リソースサーバー）の登録（フィーチャー resource_indicators。ADR 0112）。
	OAuthResources() OAuthResourceRepo
	// WorkloadIdentity は Workload Identity Federation の発行者と結び付け（フィーチャー workload_identity。ADR 0116）。
	WorkloadIdentity() WorkloadIdentityRepo
}

// Realm はユーザー集合の単位（design.md 3.1）。
type Realm struct {
	ID       string
	Slug     string
	Settings []byte // JSON。タイムゾーン、寿命、メールの保持モードなど
	// Hosts はこの realm を指すホスト名（複数 realm。design.md 11.1、ADR 0083）。小文字で、realm をまたいで重複しない。
	Hosts     []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RealmRepo は realms の Repository。
type RealmRepo interface {
	Create(ctx context.Context, r Realm) error // slug かホスト名が重複すれば errs.Conflict
	Get(ctx context.Context, id string) (Realm, error)
	GetBySlug(ctx context.Context, slug string) (Realm, error)
	GetByHost(ctx context.Context, host string) (Realm, error)
	List(ctx context.Context) ([]Realm, error)
	// Update は設定とホスト名（置き換え）と更新時刻を書く。ホスト名が他の realm と重複すれば errs.Conflict。
	Update(ctx context.Context, r Realm) error
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
	// Query は realm のイベントを条件で絞り込み、seq の降順（新しい順）に最大 q.Limit 件返す（ADR 0100）。
	// 絞り込みは索引の列（audit.IndexOf）で行う。呼び出し側はペイロードと条件を突き合わせ直す（audit.Filter.Matches）。
	Query(ctx context.Context, q AuditQuery) ([]audit.Record, error)
	// GetByEventID は realm のイベントをイベント ID で返す。無ければ（保持期間で消したものを含む）errs.NotFound。
	GetByEventID(ctx context.Context, realmID, eventID string) (audit.Record, error)
	// Checkpoint は保持期間による切り詰めの位置（最後に消したレコード。design.md 6.5）を返す。切り詰めていなければ nil。
	Checkpoint(ctx context.Context) (*audit.Checkpoint, error)
	// Truncate は seq が cp.Seq 以下のレコードを消し、チェックポイントを cp にする。
	// 最新のレコードは消さない（Last がチェーンの続きを返せるように。呼び出し側が守る）。
	Truncate(ctx context.Context, cp audit.Checkpoint) error
}

// AuditQuery は監査ログの照会（ADR 0100）。
type AuditQuery struct {
	RealmID string
	audit.Filter
	// BeforeSeq が正なら、seq がこれより小さいものだけを返す（ページング）。
	BeforeSeq int64
	Limit     int
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
	// DeleteDelivered は before より前に配送したメッセージを最大 limit 件消し、消した件数を返す（design.md 9.6）。
	DeleteDelivered(ctx context.Context, before time.Time, limit int) (int, error)
}

// EventSubscription はイベントの Webhook の購読（realm ごと。ADR 0100）。
type EventSubscription struct {
	ID      string // 外部 ID（evs_）
	RealmID string
	URL     string
	// EventTypes は送るイベントの種類。"." で終われば前方一致、ほかは完全一致。空ならすべて。
	EventTypes []string
	// PII は切り詰めた IP と User-Agent の大分類の出し方（omit / pseudonymize）。
	PII     string
	Enabled bool
	// SecretCiphertext は署名の鍵の暗号文（購読の ID を持ち主にしたデータ鍵で暗号化する）。
	SecretCiphertext []byte
	// CreatedBy は作った主体の公開 ID。
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
	EventSubscriptionDelivery
}

// EventSubscriptionDelivery は購読の配送の状態。
type EventSubscriptionDelivery struct {
	// CursorSeq は送り終えた監査ログの seq（これより後を送る）。
	CursorSeq int64
	// Failures は続けて失敗した回数。NextAttemptAt より前は送らない。
	Failures      int
	NextAttemptAt *time.Time
	// LastError は最後の失敗の理由のコード（個人情報を含めない）。成功すれば空。
	LastError       string
	LastDeliveredAt *time.Time
}

// EventSubscriptionRepo は event_subscriptions の Repository。
type EventSubscriptionRepo interface {
	Create(ctx context.Context, s EventSubscription) error // ID が重複すれば errs.Conflict
	Get(ctx context.Context, realmID, id string) (EventSubscription, error)
	// List は realm の購読を作成の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]EventSubscription, error)
	// Update は設定（URL・種類・PII・有効・秘密の暗号文・更新時刻）を書く。配送の状態は変えない。無ければ errs.NotFound。
	Update(ctx context.Context, s EventSubscription) error
	// SetDelivery は配送の状態を書く。CursorSeq は今より大きいときだけ進める（戻さない）。無ければ errs.NotFound。
	SetDelivery(ctx context.Context, realmID, id string, d EventSubscriptionDelivery) error
	Delete(ctx context.Context, realmID, id string) error // 無ければ errs.NotFound
	// Due は全 realm の、有効で NextAttemptAt が now 以前（または無い）購読を、NextAttemptAt の早い順に最大 limit 件返す。
	Due(ctx context.Context, now time.Time, limit int) ([]EventSubscription, error)
	// Count は全 realm の購読の数（フィーチャーの無効化。design.md 11.12）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm の購読を最大 limit 件消し、消した購読の ID を返す（データ鍵は呼び出し側が消す）。
	Purge(ctx context.Context, limit int) ([]string, error)
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
	Category  string     `json:"category,omitempty"`  // suspended の種別
	DeviceID  string     `json:"device_id,omitempty"` // new_device_login の端末（公開 ID。ADR 0105）
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	HasSecret bool       `json:"has_secret"`
}

// Notifier は出来事を外部に渡す。文面・URL・配送は外部が行う（ADR 0031）。
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// SMSMessage は SMS・音声で送るコード（ADR 0104）。0031 の例外として、宛先の番号とコードを事業者に渡す。名前・メールアドレス・
// ユーザーの ID は入れない。
type SMSMessage struct {
	// To は E.164 の番号（+ と数字）。
	To string
	// Channel は "sms" か "voice"。
	Channel string
	// Code は送るコード（数字）。
	Code string
	// ExpiresAt はコードの期限。
	ExpiresAt time.Time
}

// SMSSender は SMS・音声でコードを送る（フィーチャー sms_otp）。エラーなら届かなかったとみなす。
type SMSSender interface {
	Send(ctx context.Context, m SMSMessage) error
}

// PushMessage は本人の端末に送るプッシュの承認の要求（ADR 0104）。照合する番号は入れない。
type PushMessage struct {
	// Token は端末の宛先（FCM の登録トークン、APNs のデバイストークンなど）。
	Token string
	// Platform は端末が登録のときに申告した種類（"apns"・"fcm" など。空でもよい）。
	Platform string
	// ChallengeID と DeviceID は、端末が応答に署名する値。
	ChallengeID string
	DeviceID    string
	ExpiresAt   time.Time
}

// PushSender は本人の端末にプッシュを送る（フィーチャー push_auth）。
type PushSender interface {
	Send(ctx context.Context, m PushMessage) error
}

// BreachChecker は漏洩済みパスワードの確認（design.md 4.1）。パスワードそのものは渡さない。
// 外部に問い合わせるアダプタは k-匿名（SHA-1 の先頭 5 文字）で問い合わせ、残りを手元で照合する。
type BreachChecker interface {
	// Breached は SHA-1（大文字の16進 40 文字）のパスワードが漏洩済みかを返す。
	Breached(ctx context.Context, sha1Hex string) (bool, error)
}

// GeoLocation は接続元の場所（ADR 0105）。分からない項目は零値。
type GeoLocation struct {
	// Country は ISO 3166-1 alpha-2（大文字）。
	Country string
	// ASN は自律システムの番号。0 なら分からない。
	ASN uint32
	// HasCoordinates は Latitude・Longitude があるか。
	HasCoordinates      bool
	Latitude, Longitude float64
}

// GeoIP は接続元の IP から場所を引く（フィーチャー login_risk。ADR 0105）。ログインの経路で呼ぶので、外部に問い合わせない
// （手元のデータベースを引く）実装にする。見つからなければ ok=false。
type GeoIP interface {
	Lookup(ctx context.Context, ip string) (loc GeoLocation, ok bool, err error)
}

// BotVerifier はボットの確認（CAPTCHA・Turnstile など）のトークンを確かめる（フィーチャー bot_protection。ADR 0105）。
// 人と確かめられなければ ErrBotRejected、確かめられなかった（外部の障害など）ならそのほかのエラーを返す。呼び出し側はどちらも
// 通さない（fail-closed）。
type BotVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

// ErrBotRejected はボットの確認のトークンが通らなかったこと。
var ErrBotRejected = errors.New("bot check rejected")

// FIDOMetadataSource は FIDO Metadata Service（MDS3）の BLOB（署名付きの JWT）を取ってくる（フィーチャー passkey_attestation、
// ADR 0096）。署名はコアが設定したルートで確かめるので、アダプタは取り方だけを持つ（ファイル、HTTP など）。
// コアはバックグラウンドで定期的に呼び、ログインと登録の経路では呼ばない（ADR 0010）。
type FIDOMetadataSource interface {
	Fetch(ctx context.Context) ([]byte, error)
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

// AuditKeyStore は監査ログのハッシュチェーンの鍵（ADR 0086）も持つ KeyStore。持たない KeyStore、または鍵を置いていない
// （CurrentAuditKeyID が空を返す）なら、チェーンは鍵なし（SHA-256）のまま。古い鍵は監査ログの保持期間が過ぎるまで消さない。
type AuditKeyStore interface {
	AuditKey(ctx context.Context, keyID string) ([]byte, error)
	CurrentAuditKeyID(ctx context.Context) (string, error)
	// AuditUnkeyedUntil は鍵なしで許す最後の seq（鍵を置く前からのレコード）。鍵を置いていれば、それより後のレコードは
	// 鍵付きでなければ改ざんとみなす。DB の外に置くので、DB だけを書き換えられる人は鍵付きの範囲を縮められない。
	AuditUnkeyedUntil(ctx context.Context) (int64, error)
}

// ---------------------------------------------------------------------------
// EventSink

// EventSink は監査ログなどの外部出力（design.md 6.3）。
// 受け取るイベントは audit.External のもの（全文の暗号文は無く、切り詰めた IP と UA は出力先が出し方を選ぶ。sinkfmt）。
type EventSink interface {
	Emit(ctx context.Context, events []audit.Event) error
}

// Dumper は中身をアダプタに依らない形で書き出し・読み込める Storage（`iam storage export / import`。shared/sqldump）。
// 書き出しは一貫した時点の中身。読み込み先はマイグレーション済みで空でなければならず、全部を1つのトランザクションで入れる。
type Dumper interface {
	Export(ctx context.Context, w io.Writer) (map[string]int, error)
	Import(ctx context.Context, r io.Reader) (map[string]int, error)
}
