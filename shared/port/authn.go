package port

import (
	"context"
	"time"
)

// 認証側（authn）の Repository（design.md 3.1）。
//
// realm に属するデータの取得は、すべて realm の ID を引数に取る。別の realm のデータは
// 存在しないものとして扱う（errs.NotFound か空の一覧。storagetest で検査する）。

// UserStatus はユーザーの状態。停止は suspensions で表す（design.md 4.7）。
type UserStatus string

const (
	UserActive  UserStatus = "active"
	UserDeleted UserStatus = "deleted"
	UserMerged  UserStatus = "merged"
)

// User は users の1行。個人情報（メールなど）は別の表に暗号化して持つ。
//
// ID は内部 ID で、Storage の外に出さない。外に出すのは PublicID だけ（ADR 0045）。
type User struct {
	ID         string
	PublicID   string // 外部 ID。realm 内で一意。作成後は変えない
	RealmID    string
	Status     UserStatus
	ValidFrom  *time.Time // 有効期間（design.md 4.8）。nil は制限なし
	ValidUntil *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UserRepo は users の Repository。
type UserRepo interface {
	Create(ctx context.Context, u User) error // ID か (realm, PublicID) が重複すれば errs.Conflict
	Get(ctx context.Context, realmID, id string) (User, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (User, error)
}

// VerifiedVia はメールを確認済みとみなした経路（design.md 4.1）。
type VerifiedVia string

const (
	VerifiedViaCode          VerifiedVia = "code"
	VerifiedViaOAuthProvider VerifiedVia = "oauth_provider"
	VerifiedViaSSO           VerifiedVia = "sso"
	VerifiedViaInvitation    VerifiedVia = "invitation"
	VerifiedViaAdmin         VerifiedVia = "admin"
)

// UserEmail は user_emails の1行。アドレスはユーザーのデータ鍵で暗号化し、検索はブラインドインデックスで行う（9.5）。
//
// ID は内部 ID。API に出すのは PublicID（ADR 0045）。
type UserEmail struct {
	ID          string
	PublicID    string // 外部 ID。realm 内で一意
	RealmID     string
	UserID      string
	Ciphertext  []byte // 最小化モード（index_only）では空
	Index       []byte // HMAC。realm 内で一意
	DomainIndex []byte
	IndexKeyID  string // インデックス鍵の ID（ローテーション用）
	VerifiedAt  *time.Time
	VerifiedVia VerifiedVia
	IsPrimary   bool
	CreatedAt   time.Time
}

// EmailRepo は user_emails の Repository。
type EmailRepo interface {
	// Create は (realm, Index) が重複すれば errs.Conflict を返す（1つのアドレスは1ユーザーにだけ紐付く。4.2）。
	Create(ctx context.Context, e UserEmail) error
	GetByIndex(ctx context.Context, realmID string, index []byte) (UserEmail, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (UserEmail, error)
	// ListByUser はユーザーのメールを作成時刻の順（同時刻は ID の順）に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]UserEmail, error)
	// SetPrimary は id のメールを primary にし、同じユーザーのほかのメールの primary を外す。無ければ errs.NotFound。
	SetPrimary(ctx context.Context, realmID, userID, id string) error
	// Delete はメールを消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
}

// Identity は user_identities の1行。外部の IdP の ID（connection, provider_subject）とユーザーの紐付け。
// 解除は削除ではなく無効化（RevokedAt。4.6）。ID は内部 ID で、API に出すのは PublicID。
type Identity struct {
	ID              string
	PublicID        string // 外部 ID。realm 内で一意
	RealmID         string
	UserID          string
	ConnectionID    string
	ProviderSubject string // 暗号化しない（9.5）
	CreatedAt       time.Time
	RevokedAt       *time.Time
	RevokeReason    string
}

// IdentityRepo は user_identities の Repository。
type IdentityRepo interface {
	// Create は、無効化されていない同じ (ConnectionID, ProviderSubject) があれば errs.Conflict を返す。
	// 無効化した紐付けは残したまま、同じ外部 ID を新しい行として紐付け直せる。
	Create(ctx context.Context, i Identity) error
	// GetBySubject は無効化されていない紐付けを返す。無ければ errs.NotFound。
	GetBySubject(ctx context.Context, realmID, connectionID, subject string) (Identity, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Identity, error)
	// Revoke は at に無効化する。既に無効化されていれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
	// ListByUser はユーザーの外部 ID を作成時刻の順（同時刻は ID の順）に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]Identity, error)
}

// Passkey は passkeys の1行（design.md 3.1、9.4）。公開鍵は COSE の形で持つ（秘密ではない）。
// 無効化は削除ではなく RevokedAt を記録し、credential_id は revoked_passkey_credentials にも残す（4.6）。
// ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Passkey struct {
	ID           string
	PublicID     string // 外部 ID。realm 内で一意
	RealmID      string
	UserID       string
	CredentialID []byte // 認証器が決める値。realm 内で一意
	PublicKey    []byte // COSE_Key
	Alg          int64  // COSE のアルゴリズム（ES256 = -7、EdDSA = -8）
	SignCount    uint32
	// Flags は認証器のフラグ（UP、UV、BE、BS など）。BE は登録の後に変わらないことを検証に使う。
	Flags        uint8
	AAGUID       []byte
	Transports   []string
	Name         string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// PasskeyRepo は passkeys と revoked_passkey_credentials の Repository。
type PasskeyRepo interface {
	// Create は、(realm, CredentialID) か (realm, PublicID) が重複するか、CredentialID が無効化済み
	// （revoked_passkey_credentials にある）なら errs.Conflict を返す（4.6 の再登録の拒否）。
	Create(ctx context.Context, p Passkey) error
	// GetByCredentialID は無効化していない passkey を返す。無ければ errs.NotFound。
	GetByCredentialID(ctx context.Context, realmID string, credentialID []byte) (Passkey, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Passkey, error)
	// ListByUser はユーザーの passkey を作成時刻の順（同時刻は ID の順）に返す（無効化したものも含む）。
	ListByUser(ctx context.Context, realmID, userID string) ([]Passkey, error)
	// Used はログインに使ったことを記録する（署名の回数、フラグ、最終利用時刻）。無ければ errs.NotFound。
	Used(ctx context.Context, realmID, id string, signCount uint32, flags uint8, at time.Time) error
	// Rename は名前を変える。無ければ errs.NotFound。
	Rename(ctx context.Context, realmID, id, name string) error
	// Revoke は at に無効化し、credential_id を無効化済みに加える。既に無効化されていれば何もしない。
	// 無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
}

// Connection は connections の1行（外部の IdP との接続）。秘密を含む設定はコアが暗号化してから渡す。
type Connection struct {
	ID        string
	RealmID   string
	Slug      string // realm 内で一意。URL に使う（google など）
	Type      string // oauth2 / oidc / saml
	Config    []byte
	CreatedAt time.Time
}

// ConnectionRepo は connections の Repository。
type ConnectionRepo interface {
	Create(ctx context.Context, c Connection) error // (realm, slug) が重複すれば errs.Conflict
	Get(ctx context.Context, realmID, id string) (Connection, error)
	GetBySlug(ctx context.Context, realmID, slug string) (Connection, error)
	List(ctx context.Context, realmID string) ([]Connection, error)
}

// PrincipalType は主体の種類。
type PrincipalType string

const (
	PrincipalUser           PrincipalType = "user"
	PrincipalServiceAccount PrincipalType = "service_account"
)

// Session は sessions の1行（design.md 5.2）。秘密トークンは持たず、そのハッシュだけを持つ。
type Session struct {
	ID                string
	RealmID           string
	PrincipalType     PrincipalType
	PrincipalID       string
	ActiveOrgID       string   // Org がオフなら常に空
	TokenHash         []byte   // 秘密部分の SHA-256
	AuthMethods       []string // amr
	AuthCredentialIDs []string // 認証に使った認証情報（無効化の判定に使う）
	Warnings          []byte   // JSON
	IP                []byte   // ユーザーのデータ鍵で暗号化したもの
	UserAgent         []byte   // 同上
	// AuthenticatedAt は最後に本人確認した時刻（max_auth_age の判定に使う）。ID を入れ替えても引き継ぐ。
	AuthenticatedAt time.Time
	CreatedAt       time.Time // この ID を発行した時刻（ID の入れ替えの判定に使う）
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	// RevokedAt は失効の時刻。未来の時刻は失効の予定（ID の入れ替え後の猶予）を表す。
	RevokedAt    *time.Time
	RevokeReason string
}

// SessionRepo は sessions の Repository。
type SessionRepo interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, realmID, id string) (Session, error)
	// ListByPrincipal は主体のセッションを新しい順に返す（失効・期限切れも含む）。
	ListByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID string) ([]Session, error)
	// Touch は最終利用時刻を進める（戻さない）。
	Touch(ctx context.Context, realmID, id string, at time.Time) error
	// Revoke は at に失効させる。既に at 以前に失効していれば何もしない（失効の時刻は早まるだけで遅れない）。
	// 失効の時刻を早めたときは理由も置き換える。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
	// RevokeByPrincipal は主体の、at の時点で失効していないセッションを exceptID 以外すべて at に失効させ、その ID を返す。
	RevokeByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID, exceptID string, at time.Time, reason string) ([]string, error)
}

// ServiceAccount は service_accounts の1行（design.md 11.2）。
// M1 では通知の配信用（権限は notifications:claim に固定）だけを作る。
// 行の数が少なく外に出る ID なので、内部 ID を別に持たず、ID に外部 ID を使う（ADR 0045）。
type ServiceAccount struct {
	ID        string
	RealmID   string
	Name      string
	CreatedAt time.Time
}

// ServiceAccountCredential は service_account_credentials の1行。秘密はハッシュだけを持つ。
type ServiceAccountCredential struct {
	ID               string
	RealmID          string
	ServiceAccountID string
	Type             string // api_key / client_secret / private_key_jwt
	SecretHash       []byte
	CreatedAt        time.Time
	ExpiresAt        *time.Time
	RevokedAt        *time.Time
}

// ServiceAccountRepo は service_accounts と service_account_credentials の Repository。
type ServiceAccountRepo interface {
	Create(ctx context.Context, a ServiceAccount) error
	Get(ctx context.Context, realmID, id string) (ServiceAccount, error)
	CreateCredential(ctx context.Context, c ServiceAccountCredential) error
	GetCredential(ctx context.Context, realmID, id string) (ServiceAccountCredential, error)
	RevokeCredential(ctx context.Context, realmID, id string, at time.Time) error
}
