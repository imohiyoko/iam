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
type User struct {
	ID         string
	RealmID    string
	Status     UserStatus
	ValidFrom  *time.Time // 有効期間（design.md 4.8）。nil は制限なし
	ValidUntil *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UserRepo は users の Repository。
type UserRepo interface {
	Create(ctx context.Context, u User) error // ID が重複すれば errs.Conflict
	Get(ctx context.Context, realmID, id string) (User, error)
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
type UserEmail struct {
	ID          string
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
	// ListByUser はユーザーのメールを作成順に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]UserEmail, error)
}

// Identity は user_identities の1行。外部の IdP の ID（connection, provider_subject）とユーザーの紐付け。
type Identity struct {
	ID              string
	RealmID         string
	UserID          string
	ConnectionID    string
	ProviderSubject string // 暗号化しない（9.5）
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

// IdentityRepo は user_identities の Repository。
type IdentityRepo interface {
	// Create は (ConnectionID, ProviderSubject) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, i Identity) error
	GetBySubject(ctx context.Context, realmID, connectionID, subject string) (Identity, error)
	ListByUser(ctx context.Context, realmID, userID string) ([]Identity, error)
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
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	RevokeReason      string
}

// SessionRepo は sessions の Repository。
type SessionRepo interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, realmID, id string) (Session, error)
	// ListByPrincipal は主体のセッションを新しい順に返す（失効・期限切れも含む）。
	ListByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID string) ([]Session, error)
	// Touch は最終利用時刻を進める（戻さない）。
	Touch(ctx context.Context, realmID, id string, at time.Time) error
	// Revoke は失効させる。既に失効していれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
	// RevokeByPrincipal は主体の有効なセッションを exceptID 以外すべて失効させ、失効させた ID を返す。
	RevokeByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID, exceptID string, at time.Time, reason string) ([]string, error)
	// Shorten は期限を at まで早める（ID の入れ替え後の猶予）。遅くはしない。
	Shorten(ctx context.Context, realmID, id string, at time.Time) error
}

// ServiceAccount は service_accounts の1行（design.md 11.2）。
// M1 では通知の配信用（権限は notifications:claim に固定）だけを作る。
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
