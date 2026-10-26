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
	// List は realm のユーザーを内部 ID の順に、afterID より後から最大 limit 件返す（準備処理などの一括の処理用）。
	List(ctx context.Context, realmID, afterID string, limit int) ([]User, error)
	// SetValidity は有効期間（design.md 4.8）を置き換える。無ければ errs.NotFound。
	SetValidity(ctx context.Context, realmID, id string, from, until *time.Time, updatedAt time.Time) error
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
	Flags      uint8
	AAGUID     []byte
	Transports []string
	Name       string
	// PreferredOrgID はこの passkey でログインしたときに入る Org（内部 ID。4.4）。空なら指定なし。
	PreferredOrgID string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
	RevokeReason   string
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
	// SetPreferredOrg はログインで入る Org（内部 ID。空なら指定なし）を変える。無ければ errs.NotFound。
	SetPreferredOrg(ctx context.Context, realmID, id, orgID string) error
	// Revoke は at に無効化し、credential_id を無効化済みに加える。既に無効化されていれば何もしない。
	// 無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
}

// TOTPCredential は totp_credentials の1行（design.md 3.1、4.1）。秘密はユーザーのデータ鍵で暗号化する（9.5）。
// 無効化は削除ではなく RevokedAt を記録する（4.6）。ID は内部 ID で、API に出すのは PublicID。
type TOTPCredential struct {
	ID               string
	PublicID         string
	RealmID          string
	UserID           string
	SecretCiphertext []byte
	// LastUsedStep は最後に受け入れた時間窓（Unix 時刻 / 30 秒）。同じか前の窓のコードは拒否する（再利用の防止）。
	LastUsedStep int64
	CreatedAt    time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// TOTPRepo は totp_credentials の Repository。
type TOTPRepo interface {
	// Create は (realm, PublicID) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, c TOTPCredential) error
	GetByPublicID(ctx context.Context, realmID, publicID string) (TOTPCredential, error)
	// ListByUser はユーザーの TOTP を作成時刻の順（同時刻は ID の順）に返す（無効化したものも含む）。
	ListByUser(ctx context.Context, realmID, userID string) ([]TOTPCredential, error)
	// Use は step を最後に使った時間窓にする。今の値が step 以上なら errs.Conflict（再利用。原子的に判定する）。
	// 無ければ errs.NotFound。
	Use(ctx context.Context, realmID, id string, step int64) error
	// Revoke は at に無効化する。既に無効化されていれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
}

// PasswordCredential は password_credentials の1行（design.md 3.1、4.1）。有効なものはユーザーに1つまで。
// 変更・削除は無効化（RevokedAt）で表し、新しい行を作る（4.6）。
type PasswordCredential struct {
	ID      string
	RealmID string
	UserID  string
	// Hash は argon2id の PHC 文字列（`$argon2id$v=19$m=…,t=…,p=…$salt$hash`）。
	Hash         string
	CreatedAt    time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// PasswordRepo は password_credentials の Repository。
type PasswordRepo interface {
	// Create はユーザーに有効なパスワードがあれば errs.Conflict を返す（原子的に判定する）。
	Create(ctx context.Context, c PasswordCredential) error
	// Get は ID で返す（無効化したものも含む）。無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (PasswordCredential, error)
	// GetActive はユーザーの有効なパスワードを返す。無ければ errs.NotFound。
	GetActive(ctx context.Context, realmID, userID string) (PasswordCredential, error)
	// UpdateHash は有効なパスワードのハッシュを置き換える（同じパスワードの、パラメータの更新）。無ければ errs.NotFound。
	UpdateHash(ctx context.Context, realmID, id, hash string) error
	// Revoke は at に無効化する。既に無効化されていれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
}

// RecoveryCode は authn_recovery_codes の1行（design.md 4.12）。コードは表示の1回だけで、argon2id のハッシュを持つ。
// Lookup はコードの先頭の数文字（平文）で、照合するハッシュを1つに絞る（ユーザーの組の中で一意）。
type RecoveryCode struct {
	ID        string
	RealmID   string
	UserID    string
	Lookup    string
	Hash      string
	CreatedAt time.Time
	UsedAt    *time.Time
}

// RecoveryCodeRepo は authn_recovery_codes の Repository。
type RecoveryCodeRepo interface {
	// Replace はユーザーのコードをすべて消し、codes に置き換える（空なら消すだけ）。
	Replace(ctx context.Context, realmID, userID string, codes []RecoveryCode) error
	// ListByUser はユーザーのコード（使用済みも含む）を ID の順に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]RecoveryCode, error)
	// MarkUsed は未使用なら at に使用済みにして true を返す。使用済み・無ければ false（同時の使用は1つだけ通る）。
	MarkUsed(ctx context.Context, realmID, id string, at time.Time) (bool, error)
}

// SuspensionTarget は停止の対象の種類（design.md 4.7）。
type SuspensionTarget string

const (
	SuspensionTargetUser           SuspensionTarget = "user"
	SuspensionTargetOrg            SuspensionTarget = "org"
	SuspensionTargetServiceAccount SuspensionTarget = "service_account"
	SuspensionTargetMembership     SuspensionTarget = "membership"
)

// Suspension は suspensions の1行。停止中かは時刻から計算する（StartsAt ≤ 今 < min(EndsAt, LiftedAt)）。
// 解除は削除ではなく LiftedAt を記録する。ID は内部 ID で、API に出すのは PublicID。
type Suspension struct {
	ID         string
	PublicID   string
	RealmID    string
	TargetType SuspensionTarget
	TargetID   string // 対象の内部 ID
	Category   string // tos_violation / customer_request / security_risk / billing / realm で足したもの
	// Reason は内部向けの理由（本人には見せない）。
	Reason string
	// ExternalRef は外部のシステム（課金など）の参照。空でなければ、対象と種別ごとに一意（冪等な停止）。
	ExternalRef string
	StartsAt    time.Time
	EndsAt      *time.Time // nil は無期限
	CreatedBy   string     // 操作した主体の公開 ID
	CreatedAt   time.Time
	LiftedAt    *time.Time
	LiftedBy    string
}

// SuspensionRepo は suspensions の Repository。
type SuspensionRepo interface {
	// Create は (realm, PublicID) か、空でない (対象, Category, ExternalRef) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, s Suspension) error
	GetByPublicID(ctx context.Context, realmID, publicID string) (Suspension, error)
	// ListByTarget は対象の停止を StartsAt の順（同時刻は ID の順）に返す（解除・終了したものも含む）。
	ListByTarget(ctx context.Context, realmID string, t SuspensionTarget, targetID string) ([]Suspension, error)
	// Lift は at に解除する。既に解除されていれば何もしない。無ければ errs.NotFound。
	Lift(ctx context.Context, realmID, id string, at time.Time, by string) error
}

// ScheduledEvent は scheduled_events の1行（design.md 4.8）。時刻の境界（停止の開始・終了、有効期間の始まり・終わり）の
// 出来事を予約し、時刻を過ぎたら outbox に出す。アクセスの可否はこの処理の遅れに左右されない（判定は時刻から計算する）。
type ScheduledEvent struct {
	ID      string
	RealmID string
	// Ref は取り消しの単位（停止の公開 ID、ユーザーの有効期間など）。
	Ref       string
	Type      string
	Payload   []byte // 監査ログの details に入れる JSON
	FireAt    time.Time
	FiredAt   *time.Time
	CreatedAt time.Time
}

// ScheduledEventRepo は scheduled_events の Repository。
type ScheduledEventRepo interface {
	Schedule(ctx context.Context, e ScheduledEvent) error
	// Due は FireAt が now 以前で未発火のものを、全 realm から FireAt の順（同時刻は ID の順）に最大 limit 件返す。
	Due(ctx context.Context, now time.Time, limit int) ([]ScheduledEvent, error)
	// MarkFired は未発火なら at に発火済みにして true を返す。発火済み・取り消し済みなら false（同時の処理で二重に出さない）。
	MarkFired(ctx context.Context, realmID, id string, at time.Time) (bool, error)
	// CancelByRef は ref の未発火のものを取り消す（消す）。
	CancelByRef(ctx context.Context, realmID, ref string) error
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
	// Restriction は使える操作の制限。空なら制限なし（SessionRestriction を参照）。
	Restriction SessionRestriction
	Warnings    []byte // JSON
	IP          []byte // ユーザーのデータ鍵で暗号化したもの
	UserAgent   []byte // 同上
	// AuthenticatedAt は最後に本人確認した時刻（max_auth_age の判定に使う）。ID を入れ替えても引き継ぐ。
	AuthenticatedAt time.Time
	CreatedAt       time.Time // この ID を発行した時刻（ID の入れ替えの判定に使う）
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	// RevokedAt は失効の時刻。未来の時刻は失効の予定（ID の入れ替え後の猶予）を表す。
	RevokedAt    *time.Time
	RevokeReason string
}

// SessionRestriction はセッションで使える操作の制限（design.md 4.1、4.12）。
type SessionRestriction string

const (
	// RestrictionNone は制限なし（通常のセッション）。
	RestrictionNone SessionRestriction = ""
	// RestrictionSecondFactor は1要素目の後で、2要素目の確認だけができる。
	RestrictionSecondFactor SessionRestriction = "second_factor"
	// RestrictionEnroll は2要素目が必須で未登録のユーザーが、2要素目の登録だけができる。
	RestrictionEnroll SessionRestriction = "enroll"
	// RestrictionRecovery はアカウントの復旧で、新しい認証手段の登録と復旧の完了だけができる（4.12）。
	RestrictionRecovery SessionRestriction = "recovery"
)

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

// OrgKind は Org の種類（design.md 11.13）。
type OrgKind string

const (
	// OrgPersonal はユーザーごとの個人 Org。メンバーは本人だけで、ユーザーと一緒に作り、一緒に消す。
	OrgPersonal OrgKind = "personal"
	OrgShared   OrgKind = "shared"
)

// Org は orgs の1行（design.md 3.1）。ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Org struct {
	ID       string
	PublicID string // 外部 ID。realm 内で一意
	RealmID  string
	Kind     OrgKind
	Name     string
	// PersonalOwnerID は個人 Org の持ち主（ユーザーの内部 ID）。共有 Org では空。realm 内で一意。
	PersonalOwnerID string
	ValidFrom       *time.Time // 有効期間（design.md 4.8）。nil は制限なし
	ValidUntil      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// OrgRepo は orgs の Repository。
type OrgRepo interface {
	// Create は ID・(realm, PublicID)・個人 Org の持ち主が重複すれば errs.Conflict を返す（個人 Org はユーザーに1つ）。
	Create(ctx context.Context, o Org) error
	Get(ctx context.Context, realmID, id string) (Org, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Org, error)
	// GetPersonal はユーザーの個人 Org を返す。無ければ errs.NotFound。
	GetPersonal(ctx context.Context, realmID, userID string) (Org, error)
}

// MembershipStatus は Membership の状態（design.md 3.1）。
type MembershipStatus string

const (
	MembershipInvited MembershipStatus = "invited"
	MembershipActive  MembershipStatus = "active"
	MembershipEnded   MembershipStatus = "ended"
)

// OrgRole は Org の中の役割（design.md 4.11）。
type OrgRole string

const (
	OrgOwner  OrgRole = "owner"
	OrgAdmin  OrgRole = "admin"
	OrgMember OrgRole = "member"
)

// Membership は memberships の1行。ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Membership struct {
	ID       string
	PublicID string
	RealmID  string
	UserID   string
	OrgID    string
	Status   MembershipStatus
	Role     OrgRole
	// EmailID はこの Org で使うメール（内部 ID）。空なら primary（4.4）。
	EmailID     string
	ValidFrom   *time.Time
	ValidUntil  *time.Time
	EndedReason string // self_leave / removed / expired / org_deleted / user_deleted
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// MembershipRepo は memberships の Repository。
type MembershipRepo interface {
	// Create は ID・(realm, PublicID)・(UserID, OrgID) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, m Membership) error
	GetByPublicID(ctx context.Context, realmID, publicID string) (Membership, error)
	// GetByUserOrg はユーザーと Org の Membership を返す（終了したものも含む）。無ければ errs.NotFound。
	GetByUserOrg(ctx context.Context, realmID, userID, orgID string) (Membership, error)
	// ListByUser は作成時刻の順（同時刻は ID の順）に返す（終了したものも含む）。
	ListByUser(ctx context.Context, realmID, userID string) ([]Membership, error)
	// ListByOrg は公開 ID の順に、afterPublicID より後を最大 limit 件返す（終了したものも含む）。
	// Org のメンバーは多くなりうるため、ページングで取る（カーソルは外に出してよい公開 ID）。
	ListByOrg(ctx context.Context, realmID, orgID, afterPublicID string, limit int) ([]Membership, error)
	// Update は ID の Membership の状態・役割・メール・有効期間・終了の理由・更新時刻を m の値に置き換える。
	// ユーザー・Org・作成時刻は変えない。無ければ errs.NotFound。
	Update(ctx context.Context, m Membership) error
}

// InvitationStatus は招待の状態。期限切れは ExpiresAt から計算し、行は pending のまま残してよい。
type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "pending"
	InvitationAccepted InvitationStatus = "accepted"
	InvitationRevoked  InvitationStatus = "revoked"
)

// Invitation は invitations の1行（design.md 3.1、4.4）。アドレスは招待ごとのデータ鍵（ID は招待の内部 ID）で暗号化し、
// 終わったら鍵を消す。トークンは秘密のハッシュだけを持つ。ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Invitation struct {
	ID              string
	PublicID        string
	RealmID         string
	OrgID           string
	EmailIndex      []byte
	EmailCiphertext []byte
	IndexKeyID      string
	Role            OrgRole
	TokenHash       []byte     // 秘密部分の SHA-256
	ValidFrom       *time.Time // 受け入れて作る Membership の有効期間
	ValidUntil      *time.Time
	InvitedBy       string // 招待した主体の公開 ID
	ExpiresAt       time.Time
	Status          InvitationStatus
	CreatedAt       time.Time
	// ClosedAt は受け入れ・取り消しの時刻。ClosedBy は受け入れたユーザーか、取り消した主体の公開 ID。
	ClosedAt *time.Time
	ClosedBy string
}

// InvitationRepo は invitations の Repository。
type InvitationRepo interface {
	// Create は ID・(realm, PublicID) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, i Invitation) error
	GetByPublicID(ctx context.Context, realmID, publicID string) (Invitation, error)
	// ListByOrg は Org の招待を作成時刻の順（同時刻は ID の順）に返す（終わったものも含む）。
	ListByOrg(ctx context.Context, realmID, orgID string) ([]Invitation, error)
	// Close は pending なら status にして true を返す。pending でなければ false（同時の受け入れは1つだけ通る）。無ければ errs.NotFound。
	Close(ctx context.Context, realmID, id string, status InvitationStatus, at time.Time, by string) (bool, error)
}
