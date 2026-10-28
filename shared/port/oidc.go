package port

import (
	"context"
	"time"
)

// OIDC Provider の Repository（design.md 3.1 の clients、5.1、5.5、9.3）。

// クライアントの認証方式（token エンドポイントでの認証）。
const (
	ClientAuthSecret        = "client_secret"   // client_secret_basic / client_secret_post
	ClientAuthPrivateKeyJWT = "private_key_jwt" // 公開鍵（JWKS）を登録する
	ClientAuthNone          = "none"            // 公開クライアント（PKCE 必須）
)

// TrustFirstParty はホスト先が登録したファーストパーティのクライアント（当面これだけ。ADR 0026）。
const TrustFirstParty = "first_party"

// ID トークンの署名のアルゴリズム（9.3）。
const (
	AlgES256   = "ES256"
	AlgMLDSA65 = "ML-DSA-65"
)

// Client は clients の1行（連携先）。
type Client struct {
	ID       string
	PublicID string // client_id。realm 内で一意
	RealmID  string
	Name     string
	// TrustLevel は first_party だけ（同意画面を出さない。ADR 0026）。
	TrustLevel             string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AuthMethod             string
	// SecretHash は client_secret の SHA-256（ClientAuthSecret のとき）。秘密そのものは保存しない。
	SecretHash []byte
	// JWKS は private_key_jwt の公開鍵（JWKS の JSON）。
	JWKS []byte
	// IDTokenAlg は id_token_signed_response_alg（ES256 / ML-DSA-65）。
	IDTokenAlg string
	// BackchannelLogoutURI は Back-Channel Logout の送り先（空なら送らない。5.2）。
	BackchannelLogoutURI string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// ClientRepo は clients の Repository。
type ClientRepo interface {
	// Create は ID・(realm, PublicID) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, c Client) error
	Get(ctx context.Context, realmID, id string) (Client, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Client, error)
	// List は realm のクライアントを作成時刻の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]Client, error)
	// Update は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound。
	Update(ctx context.Context, c Client) error
	// Delete はクライアントと、その認可・トークンを消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
}

// SigningKey は signing_keys の1行（ID トークンの署名鍵。9.3）。
type SigningKey struct {
	// ID は kid（JWKS と JWS のヘッダーに出す）。
	ID      string
	RealmID string
	Alg     string
	// Public は公開鍵（ES256 は PKIX の DER、ML-DSA-65 は FIPS 204 の公開鍵のバイト列）。
	Public []byte
	// Private はマスター鍵から導いた鍵で暗号化した秘密鍵（pii.Crypter.Seal）。
	Private   []byte
	CreatedAt time.Time
	// RetiredAt は署名に使うのをやめた時刻。退役した鍵も、発行済みの ID トークンの検証のため JWKS には残す。
	RetiredAt *time.Time
}

// SigningKeyRepo は signing_keys の Repository。
type SigningKeyRepo interface {
	// Create は ID が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, k SigningKey) error
	// List は realm の鍵を作成時刻の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]SigningKey, error)
	// Retire は鍵を退役させる。無ければ errs.NotFound。
	Retire(ctx context.Context, realmID, id string, at time.Time) error
	// Delete は鍵を消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
}

// Grant は連携先への認可の1件（認可コードの交換ごとに作る。アクセストークンとリフレッシュトークンの親。5.1）。
// ログインの系列（Session.SID）に結び付け、系列が終われば（ログアウト・失効・期限）使えなくなる。
type Grant struct {
	ID       string // 内部 ID。外に出さない
	RealmID  string
	ClientID string // 内部 ID
	UserID   string // 内部 ID
	// OrgID は認可したときの active な Org（内部 ID）。Org がオフなら空。
	OrgID       string
	SID         string
	Scopes      []string
	AuthMethods []string // amr
	// AuthTime は認可に使ったセッションで最後に本人確認した時刻（auth_time）。
	AuthTime     time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// GrantRepo は oidc_grants の Repository。認可とそのトークンは、連携先の削除（ClientRepo.Delete）と
// ユーザーの消去（UserRepo.Erase）で一緒に消える。
type GrantRepo interface {
	// Create は ID が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, g Grant) error
	Get(ctx context.Context, realmID, id string) (Grant, error)
	// ListBySID はログインの系列に結び付いた認可を作成時刻の順（同時刻は ID の順）に返す（失効したものも含む）。
	ListBySID(ctx context.Context, realmID, sid string) ([]Grant, error)
	// Revoke は at に失効させる。既に at 以前に失効していれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
}

// トークンの種類。
const (
	TokenAccess  = "access"
	TokenRefresh = "refresh"
)

// OIDCToken は oidc_tokens の1行（不透明なアクセストークン・リフレッシュトークン。5.1）。
// トークンは `<ID>.<256bit 乱数>` で、保存するのは秘密部分の SHA-256 だけ（セッションと同じ。5.2）。
type OIDCToken struct {
	ID        string
	RealmID   string
	GrantID   string
	Kind      string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt はリフレッシュトークンを使った（ローテーションした）時刻。
	UsedAt *time.Time
}

// OIDCTokenRepo は oidc_tokens の Repository。
type OIDCTokenRepo interface {
	// Create は ID が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, t OIDCToken) error
	Get(ctx context.Context, realmID, id string) (OIDCToken, error)
	// Use はまだ使っていなければ at に使用済みにして true を返す（同時に使われても true は1回だけ）。無ければ errs.NotFound。
	Use(ctx context.Context, realmID, id string, at time.Time) (bool, error)
}
