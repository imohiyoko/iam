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
	// ClientAuthTLS は PKI の証明書での mTLS の認証（RFC 8705 2.1。フィーチャー mtls_client_auth。ADR 0113）。
	ClientAuthTLS = "tls_client_auth"
	// ClientAuthSelfSignedTLS は自己署名の証明書での mTLS の認証（RFC 8705 2.2。鍵は JWKS に登録する）。
	ClientAuthSelfSignedTLS = "self_signed_tls_client_auth"
)

// tls_client_auth で証明書と照合する項目（RFC 8705 2.1.2。ADR 0113）。
const (
	TLSAuthSubjectDN = "subject_dn"
	TLSAuthSANDNS    = "san_dns"
	TLSAuthSANURI    = "san_uri"
	TLSAuthSANIP     = "san_ip"
	TLSAuthSANEmail  = "san_email"
)

// TrustFirstParty はホスト先が登録したファーストパーティのクライアント（当面これだけ。ADR 0026）。
const TrustFirstParty = "first_party"

// ID トークンの署名のアルゴリズム（9.3）。
const (
	AlgES256   = "ES256"
	AlgMLDSA65 = "ML-DSA-65"
	// AlgRS256 はフィーチャー rs256 で連携先ごとに選べる（ADR 0122）。
	AlgRS256 = "RS256"
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
	// IDTokenAlg は id_token_signed_response_alg（ES256 / ML-DSA-65。フィーチャー rs256 なら RS256 も）。
	IDTokenAlg string
	// BackchannelLogoutURI は Back-Channel Logout の送り先（空なら送らない。5.2）。
	BackchannelLogoutURI string
	// DeviceGrant は Device Authorization Grant（RFC 8628）を許す（フィーチャー device_flow。ADR 0095）。
	DeviceGrant bool
	// FrontchannelLogoutURI は Front-Channel Logout の送り先（ログアウトの完了画面の iframe で開く。空なら開かない。
	// フィーチャー oidc_logout。ADR 0094）。
	FrontchannelLogoutURI string
	// FrontchannelLogoutSessionRequired は FrontchannelLogoutURI に iss と sid を付けるか。
	FrontchannelLogoutSessionRequired bool
	// TokenExchange は Token Exchange（RFC 8693）で許す交換（JSON。形は authn/provider の ExchangePolicy）。nil なら何も許さない
	// （フィーチャー token_exchange。ADR 0099）。
	TokenExchange []byte
	// DPoPBoundAccessTokens は token エンドポイントで常に DPoP の証明を求める（RFC 9449 5.2。フィーチャー dpop。ADR 0113）。
	DPoPBoundAccessTokens bool
	// TLSBoundAccessTokens はアクセストークンをクライアント証明書に結び付ける
	// （tls_client_certificate_bound_access_tokens。RFC 8705 3.4。フィーチャー mtls_client_auth）。
	TLSBoundAccessTokens bool
	// TLSAuthField と TLSAuthValue は tls_client_auth で照合する証明書の項目（TLSAuth*）と値。
	TLSAuthField string
	TLSAuthValue string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// CIBAMode は CIBA のトークンの受け取り方（backchannel_token_delivery_mode。CIBAPoll か CIBAPing）。空なら CIBA を使えない
	// （フィーチャー ciba。ADR 0114）。
	CIBAMode string
	// CIBANotificationEndpoint は ping の通知先（backchannel_client_notification_endpoint。ping のときだけ）。
	CIBANotificationEndpoint string
	// RequirePAR は認可要求を PAR（RFC 9126）で送らせる（require_pushed_authorization_requests。フィーチャー par。ADR 0112）。
	RequirePAR bool
	// FAPI2 はこの連携先に FAPI 2.0 Security Profile を強いる（fapi2_security_profile。フィーチャー fapi2。ADR 0117）。
	FAPI2 bool
	// JWTAccessTokens はアクセストークンを JWT（RFC 9068）で出す（jwt_access_tokens。フィーチャー jwt_access_tokens。ADR 0123）。
	JWTAccessTokens bool
	// OfflineAccess は offline_access のスコープを受ける（ログインの系列から切り離した認可。フィーチャー offline_access。ADR 0126）。
	OfflineAccess bool
}

// CIBA のトークンの受け取り方（ADR 0114）。push は持たない。
const (
	CIBAPoll = "poll"
	CIBAPing = "ping"
)

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
	// Exchange は Token Exchange（RFC 8693）で作った認可の種類（ExchangeDelegation・ExchangeImpersonation）。空なら認可コードの
	// 認可。交換の認可はアクセストークンだけを持つ（ADR 0099）。
	Exchange string
	// ParentID は交換の元の認可（内部 ID）。元が失効・期限切れなら、この認可も使えない。ID トークンを交換したときは空。
	ParentID string
	// ActorUserID は行為者のユーザー（内部 ID）。なりすましでは運営者で、SID はこのユーザーのログインの系列。委任では actor_token の
	// ユーザー（無ければ空）。ユーザーの消去で、UserID と同じく認可を消す。
	ActorUserID string
	// Act は act クレーム（JSON の object。RFC 8693 4.1）。
	Act []byte
	// Audiences は交換で発行したトークンの aud（連携先の client_id か資源の URI。RFC 8707）。
	Audiences []string
	// ACR は認可したときに決めた acr（フィーチャー acr。ADR 0093）。空ならフィーチャーがオフで、acr を返さない。
	ACR string
	// Offline はログインの系列から切り離した認可（offline_access。ADR 0126）。系列のログアウト・期限では失効せず、
	// ユーザーの状態（停止・削除・有効期間）と AuthCredentialIDs の認証情報で確かめる。
	Offline bool
	// AuthCredentialIDs は認可に使ったセッションの認証に使った認証情報（外部 ID・passkey・TOTP など。Offline のときだけ）。
	// どれかが無効化されれば認可も使えない。
	AuthCredentialIDs []string
}

// 交換の認可の種類（Grant.Exchange）。
const (
	ExchangeDelegation    = "delegation"
	ExchangeImpersonation = "impersonation"
)

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
	// CountExchanged は全 realm の、種類が exchange の交換の認可を数える（フィーチャーの無効化）。
	CountExchanged(ctx context.Context, exchange string) (int, error)
	// PurgeExchanged は全 realm の、種類が exchange の交換の認可を、そのトークンと一緒に最大 limit 件消し、消した件数を返す。
	PurgeExchanged(ctx context.Context, exchange string, limit int) (int, error)
	// ListOfflineByUser はユーザーの Offline の認可を作成時刻の順（同時刻は ID の順）に返す（失効・期限切れも含む）。
	ListOfflineByUser(ctx context.Context, realmID, userID string) ([]Grant, error)
	// CountOffline は全 realm の Offline の認可を数える（フィーチャーの無効化）。
	CountOffline(ctx context.Context) (int, error)
	// PurgeOffline は全 realm の Offline の認可を、そのトークンと一緒に最大 limit 件消し、消した件数を返す。
	PurgeOffline(ctx context.Context, limit int) (int, error)
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
	// JKT はトークンを結び付けた DPoP の鍵の JWK SHA-256 Thumbprint（RFC 9449 6.1 の cnf.jkt）。空なら結び付けない。
	JKT string
	// X5T はトークンを結び付けたクライアント証明書の SHA-256 の指紋（RFC 8705 3.1 の cnf.x5t#S256）。空なら結び付けない。
	X5T string
}

// トークンの結び付けの種類（OIDCTokenRepo.CountBound・PurgeBound。ADR 0113）。
const (
	BindingDPoP = "dpop"
	BindingMTLS = "mtls"
)

// OIDCTokenRepo は oidc_tokens の Repository。
type OIDCTokenRepo interface {
	// Create は ID が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, t OIDCToken) error
	Get(ctx context.Context, realmID, id string) (OIDCToken, error)
	// Use はまだ使っていなければ at に使用済みにして true を返す（同時に使われても true は1回だけ）。無ければ errs.NotFound。
	Use(ctx context.Context, realmID, id string, at time.Time) (bool, error)
	// Extend はトークンの期限を expiresAt にする（ローテーションしない Offline のリフレッシュトークン。ADR 0126）。
	// 無ければ errs.NotFound。
	Extend(ctx context.Context, realmID, id string, expiresAt time.Time) error
	// CountBound は全 realm の、binding（BindingDPoP・BindingMTLS）で結び付けたトークンの数を返す。
	CountBound(ctx context.Context, binding string) (int, error)
	// PurgeBound は全 realm の、binding で結び付けたトークンを最大 limit 件消し、消した件数を返す（フィーチャーの無効化）。
	PurgeBound(ctx context.Context, binding string, limit int) (int, error)
}
