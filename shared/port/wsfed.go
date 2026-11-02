package port

import (
	"context"
	"time"
)

// WS-Federation のパッシブ要求者プロファイル（iam が IdP。フィーチャー wsfed。ADR 0110）の Repository。

// WSFedRelyingParty は authn_wsfed_relying_parties の1行（WS-Federation の RP）。
type WSFedRelyingParty struct {
	ID      string // 外部 ID（管理 API で使う）
	RealmID string
	// Realm は wtrealm（絶対 URI）。realm の中で一意。
	Realm string
	Name  string
	// ReplyURLs は wreply の許可リスト（完全一致。最初のものが既定）。
	ReplyURLs []string
	// TokenType は saml11 か saml20。
	TokenType string
	// Claims はクレームの対応（JSON。形は authn/wsfed の Claim の配列）。
	Claims []byte
	// TokenLifetime は Assertion の有効期間（秒）。
	TokenLifetime int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// WSFedCertificate は authn_wsfed_certificates の1行。realm の署名鍵（ES256）の自己署名の証明書（ECDSA の署名は毎回変わるため、
// 作ったものを置いて同じものを返す）。
type WSFedCertificate struct {
	RealmID string
	// KeyID は署名鍵の kid（signing_keys の ID）。
	KeyID string
	// DER は証明書（DER）。
	DER       []byte
	CreatedAt time.Time
}

// WSFedRepo は WS-Federation の RP と証明書の Repository。
type WSFedRepo interface {
	// CreateRelyingParty は ID・(realm, Realm) が重複すれば errs.Conflict を返す。
	CreateRelyingParty(ctx context.Context, rp WSFedRelyingParty) error
	// GetRelyingParty は ID で引く。無ければ errs.NotFound。
	GetRelyingParty(ctx context.Context, realmID, id string) (WSFedRelyingParty, error)
	// GetRelyingPartyByRealm は wtrealm（完全一致）で引く。無ければ errs.NotFound。
	GetRelyingPartyByRealm(ctx context.Context, realmID, wtrealm string) (WSFedRelyingParty, error)
	// ListRelyingParties は realm の RP を作成時刻の順（同時刻は ID の順）に返す。
	ListRelyingParties(ctx context.Context, realmID string) ([]WSFedRelyingParty, error)
	// UpdateRelyingParty は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound、Realm が重複すれば errs.Conflict。
	UpdateRelyingParty(ctx context.Context, rp WSFedRelyingParty) error
	// DeleteRelyingParty は RP を消す。無ければ errs.NotFound。
	DeleteRelyingParty(ctx context.Context, realmID, id string) error

	// CreateCertificate は (realm, KeyID) が重複すれば errs.Conflict を返す。
	CreateCertificate(ctx context.Context, c WSFedCertificate) error
	// ListCertificates は realm の証明書を KeyID の順に返す。
	ListCertificates(ctx context.Context, realmID string) ([]WSFedCertificate, error)
	// DeleteCertificate は証明書を消す。無ければ errs.NotFound。
	DeleteCertificate(ctx context.Context, realmID, keyID string) error

	// Count は全 realm の RP と証明書の数（フィーチャーの無効化）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm の RP と証明書を最大 limit 件消し、その数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
