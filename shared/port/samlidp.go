package port

import (
	"context"
	"time"
)

// SAML 2.0 の IdP（iam が IdP。フィーチャー saml_idp。ADR 0115）の Repository。

// SAMLServiceProvider は authn_saml_service_providers の1行（SAML の SP の登録）。
type SAMLServiceProvider struct {
	ID      string // 外部 ID（管理 API で使う）
	RealmID string
	// EntityID は SP の Entity ID（AuthnRequest の Issuer と Audience）。realm の中で一意。
	EntityID string
	Name     string
	// Config は残りの設定（JSON。形は authn/samlidp の Config。ACS、SP の証明書、NameID、属性の対応、署名・暗号化など）。
	Config    []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SAMLIdPCertificate は authn_saml_idp_certificates の1行。realm の署名鍵（ES256）の自己署名の証明書（ECDSA の署名は毎回変わるため、
// 作ったものを置いて同じものを返す。ADR 0110 と同じ）。
type SAMLIdPCertificate struct {
	RealmID string
	// KeyID は署名鍵の kid（signing_keys の ID）。
	KeyID string
	// DER は証明書（DER）。
	DER       []byte
	CreatedAt time.Time
}

// SAMLIdPRepo は SAML の SP の登録と IdP の署名の証明書の Repository。
type SAMLIdPRepo interface {
	// CreateServiceProvider は ID・(realm, EntityID) が重複すれば errs.Conflict を返す。
	CreateServiceProvider(ctx context.Context, sp SAMLServiceProvider) error
	// GetServiceProvider は ID で引く。無ければ errs.NotFound。
	GetServiceProvider(ctx context.Context, realmID, id string) (SAMLServiceProvider, error)
	// GetServiceProviderByEntityID は Entity ID（完全一致）で引く。無ければ errs.NotFound。
	GetServiceProviderByEntityID(ctx context.Context, realmID, entityID string) (SAMLServiceProvider, error)
	// ListServiceProviders は realm の SP を作成時刻の順（同時刻は ID の順）に返す。
	ListServiceProviders(ctx context.Context, realmID string) ([]SAMLServiceProvider, error)
	// UpdateServiceProvider は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound、EntityID が重複すれば errs.Conflict。
	UpdateServiceProvider(ctx context.Context, sp SAMLServiceProvider) error
	// DeleteServiceProvider は SP を消す。無ければ errs.NotFound。
	DeleteServiceProvider(ctx context.Context, realmID, id string) error

	// CreateCertificate は (realm, KeyID) が重複すれば errs.Conflict を返す。
	CreateCertificate(ctx context.Context, c SAMLIdPCertificate) error
	// ListCertificates は realm の証明書を KeyID の順に返す。
	ListCertificates(ctx context.Context, realmID string) ([]SAMLIdPCertificate, error)
	// DeleteCertificate は証明書を消す。無ければ errs.NotFound。
	DeleteCertificate(ctx context.Context, realmID, keyID string) error

	// Count は全 realm の SP と証明書の数（フィーチャーの無効化）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm の SP と証明書を最大 limit 件消し、その数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
