package port

import (
	"context"
	"time"
)

// Workload Identity Federation（フィーチャー workload_identity。ADR 0116）の Repository。

// WorkloadIdentityProvider は authn_workload_identity_providers の1行（外部の JWT の発行者）。
type WorkloadIdentityProvider struct {
	ID      string // 外部 ID（管理 API で使う）
	RealmID string
	// Issuer は JWT の iss（完全一致）。realm の中で一意。
	Issuer string
	Name   string
	// Config は残りの設定（JSON。形は authn/workloadidentity の Config。aud・鍵・alg・寿命の上限）。
	Config []byte
	// Disabled なら交換を受けず、この発行者で発行したトークンも使えない。
	Disabled  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// WorkloadIdentityBinding は authn_workload_identity_bindings の1行（条件を満たす外部の主体をサービスアカウントに対応させる）。
type WorkloadIdentityBinding struct {
	ID               string // 外部 ID。発行したアクセストークンの CredentialID になる
	RealmID          string
	ProviderID       string
	ServiceAccountID string
	// Conditions は条件（JSON。形は authn/workloadidentity の Condition の配列）。
	Conditions []byte
	CreatedAt  time.Time
}

// WorkloadIdentityRepo は発行者と結び付けの Repository。
type WorkloadIdentityRepo interface {
	// CreateProvider は ID・(realm, Issuer) が重複すれば errs.Conflict を返す。
	CreateProvider(ctx context.Context, p WorkloadIdentityProvider) error
	// GetProvider は ID で引く。無ければ errs.NotFound。
	GetProvider(ctx context.Context, realmID, id string) (WorkloadIdentityProvider, error)
	// GetProviderByIssuer は issuer（完全一致）で引く。無ければ errs.NotFound。
	GetProviderByIssuer(ctx context.Context, realmID, issuer string) (WorkloadIdentityProvider, error)
	// ListProviders は realm の発行者を作成時刻の順（同時刻は ID の順）に返す。
	ListProviders(ctx context.Context, realmID string) ([]WorkloadIdentityProvider, error)
	// UpdateProvider は ID と realm と作成時刻以外を置き換える。無ければ errs.NotFound、Issuer が重複すれば errs.Conflict。
	UpdateProvider(ctx context.Context, p WorkloadIdentityProvider) error
	// DeleteProvider は発行者とその結び付けを消す。無ければ errs.NotFound。
	DeleteProvider(ctx context.Context, realmID, id string) error

	// CreateBinding は ID が重複すれば errs.Conflict を返す。
	CreateBinding(ctx context.Context, b WorkloadIdentityBinding) error
	// GetBinding は ID で引く。無ければ errs.NotFound。
	GetBinding(ctx context.Context, realmID, id string) (WorkloadIdentityBinding, error)
	// ListBindings は発行者の結び付けを作成時刻の順（同時刻は ID の順）に返す。
	ListBindings(ctx context.Context, realmID, providerID string) ([]WorkloadIdentityBinding, error)
	// DeleteBinding は結び付けを消す。無ければ errs.NotFound。
	DeleteBinding(ctx context.Context, realmID, id string) error

	// Count は全 realm の発行者・結び付けと、結び付けで発行したアクセストークンの数（フィーチャーの無効化）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm の、結び付けで発行したアクセストークン・結び付け・発行者の順に最大 limit 件消し、その数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, limit int) (int, error)
}
