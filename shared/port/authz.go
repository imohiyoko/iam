package port

import (
	"context"
	"time"
)

// 認可側（authz）の Repository（design.md 3.2）。

// RoleBinding は role_bindings の1行。
//
// M1 では組み込みのロール（realm:owner など）を名前で付与する。ロールの表（roles）とホスト先の
// 独自のロールは M4 で足し、Role をロールの ID に置き換える。
type RoleBinding struct {
	ID            string
	RealmID       string
	Role          string
	PrincipalType PrincipalType
	PrincipalID   string
	OrgID         string // 空なら realm 全体
	CreatedAt     time.Time
}

// RoleBindingRepo は role_bindings の Repository。
type RoleBindingRepo interface {
	// Create は (realm, role, principal, org) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, b RoleBinding) error
	ListByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID string) ([]RoleBinding, error)
	ListByRole(ctx context.Context, realmID, role string) ([]RoleBinding, error)
}
