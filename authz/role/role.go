// Package role は組み込みのロールと、その権限を定める（design.md 4.11）。
//
// M1 では組み込みのロールだけを名前で付与する。ロールの表とホスト先の独自のロールは M4 で足す。
// 判定は fail-closed：知らないロールは権限を持たない。
package role

import (
	"context"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 組み込みのロール。
const (
	RealmOwner    = "realm:owner"
	RealmAdmin    = "realm:admin"
	RealmSecurity = "realm:security"
	RealmSupport  = "realm:support"
	RealmBilling  = "realm:billing"
	// NotificationDelivery は配信用のサービスアカウントのロール（権限は notifications:claim に固定。2.4）。
	NotificationDelivery = "system:notification_delivery"
)

// 権限。
const (
	PermNotificationsClaim = "notifications:claim"
	PermSessionsRevoke     = "sessions:revoke"
	PermUsersCreate        = "users:create"
	PermUsersLoginLink     = "users:login_link"
	PermConnectionsManage  = "connections:manage"
	PermPIIRead            = "pii:read"
	// PermCredentialsRevoke はユーザーの認証情報の一覧と無効化（4.6）。
	PermCredentialsRevoke = "credentials:revoke"
)

var builtin = map[string][]string{
	RealmOwner:           {PermSessionsRevoke, PermUsersCreate, PermUsersLoginLink, PermConnectionsManage, PermPIIRead, PermCredentialsRevoke},
	RealmAdmin:           {PermSessionsRevoke, PermUsersCreate, PermUsersLoginLink, PermCredentialsRevoke},
	RealmSecurity:        {PermSessionsRevoke, PermCredentialsRevoke},
	RealmSupport:         {},
	RealmBilling:         {},
	NotificationDelivery: {PermNotificationsClaim},
}

// Known は組み込みのロールかを返す。
func Known(r string) bool { _, ok := builtin[r]; return ok }

// Grant はロールを付与する（realm 全体）。
func Grant(ctx context.Context, tx port.Tx, realmID, roleName string, t port.PrincipalType, principalID string, now time.Time) error {
	return tx.RoleBindings().Create(ctx, port.RoleBinding{ID: id.New(id.RoleBinding), RealmID: realmID, Role: roleName,
		PrincipalType: t, PrincipalID: principalID, CreatedAt: now})
}

// Allowed は主体が realm 全体の範囲で perm を持つかを返す。
func Allowed(ctx context.Context, tx port.Tx, realmID string, t port.PrincipalType, principalID, perm string) (bool, error) {
	bs, err := tx.RoleBindings().ListByPrincipal(ctx, realmID, t, principalID)
	if err != nil {
		return false, err
	}
	for _, b := range bs {
		if b.OrgID == "" && slices.Contains(builtin[b.Role], perm) {
			return true, nil
		}
	}
	return false, nil
}
