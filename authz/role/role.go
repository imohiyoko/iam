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
	// PermSuspensionsRead は停止の一覧（4.7）。
	PermSuspensionsRead = "suspensions:read"
	// PermUsersUpdate はユーザーの有効期間などの変更（4.8）。
	PermUsersUpdate = "users:update"
	// PermUsersRecover は運営者による復旧用リンクの発行（4.12。realm:support の「復旧手続き」）。
	PermUsersRecover = "users:recover"
	// PermSuspensionsAny は realm で足した種別を含む、すべての種別の停止と解除（realm:owner）。
	PermSuspensionsAny = "suspensions:*"
	// PermOrgsCreate は運営者による共有 Org の作成（realm の org_creation に関わらない。4.11）。
	PermOrgsCreate = "orgs:create"
	// PermOrgsRead は Org と Membership の参照。
	PermOrgsRead = "orgs:read"
	// PermOrgsUpdate は Org と Membership の有効期間の変更（4.8）。
	PermOrgsUpdate = "orgs:update"
	// PermOrgsDelete は共有 Org の削除とその取り消し（4.10）。
	PermOrgsDelete = "orgs:delete"
	// PermUsersDelete はユーザーの削除とその取り消し（4.10）。
	PermUsersDelete = "users:delete"
	// PermUsersLegalHold は消去の保留（4.10）。realm:owner だけ。
	PermUsersLegalHold = "users:legal_hold"
)

// SuspensionPerm は停止の種別ごとの停止・解除の権限（`suspensions:<category>`。4.11）。
// realm で足した種別は realm:owner（suspensions:*）だけが扱える。
func SuspensionPerm(category string) string { return "suspensions:" + category }

func suspend(categories ...string) []string {
	out := []string{PermSuspensionsRead}
	for _, c := range categories {
		out = append(out, SuspensionPerm(c))
	}
	return out
}

var builtin = map[string][]string{
	RealmOwner: append([]string{PermOrgsCreate, PermOrgsRead, PermOrgsUpdate, PermOrgsDelete, PermUsersDelete, PermUsersLegalHold, PermSessionsRevoke, PermUsersCreate, PermUsersUpdate, PermUsersRecover, PermUsersLoginLink, PermConnectionsManage, PermPIIRead,
		PermCredentialsRevoke, PermSuspensionsAny}, suspend("tos_violation", "customer_request", "security_risk", "billing")...),
	RealmAdmin: append([]string{PermOrgsCreate, PermOrgsRead, PermOrgsUpdate, PermOrgsDelete, PermUsersDelete, PermSessionsRevoke, PermUsersCreate, PermUsersUpdate, PermUsersRecover, PermUsersLoginLink, PermCredentialsRevoke},
		suspend("tos_violation", "customer_request")...),
	RealmSecurity:        append([]string{PermSessionsRevoke, PermCredentialsRevoke}, suspend("security_risk")...),
	RealmSupport:         {PermOrgsRead, PermSuspensionsRead, PermUsersRecover},
	RealmBilling:         suspend("billing"),
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

// Covers は、主体が対象のユーザーの realm 全体のロールの権限をすべて持つかを返す。
// 対象になりすませる操作（ログイン用・復旧用のリンクの発行）で、下位のロールが上位のロールの人を乗っ取れないようにする。
func Covers(ctx context.Context, tx port.Tx, realmID string, t port.PrincipalType, principalID, targetUserID string) (bool, error) {
	have, err := perms(ctx, tx, realmID, t, principalID)
	if err != nil {
		return false, err
	}
	need, err := perms(ctx, tx, realmID, port.PrincipalUser, targetUserID)
	if err != nil {
		return false, err
	}
	for p := range need {
		if _, ok := have[p]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func perms(ctx context.Context, tx port.Tx, realmID string, t port.PrincipalType, principalID string) (map[string]struct{}, error) {
	bs, err := tx.RoleBindings().ListByPrincipal(ctx, realmID, t, principalID)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, b := range bs {
		if b.OrgID == "" {
			for _, p := range builtin[b.Role] {
				out[p] = struct{}{}
			}
		}
	}
	return out, nil
}
