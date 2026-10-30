// Package role は組み込みのロールと、その権限を定める（design.md 4.11）。
//
// M1 では組み込みのロールだけを名前で付与する。ロールの表とホスト先の独自のロールは M4 で足す。
// 判定は fail-closed：知らないロールは権限を持たない。
package role

import (
	"context"
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
	// PermRolesManage は realm 共通の独自のロールと、realm の範囲のロールの付与の管理（運営者ロールの付与を含む。4.11）。
	PermRolesManage = "roles:manage"
	// PermGroupsManage は realm 全体の Group と所属の管理。
	PermGroupsManage = "groups:manage"
	// PermAuthzCheck は他の主体についての判定の問い合わせ（連携先・サービスアカウント向け）。
	PermAuthzCheck = "authz:check"
	// PermClientsManage は連携先（OIDC のクライアント）の登録・変更・削除（5.5）。
	PermClientsManage = "clients:manage"
	// PermSigningKeysRotate は ID トークンの署名鍵のローテーション（9.3）。
	PermSigningKeysRotate = "signing_keys:rotate"
	// PermServiceAccountsManage は汎用サービスアカウントとその認証情報の作成・削除（ADR 0074）。
	PermServiceAccountsManage = "service_accounts:manage"
	// PermRealmsManage は realm の作成・変更と、realm の運営者の作成（複数 realm。ADR 0083）。既定の realm でだけ効く。
	PermRealmsManage = "realms:manage"
	// PermAttributesManage はカスタム属性の定義（ADR 0080）。PermAttributesRead・PermAttributesWrite はユーザーの値。
	PermAttributesManage = "attributes:manage"
	PermAttributesRead   = "attributes:read"
	PermAttributesWrite  = "attributes:write"
	// PermRiskTypesManage は realm のリスクの種類の一覧と境界（ADR 0084）。
	PermRiskTypesManage = "risk_types:manage"
	// PermRiskWrite は評価器によるセッションのリスクの点数の更新（ADR 0084）。サービスアカウントにだけ効く（人が持っても使えない）。
	// realm:owner が持つのは、評価器のサービスアカウントに独自のロールで渡すため（渡すには自分が持っていなければならない）。
	PermRiskWrite = "risk:write"
	// PermRequirementsManage は操作の名前空間ごとの設定（要件と段階の境界。ADR 0084）。resource_type = action_namespace の
	// リソース単位の付与で、1つの名前空間に限れる。
	PermRequirementsManage = "requirements:manage"
)

// 本人の重要な操作の名前（ADR 0084）。付与は要らず、直近の認証（max_auth_age）に加えて、名前空間 `me` と active な Org の
// 要件を求める（要件 auth_within などで操作ごとに厳しくできる）。
const (
	ActionMeMethods          = "me:methods"  // 認証手段（メール・パスキー・TOTP など）の追加・削除
	ActionMePassword         = "me:password" // パスワードの設定・変更
	ActionMeRecoveryCodes    = "me:recovery_codes"
	ActionMeDelete           = "me:delete"
	ActionMeMerge            = "me:merge"
	ActionMeAcceptManagement = "me:accept_management" // Org の管理下に入る（ADR 0077）
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
	RealmOwner: append([]string{PermRealmsManage, PermRiskTypesManage, PermRiskWrite, PermRequirementsManage, PermAttributesManage, PermAttributesRead, PermAttributesWrite, PermServiceAccountsManage, PermClientsManage, PermSigningKeysRotate, PermRolesManage, PermGroupsManage, PermAuthzCheck, PermOrgsCreate, PermOrgsRead, PermOrgsUpdate, PermOrgsDelete, PermUsersDelete, PermUsersLegalHold, PermSessionsRevoke, PermUsersCreate, PermUsersUpdate, PermUsersRecover, PermUsersLoginLink, PermConnectionsManage, PermPIIRead,
		PermCredentialsRevoke, PermSuspensionsAny}, suspend("tos_violation", "customer_request", "security_risk", "billing")...),
	RealmAdmin: append([]string{PermAttributesRead, PermAttributesWrite, PermServiceAccountsManage, PermGroupsManage, PermAuthzCheck, PermOrgsCreate, PermOrgsRead, PermOrgsUpdate, PermOrgsDelete, PermUsersDelete, PermSessionsRevoke, PermUsersCreate, PermUsersUpdate, PermUsersRecover, PermUsersLoginLink, PermCredentialsRevoke},
		suspend("tos_violation", "customer_request")...),
	RealmSecurity:        append([]string{PermSessionsRevoke, PermCredentialsRevoke}, suspend("security_risk")...),
	RealmSupport:         {PermAttributesRead, PermOrgsRead, PermSuspensionsRead, PermUsersRecover},
	RealmBilling:         suspend("billing"),
	NotificationDelivery: {PermNotificationsClaim},
}

// Known は組み込みのロールかを返す。
func Known(r string) bool { _, ok := builtin[r]; return ok }

// Grant はロールを付与する（realm 全体）。
func Grant(ctx context.Context, tx port.Tx, realmID, roleName string, t port.PrincipalType, principalID string, now time.Time) error {
	return tx.RoleBindings().Create(ctx, port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: realmID, Role: roleName,
		PrincipalType: t, PrincipalID: principalID, CreatedAt: now})
}
