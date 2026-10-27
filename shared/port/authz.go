package port

import (
	"context"
	"time"
)

// 認可側（authz）の Repository（design.md 3.2、ADR 0064）。

// PrincipalGroup は Group を主体とするロールの付与（group_members の member_type には使わない。ネストは M7）。
const PrincipalGroup PrincipalType = "group"

// Role は roles の1行（ホスト先・Org が足した独自のロール）。組み込みのロールは authz/role のコードにあり、表には置かない。
type Role struct {
	ID       string
	PublicID string // 外部 ID。realm 内で一意
	RealmID  string
	OrgID    string // 空なら realm 共通
	Name     string // (realm, org) の中で一意
	// Permissions は権限（"project:read" など）。並びは保存した順。
	Permissions []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RoleRepo は roles と role_permissions の Repository。
type RoleRepo interface {
	// Create は ID・(realm, PublicID)・(realm, org, name) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, r Role) error
	Get(ctx context.Context, realmID, id string) (Role, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Role, error)
	// ListByOrg は org の（orgID が空なら realm 共通の）ロールを名前の順に返す。
	ListByOrg(ctx context.Context, realmID, orgID string) ([]Role, error)
	// Update は名前と権限と更新時刻を置き換える。無ければ errs.NotFound、名前が重複すれば errs.Conflict。
	Update(ctx context.Context, r Role) error
	// Delete はロールを消す。無ければ errs.NotFound。付与は呼び出し側が先に消す。
	Delete(ctx context.Context, realmID, id string) error
}

// RoleBinding は role_bindings の1行。
type RoleBinding struct {
	ID       string
	PublicID string // 外部 ID。realm 内で一意
	RealmID  string
	// Role は組み込みのロールの名前（realm:owner など）か、独自のロール（roles）の内部 ID。
	Role          string
	PrincipalType PrincipalType
	PrincipalID   string
	OrgID         string // 空なら realm 全体
	// ResourceType と ResourceID は付与の範囲のリソース。空なら Org 全体（OrgID が空なら realm 全体）。
	ResourceType string
	ResourceID   string
	CreatedAt    time.Time
}

// RoleBindingRepo は role_bindings の Repository。
type RoleBindingRepo interface {
	// Create は ID・(realm, PublicID)・(realm, role, principal, org, resource) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, b RoleBinding) error
	GetByPublicID(ctx context.Context, realmID, publicID string) (RoleBinding, error)
	// Delete は付与を消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
	// ListByPrincipal・ListByRole・ListByOrg は作成時刻の順（同時刻は ID の順）に返す。
	ListByPrincipal(ctx context.Context, realmID string, t PrincipalType, principalID string) ([]RoleBinding, error)
	ListByRole(ctx context.Context, realmID, role string) ([]RoleBinding, error)
	// ListByOrg は org の（orgID が空なら realm 全体の）付与を返す。
	ListByOrg(ctx context.Context, realmID, orgID string) ([]RoleBinding, error)
	// ListEffective は判定のために、主体の直接の付与と、主体が所属する Group の付与を、独自のロールの中身とともに
	// 1回で返す（作成時刻の順、同時刻は ID の順）。nested なら、所属する Group を含む Group（閉包、design.md 11.5）の付与も返す。
	ListEffective(ctx context.Context, realmID string, t PrincipalType, principalID string, nested bool) ([]EffectiveBinding, error)
}

// EffectiveBinding は判定に使う付与（ListEffective）。
type EffectiveBinding struct {
	RoleBinding
	// GroupOrgID は Group の付与のときの、その Group の Org（空なら realm 全体）。
	GroupOrgID string
	// Custom は独自のロールの付与のときの、そのロール。組み込みのロールの名前か、消えたロールなら nil。
	Custom *Role
}

// Group は groups の1行（design.md 3.2）。
type Group struct {
	ID        string
	PublicID  string // 外部 ID。realm 内で一意
	RealmID   string
	OrgID     string // 空なら realm 全体
	Name      string // (realm, org) の中で一意
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GroupMember は group_members の1行。ユーザー・サービスアカウントと、Group のネスト（design.md 11.5）では Group。
type GroupMember struct {
	GroupID    string
	MemberType PrincipalType
	MemberID   string
	CreatedAt  time.Time
}

// GroupLink は Group のネストの閉包の1行（design.md 11.5）。Depth は最も長い経路の段数（1 が直接）。
type GroupLink struct {
	GroupID string
	Depth   int
}

// GroupRepo は groups と group_members の Repository。
type GroupRepo interface {
	// Create は ID・(realm, PublicID)・(realm, org, name) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, g Group) error
	Get(ctx context.Context, realmID, id string) (Group, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Group, error)
	// ListByOrg は org の（orgID が空なら realm 全体の）Group を名前の順に返す。
	ListByOrg(ctx context.Context, realmID, orgID string) ([]Group, error)
	// Rename は名前と更新時刻を置き換える。無ければ errs.NotFound、重複すれば errs.Conflict。
	Rename(ctx context.Context, realmID, id, name string, updatedAt time.Time) error
	// Delete は Group とその所属（Group の中の所属と、Group としての所属）と閉包の行を消す。無ければ errs.NotFound。
	// 付与は呼び出し側が先に消し、子孫の閉包は後で計算し直す。
	Delete(ctx context.Context, realmID, id string) error
	// AddMember は所属を足す。既にあれば errs.Conflict、Group が無ければ errs.NotFound。
	AddMember(ctx context.Context, realmID string, m GroupMember) error
	// RemoveMember は所属を消す。無ければ errs.NotFound。
	RemoveMember(ctx context.Context, realmID, groupID string, t PrincipalType, memberID string) error
	// ListMembers は所属を作成時刻の順に返す。
	ListMembers(ctx context.Context, realmID, groupID string) ([]GroupMember, error)
	// ListByMember は主体が所属する Group を作成時刻の順に返す。
	ListByMember(ctx context.Context, realmID string, t PrincipalType, memberID string) ([]Group, error)

	// Ancestors は Group を（推移的に）含む Group を、Depth の順（同じなら ID の順）に返す。
	Ancestors(ctx context.Context, realmID, groupID string) ([]GroupLink, error)
	// Descendants は Group が（推移的に）含む Group を、Depth の順（同じなら ID の順）に返す。
	Descendants(ctx context.Context, realmID, groupID string) ([]GroupLink, error)
	// SetAncestors は Group の閉包の行（含む側）を置き換える。
	SetAncestors(ctx context.Context, realmID, groupID string, ancestors []GroupLink) error
	// CountNested は Group としての所属と閉包の行の数（すべての realm）。
	CountNested(ctx context.Context) (int, error)
	// PurgeNested は閉包の行を、その後に Group としての所属を、合わせて最大 limit 件消し、消した件数を返す。
	PurgeNested(ctx context.Context, limit int) (int, error)
}
