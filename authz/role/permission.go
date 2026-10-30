package role

import (
	"regexp"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/shared/port"
)

// 権限の形と照合、組み込みのロールの一覧（design.md 4.11、ADR 0064）。

// 組み込みの Org のロール。org_role（owner / admin / member）の Membership は、その Org の範囲でこのロールを持つ。
const (
	OrgOwner  = "org:owner"
	OrgAdmin  = "org:admin"
	OrgMember = "org:member"
)

// OrgRoleOf は org_role に対応する組み込みのロールの名前を返す。知らない org_role は空。
func OrgRoleOf(r port.OrgRole) string {
	switch r {
	case port.OrgOwner:
		return OrgOwner
	case port.OrgAdmin:
		return OrgAdmin
	case port.OrgMember:
		return OrgMember
	}
	return ""
}

var orgRoles = map[string][]string{
	OrgOwner:  orgBuiltin[port.OrgOwner],
	OrgAdmin:  orgBuiltin[port.OrgAdmin],
	OrgMember: orgBuiltin[port.OrgMember],
}

// Scope は組み込みのロールを付与できる範囲。
type Scope string

const (
	ScopeRealm  Scope = "realm"  // 運営者ロール（org_id が空の付与）
	ScopeOrg    Scope = "org"    // Org のロール（Membership の org_role から。付与はしない）
	ScopeSystem Scope = "system" // 組み込みのサービスアカウントだけ
)

// Builtin は組み込みのロールの定義。
type Builtin struct {
	Name        string
	Scope       Scope
	Permissions []string
}

// Lookup は組み込みのロールを返す。
func Lookup(name string) (Builtin, bool) {
	if ps, ok := builtin[name]; ok {
		sc := ScopeRealm
		if name == NotificationDelivery {
			sc = ScopeSystem
		}
		return Builtin{Name: name, Scope: sc, Permissions: slices.Clone(ps)}, true
	}
	if ps, ok := orgRoles[name]; ok {
		return Builtin{Name: name, Scope: ScopeOrg, Permissions: slices.Clone(ps)}, true
	}
	return Builtin{}, false
}

// Builtins は組み込みのロールを名前の順に返す。
func Builtins() []Builtin {
	var out []Builtin
	for name := range builtin {
		b, _ := Lookup(name)
		out = append(out, b)
	}
	for name := range orgRoles {
		b, _ := Lookup(name)
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b Builtin) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// IsBuiltinName は組み込みのロールの名前か、その名前空間（realm:・org:・system:）かを返す。独自のロールには使えない。
func IsBuiltinName(name string) bool {
	return strings.HasPrefix(name, "realm:") || strings.HasPrefix(name, "org:") || strings.HasPrefix(name, "system:")
}

var permRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}:(\*|[a-z0-9_.-]{1,64})$`)

// ValidPermission は権限の形（`<リソース>:<操作>`、操作の `*` はそのリソースのすべて）かを返す。
func ValidPermission(p string) bool { return permRE.MatchString(p) }

// Matches は付与された権限 granted が、求める権限 want を満たすかを返す（`x:*` は `x:` のすべて）。
func Matches(granted, want string) bool {
	if granted == want {
		return true
	}
	res, ok := strings.CutSuffix(granted, ":*")
	return ok && strings.HasPrefix(want, res+":")
}

// Covered は want が granted のどれかで満たされるかを返す。
func Covered(granted []string, want string) bool {
	return slices.ContainsFunc(granted, func(g string) bool { return Matches(g, want) })
}

// realmResources は IAM 自身の、realm の範囲の管理の権限のリソース。Org の範囲のロールには入れられない
// （Org の範囲の付与は realm の範囲の判定に効かないため、入れても意味が無く、誤解のもとになる）。
var realmResources = []string{"users", "orgs", "sessions", "credentials", "suspensions", "connections", "pii", "notifications", "roles", "groups", "authz", "clients", "signing_keys", "attributes", "risk", "risk_types"}

// IAM は IAM 自身の権限（realm の管理の権限と、Org の操作の `org:`）かを返す。管理の操作では、これを渡すには自分が持って
// いなければならない（権限の引き上げを防ぐ）。それ以外は連携先の権限で、範囲の管理者が自由に渡せる。
func IAM(p string) bool {
	res, _, _ := strings.Cut(p, ":")
	return res == "org" || slices.Contains(realmResources, res)
}

// RealmOnly は realm の範囲でしか意味の無い（IAM 自身の管理の）権限かを返す。
func RealmOnly(p string) bool {
	res, _, _ := strings.Cut(p, ":")
	return slices.Contains(realmResources, res)
}
