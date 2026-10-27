// Package check は認可の判定（check）を行う（design.md 4.5、11.5、ADR 0064）。
//
//	check(principal, action, resource, context) -> allow / deny
//
// 主体の直接のロールと所属 Group のロールのうち、範囲（realm 全体 / Org 全体 / リソース）が合うものを合算する。
// Org がオン（Members がある）なら、Org の範囲の付与と、Membership の org_role の組み込みのロールが、その Org の
// 使える所属を持つ間だけ効く。Org がオフなら realm 全体の RBAC。判定は fail-closed（知らないロールは権限を持たない）。
//
// 判定の材料（主体と範囲ごとの付与）は TTL の間だけプロセスの中にキャッシュする。authz の変更は Invalidate ですぐに、
// 所属の変更や他のインスタンスでの変更は TTL の内に反映する（反映の遅れの上限。5.3 と同じ保証）。
package check

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// Principal は判定の主体（内部 ID）。
type Principal struct {
	Type port.PrincipalType
	ID   string
}

// Resource は判定の対象のリソース。空なら範囲（Org か realm）全体。Type が "org" なら、その Org 全体を表す。
type Resource struct {
	Type string
	ID   string
}

// ResourceOrg は Org 全体を表すリソースの種類。
const ResourceOrg = "org"

// Request は判定の問い。
type Request struct {
	Principal Principal
	Action    string
	// OrgID は判定の文脈の Org（内部 ID）。空なら realm の範囲。
	OrgID    string
	Resource Resource
}

// Members は authn 側の所属の問い合わせ（authz は authn を import しない。server が組み立てる）。
type Members interface {
	// OrgRole は主体が now に orgID（内部 ID）で使える所属の org_role を返す。所属が無いか、停止・有効期間の外などで
	// 使えなければ ok が false。
	OrgRole(ctx context.Context, tx port.Tx, realmID string, p Principal, orgID string, now time.Time) (r port.OrgRole, ok bool, err error)
}

// Checker は判定を行う。
type Checker struct {
	Storage port.Storage
	Clock   clock.Clock
	// Members は所属の問い合わせ。nil なら Org がオフで、Org の範囲の付与は効かない。
	Members Members
	// TTL は判定の材料のキャッシュの期限（反映の遅れの上限）。0 ならキャッシュしない。
	TTL time.Duration
	// MaxEntries はキャッシュの件数の上限。超えたら全部捨てる。0 なら 100000。
	MaxEntries int

	mu    sync.Mutex
	cache map[key]entry
	gen   map[string]uint64 // realm ごとの世代。Invalidate で進める
}

type key struct {
	realmID string
	p       Principal
	orgID   string
}

type entry struct {
	grants []Grant
	exp    time.Time
	gen    uint64
}

// Grant は判定の材料の1件：範囲のリソース（空なら範囲全体）と、そこで持つ権限。
type Grant struct {
	ResourceType string
	ResourceID   string
	Permissions  []string
	// Role はもとになったロール（組み込みは名前、独自は内部 ID）。
	Role string
}

func (g Grant) covers(r Resource, action string) bool {
	if g.ResourceType != "" && (g.ResourceType != r.Type || g.ResourceID != r.ID) {
		return false
	}
	return role.Covered(g.Permissions, action)
}

func normalize(r Request) Request {
	if r.Resource.Type == ResourceOrg {
		r.OrgID, r.Resource = r.Resource.ID, Resource{}
	}
	return r
}

// Check は判定する。判定の材料はキャッシュから使い、無ければ1つのトランザクションで集める。
func (c *Checker) Check(ctx context.Context, realmID string, r Request) (bool, error) {
	r = normalize(r)
	gs, err := c.cached(ctx, realmID, r.Principal, r.OrgID)
	if err != nil {
		return false, err
	}
	return allowed(gs, r), nil
}

// CheckTx は呼び出し側のトランザクションで判定する（キャッシュを使わない。同じトランザクションの変更を見る）。
func (c *Checker) CheckTx(ctx context.Context, tx port.Tx, realmID string, r Request) (bool, error) {
	r = normalize(r)
	gs, err := c.Grants(ctx, tx, realmID, r.Principal, r.OrgID)
	if err != nil {
		return false, err
	}
	return allowed(gs, r), nil
}

func allowed(gs []Grant, r Request) bool {
	if r.Action == "" {
		return false
	}
	return slices.ContainsFunc(gs, func(g Grant) bool { return g.covers(r.Resource, r.Action) })
}

// Holds は主体が範囲全体（リソースを限らない付与）で perms をすべて持つかを返す。ロールの付与や作成で、
// 持っていない権限を人に渡せないようにするために使う。
func (c *Checker) Holds(ctx context.Context, tx port.Tx, realmID string, p Principal, orgID string, perms []string) (bool, error) {
	gs, err := c.Grants(ctx, tx, realmID, p, orgID)
	if err != nil {
		return false, err
	}
	var have []string
	for _, g := range gs {
		if g.ResourceType == "" {
			have = append(have, g.Permissions...)
		}
	}
	for _, want := range perms {
		if !role.Covered(have, want) {
			return false, nil
		}
	}
	return true, nil
}

func (c *Checker) cached(ctx context.Context, realmID string, p Principal, orgID string) ([]Grant, error) {
	if c.TTL <= 0 {
		var gs []Grant
		err := c.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			gs, err = c.Grants(ctx, tx, realmID, p, orgID)
			return err
		})
		return gs, err
	}
	k := key{realmID, p, orgID}
	now := c.Clock.Now()
	c.mu.Lock()
	e, hit := c.cache[k]
	gen := c.gen[realmID]
	c.mu.Unlock()
	if hit && e.gen == gen && now.Before(e.exp) {
		return e.grants, nil
	}
	var gs []Grant
	err := c.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		gs, err = c.Grants(ctx, tx, realmID, p, orgID)
		return err
	})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// 集める間に Invalidate されたら、古い材料をキャッシュしない。
	if c.gen[realmID] != gen {
		return gs, nil
	}
	limit := c.MaxEntries
	if limit <= 0 {
		limit = 100000
	}
	if c.cache == nil || len(c.cache) >= limit {
		c.cache = map[key]entry{}
	}
	c.cache[k] = entry{grants: gs, exp: now.Add(c.TTL), gen: gen}
	return gs, nil
}

// Invalidate は realm の判定の材料のキャッシュを捨てる（このインスタンスの authz の変更の後に呼ぶ）。
func (c *Checker) Invalidate(realmID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen == nil {
		c.gen = map[string]uint64{}
	}
	c.gen[realmID]++
}

// Grants は主体の、範囲（orgID が空なら realm）で効く付与を集める。
func (c *Checker) Grants(ctx context.Context, tx port.Tx, realmID string, p Principal, orgID string) ([]Grant, error) {
	if c.Members == nil {
		orgID = "" // Org がオフなら realm の範囲だけ
	}
	var member *bool
	var orgRole port.OrgRole
	isMember := func() (bool, error) {
		if member == nil {
			ok := false
			if orgID != "" {
				var err error
				if orgRole, ok, err = c.Members.OrgRole(ctx, tx, realmID, p, orgID, c.Clock.Now()); err != nil {
					return false, err
				}
			}
			member = &ok
		}
		return *member, nil
	}

	// 直接の付与と Group の付与を、独自のロールの中身とともに1回で集める（キャッシュに外れたときの往復を減らす）。
	bs, err := tx.RoleBindings().ListEffective(ctx, realmID, p.Type, p.ID)
	if err != nil {
		return nil, err
	}
	var out []Grant
	// Org の Group と Org の範囲の付与は、その Org の使える所属を持つ間だけ効く（3.2）。
	inScope := func(b port.EffectiveBinding) (bool, error) {
		for _, sc := range []string{b.GroupOrgID, b.OrgID} {
			if sc == "" {
				continue
			}
			if sc != orgID {
				return false, nil
			}
			if ok, err := isMember(); err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
	for _, b := range bs {
		ok, err := inScope(b)
		if err != nil {
			return nil, err
		}
		if perms := permissionsOf(b); ok && len(perms) > 0 {
			out = append(out, Grant{ResourceType: b.ResourceType, ResourceID: b.ResourceID, Permissions: perms, Role: b.Role})
		}
	}
	if orgID != "" {
		if ok, err := isMember(); err != nil {
			return nil, err
		} else if ok {
			if b, found := role.Lookup(role.OrgRoleOf(orgRole)); found {
				out = append(out, Grant{Permissions: b.Permissions, Role: b.Name})
			}
		}
	}
	return out, nil
}

// permissionsOf は付与のロールの権限を返す。組み込みの Org のロールは付与では効かせない（org_role から効く）。
// 独自のロールは、その付与の範囲（realm 共通か、同じ Org）のものだけが効く。消えたロールは権限を持たない。
func permissionsOf(b port.EffectiveBinding) []string {
	if bi, ok := role.Lookup(b.Role); ok {
		if bi.Scope == role.ScopeOrg || b.OrgID != "" { // 運営者ロールは realm の範囲だけ
			return nil
		}
		return bi.Permissions
	}
	if b.Custom == nil || (b.Custom.OrgID != "" && b.Custom.OrgID != b.OrgID) {
		return nil
	}
	return b.Custom.Permissions
}
