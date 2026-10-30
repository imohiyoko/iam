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
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
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
	// Context は主体の認証の文脈（ADR 0084）。nil なら文脈が無く、条件付きの付与は効かない（fail-closed）。
	Context *AuthContext
	// Bands はリスクの段階の境界。nil なら realm の一覧の境界を使う（条件付きの付与があるときだけ読む）。
	Bands Bands
}

// Members は authn 側の所属の問い合わせ（authz は authn を import しない。server が組み立てる）。
type Members interface {
	// OrgRole は主体が now に orgID（内部 ID）で使える所属の org_role を返す。所属が無いか、停止・有効期間の外などで
	// 使えなければ ok が false。
	OrgRole(ctx context.Context, tx port.Tx, realmID string, p Principal, orgID string, now time.Time) (r port.OrgRole, ok bool, err error)
	// OrgUsable は Org（内部 ID）が now に使えるか（削除・停止・有効期間の外でない）を返す。親から効かせる付与の判定に使う。
	OrgUsable(ctx context.Context, tx port.Tx, realmID, orgID string, now time.Time) (bool, error)
}

// Checker は判定を行う。
type Checker struct {
	Storage port.Storage
	Clock   clock.Clock
	// Members は所属の問い合わせ。nil なら Org がオフで、Org の範囲の付与は効かない。
	Members Members
	// Hierarchy は Org 階層（フィーチャー org_hierarchy。ADR 0078）。true なら、Org の範囲の判定に祖先の Org の付与と
	// org_role を、祖先の使える所属を持つ間だけ（判定の Org が使えるときに）効かせる。
	Hierarchy bool
	// NestedGroups は Group のネスト（フィーチャー nested_groups。ADR 0079）。true なら、所属する Group を含む Group の付与も効く。
	NestedGroups bool
	// TTL は判定の材料のキャッシュの期限（反映の遅れの上限）。0 ならキャッシュしない。
	TTL time.Duration
	// MaxEntries はキャッシュの件数の上限。超えたら全部捨てる。0 なら 100000。
	MaxEntries int

	mu    sync.Mutex
	cache map[key]entry
	reqs  map[reqKey]reqEntry
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
	// Condition は付与の条件（ADR 0084）。nil なら条件なし。
	Condition *Condition
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
	d, err := c.Decide(ctx, realmID, r)
	return d.Allow, err
}

// CheckTx は呼び出し側のトランザクションで判定する（キャッシュを使わない。同じトランザクションの変更を見る）。
func (c *Checker) CheckTx(ctx context.Context, tx port.Tx, realmID string, r Request) (bool, error) {
	d, err := c.DecideTx(ctx, tx, realmID, r)
	return d.Allow, err
}

// Decide は判定し、条件で拒んだときは満たさなかった条件の理由を返す（ADR 0084）。材料は Check と同じくキャッシュから使う。
// 条件と要件はキャッシュの外で、判定のたびに文脈と突き合わせる。
func (c *Checker) Decide(ctx context.Context, realmID string, r Request) (Decision, error) {
	r = normalize(r)
	gs, err := c.cached(ctx, realmID, r.Principal, r.OrgID)
	if err != nil {
		return Decision{}, err
	}
	return c.decide(gs, r, c.source(ctx, realmID, r))
}

// Require は操作の要件（名前空間と Org の要件。ADR 0084）だけを評価する。付与を問わない操作（本人の重要な操作など）に使う。
func (c *Checker) Require(ctx context.Context, realmID string, r Request) (Decision, error) {
	r = normalize(r)
	return c.decide([]Grant{{Permissions: []string{r.Action}}}, r, c.source(ctx, realmID, r))
}

// source は Decide の材料（境界と要件）を、キャッシュとそのたびのトランザクションで読む。
func (c *Checker) source(ctx context.Context, realmID string, r Request) source {
	return source{
		bands: func() (Bands, error) {
			var b Bands
			err := c.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				var err error
				b, err = RealmBands(ctx, tx, realmID)
				return err
			})
			return b, err
		},
		requirements: func() (requirements, error) { return c.cachedRequirements(ctx, realmID, NamespaceOf(r.Action), r.OrgID) },
	}
}

// DecideTx は呼び出し側のトランザクションで Decide を行う。
func (c *Checker) DecideTx(ctx context.Context, tx port.Tx, realmID string, r Request) (Decision, error) {
	r = normalize(r)
	gs, err := c.Grants(ctx, tx, realmID, r.Principal, r.OrgID)
	if err != nil {
		return Decision{}, err
	}
	return c.decide(gs, r, source{
		bands:        func() (Bands, error) { return RealmBands(ctx, tx, realmID) },
		requirements: func() (requirements, error) { return c.Requirements(ctx, tx, realmID, NamespaceOf(r.Action), r.OrgID) },
	})
}

// RealmBands は realm の一覧のリスクの段階の境界（有効な種類だけ）。
func RealmBands(ctx context.Context, tx port.Tx, realmID string) (Bands, error) {
	rows, err := tx.RiskTypes().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return Bands(risk.CatalogOf(rows).Bands()), nil
}

// source は判定が必要になったときだけ読む材料（境界と要件）。
type source struct {
	bands        func() (Bands, error)
	requirements func() (requirements, error)
}

// decide は操作を許す付与があるかを見る。条件なしの付与か、条件を満たす付与があれば許す。条件付きの付与だけが操作を
// 許すなら、それらの満たさなかった条件の理由を返す（付与が無い拒否は理由なし。権限の有無を条件の理由で漏らさない）。
// 付与で許すなら、操作に当たる名前空間の要件と Org の要件をすべて AND する（ADR 0084）。
// 境界は r.Bands（無ければ realm の一覧）に名前空間の境界を重ねたもの。
func (c *Checker) decide(gs []Grant, r Request, src source) (Decision, error) {
	if r.Action == "" {
		return Decision{}, nil
	}
	now := c.Clock.Now()
	var rq *requirements
	loadRequirements := func() (requirements, error) {
		if rq == nil {
			x, err := src.requirements()
			if err != nil {
				return requirements{}, err
			}
			rq = &x
		}
		return *rq, nil
	}
	var bands Bands
	loadBands := func() (Bands, error) {
		if bands != nil {
			return bands, nil
		}
		base := r.Bands
		if base == nil {
			b, err := src.bands()
			if err != nil {
				return nil, err
			}
			base = b
		}
		x, err := loadRequirements()
		if err != nil {
			return nil, err
		}
		bands = bandsWith(base, x.namespace.Bands)
		if bands == nil {
			bands = Bands{}
		}
		return bands, nil
	}

	var unmet []string
	allow, conditional := false, false
	for _, g := range gs {
		if !g.covers(r.Resource, r.Action) {
			continue
		}
		if g.Condition == nil {
			allow = true
			break
		}
		b, err := loadBands()
		if err != nil {
			return Decision{}, err
		}
		ok, u := g.Condition.Eval(r.Context, now, b)
		if ok {
			allow = true
			break
		}
		conditional, unmet = true, append(unmet, u...)
	}
	if !allow {
		if !conditional {
			return Decision{}, nil
		}
		slices.Sort(unmet)
		return Decision{Unmet: slices.Compact(unmet)}, nil
	}

	x, err := loadRequirements()
	if err != nil {
		return Decision{}, err
	}
	conds := x.matching(r.Action)
	if len(conds) == 0 {
		return Decision{Allow: true}, nil
	}
	b, err := loadBands()
	if err != nil {
		return Decision{}, err
	}
	unmet = nil
	for _, cond := range conds {
		if ok, u := cond.EvalRequirement(r.Context, now, b); !ok {
			unmet = append(unmet, u...)
		}
	}
	if len(unmet) == 0 {
		return Decision{Allow: true}, nil
	}
	slices.Sort(unmet)
	return Decision{Unmet: slices.Compact(unmet)}, nil
}

// Holds は主体が範囲全体（リソースを限らない付与）で perms をすべて持つかを返す。ロールの付与や作成で、
// 持っていない権限を人に渡せないようにするために使う。条件付きの付与は、主体の今の文脈 ac で条件を満たすものだけを数える
// （ADR 0084。ac が nil なら数えない。境界は realm の一覧のもの）。
func (c *Checker) Holds(ctx context.Context, tx port.Tx, realmID string, p Principal, orgID string, perms []string, ac *AuthContext) (bool, error) {
	gs, err := c.Grants(ctx, tx, realmID, p, orgID)
	if err != nil {
		return false, err
	}
	now := c.Clock.Now()
	var bands Bands
	var have []string
	for _, g := range gs {
		if g.Condition != nil {
			if bands == nil {
				if bands, err = RealmBands(ctx, tx, realmID); err != nil {
					return false, err
				}
			}
			if ok, _ := g.Condition.Eval(ac, now, bands); !ok {
				continue
			}
		}
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
	now := c.Clock.Now()
	// 範囲の Org：判定の Org と、階層がオンならその祖先（近い順）。
	scopes := []string{}
	if orgID != "" {
		scopes = append(scopes, orgID)
		if c.Hierarchy {
			up, err := tx.Orgs().Ancestors(ctx, realmID, orgID)
			if err != nil {
				return nil, err
			}
			scopes = append(scopes, up...)
		}
	}
	type membership struct {
		role port.OrgRole
		ok   bool
	}
	members := map[string]membership{}
	memberOf := func(sc string) (membership, error) {
		if m, done := members[sc]; done {
			return m, nil
		}
		r, ok, err := c.Members.OrgRole(ctx, tx, realmID, p, sc, now)
		if err != nil {
			return membership{}, err
		}
		members[sc] = membership{r, ok}
		return members[sc], nil
	}
	// 祖先から効かせるのは、判定の Org そのものが使えるときだけ。
	var usable *bool
	orgUsable := func() (bool, error) {
		if usable == nil {
			ok, err := c.Members.OrgUsable(ctx, tx, realmID, orgID, now)
			if err != nil {
				return false, err
			}
			usable = &ok
		}
		return *usable, nil
	}
	// sc の付与が効くか：範囲の Org のどれかで、その Org の使える所属を持つこと（祖先なら判定の Org が使えること）。
	applies := func(sc string) (bool, error) {
		if !slices.Contains(scopes, sc) {
			return false, nil
		}
		m, err := memberOf(sc)
		if err != nil || !m.ok {
			return false, err
		}
		if sc == orgID {
			return true, nil
		}
		return orgUsable()
	}

	// 直接の付与と Group（ネストなら、それを含む Group も）の付与を、独自のロールの中身とともに1回で集める
	// （キャッシュに外れたときの往復を減らす）。
	bs, err := tx.RoleBindings().ListEffective(ctx, realmID, p.Type, p.ID, c.NestedGroups)
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
			if ok, err := applies(sc); err != nil || !ok {
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
			cond, valid := conditionOf(b)
			if !valid {
				continue
			}
			out = append(out, Grant{ResourceType: b.ResourceType, ResourceID: b.ResourceID, Permissions: perms, Role: b.Role, Condition: cond})
		}
	}
	for _, sc := range scopes {
		ok, err := applies(sc)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if b, found := role.Lookup(role.OrgRoleOf(members[sc].role)); found {
			out = append(out, Grant{Permissions: b.Permissions, Role: b.Name})
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

// conditionOf は付与の条件を読む。読めない条件の付与は効かせない（fail-closed）。保存のときに検査しているので、通常は起きない。
func conditionOf(b port.EffectiveBinding) (*Condition, bool) {
	c, err := ParseCondition(b.Condition)
	return c, err == nil
}

// ParseCondition は保存した付与の条件を読む。空なら nil（条件なし）。
func ParseCondition(raw []byte) (*Condition, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var c Condition
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
