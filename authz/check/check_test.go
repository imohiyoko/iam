package check_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

var realm string

// members は所属の偽物：主体ごとの Org と org_role。
type members map[string]map[string]port.OrgRole

// unusable は members で、使えない Org を並べる行のキー。
const unusable = "!unusable"

func (m members) OrgRole(_ context.Context, _ port.Tx, _ string, p check.Principal, orgID string, _ time.Time) (port.OrgRole, bool, error) {
	r, ok := m[p.ID][orgID]
	return r, ok, nil
}

// OrgUsable は、unusable の行に載せた Org だけを使えないとみなす。
func (m members) OrgUsable(_ context.Context, _ port.Tx, _, orgID string, _ time.Time) (bool, error) {
	_, bad := m[unusable][orgID]
	return !bad, nil
}

type env struct {
	t   *testing.T
	s   port.Storage
	clk *clock.Fake
	c   *check.Checker
	n   int
}

func newEnv(t *testing.T, m check.Members) *env {
	k := testkit.New(t)
	realm = k.RealmID
	return &env{t: t, s: k.Storage, clk: k.Clock, c: &check.Checker{Storage: k.Storage, Clock: k.Clock, Members: m, TTL: time.Minute}}
}

func (e *env) tx(f func(ctx context.Context, tx port.Tx) error) {
	e.t.Helper()
	if err := e.s.Tx(context.Background(), f); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) next(p string) string { e.n++; return p + string(rune('a'+e.n)) }

func (e *env) bind(roleKey string, p check.Principal, orgID, resType, resID string) port.RoleBinding {
	b := port.RoleBinding{ID: e.next("rb_"), PublicID: e.next("rbd_"), RealmID: realm, Role: roleKey, PrincipalType: p.Type, PrincipalID: p.ID,
		OrgID: orgID, ResourceType: resType, ResourceID: resID, CreatedAt: e.clk.Now()}
	e.tx(func(ctx context.Context, tx port.Tx) error { return tx.RoleBindings().Create(ctx, b) })
	return b
}

func (e *env) role(orgID string, perms ...string) port.Role {
	r := port.Role{ID: e.next("ro_"), PublicID: e.next("rol_"), RealmID: realm, OrgID: orgID, Name: e.next("role-"), Permissions: perms,
		CreatedAt: e.clk.Now(), UpdatedAt: e.clk.Now()}
	e.tx(func(ctx context.Context, tx port.Tx) error { return tx.Roles().Create(ctx, r) })
	return r
}

func (e *env) group(orgID string, ms ...check.Principal) port.Group {
	g := port.Group{ID: e.next("gr_"), PublicID: e.next("grp_"), RealmID: realm, OrgID: orgID, Name: e.next("group-"), CreatedAt: e.clk.Now(),
		UpdatedAt: e.clk.Now()}
	e.tx(func(ctx context.Context, tx port.Tx) error {
		if err := tx.Groups().Create(ctx, g); err != nil {
			return err
		}
		for _, m := range ms {
			if err := tx.Groups().AddMember(ctx, realm, port.GroupMember{GroupID: g.ID, MemberType: m.Type, MemberID: m.ID, CreatedAt: e.clk.Now()}); err != nil {
				return err
			}
		}
		return nil
	})
	return g
}

func (e *env) check(want bool, r check.Request) {
	e.t.Helper()
	got, err := e.c.Check(context.Background(), realm, r)
	if err != nil {
		e.t.Fatal(err)
	}
	if got != want {
		e.t.Errorf("Check(%+v) = %v, want %v", r, got, want)
	}
}

var (
	alice = check.Principal{Type: port.PrincipalUser, ID: "u_alice"}
	bob   = check.Principal{Type: port.PrincipalUser, ID: "u_bob"}
	robot = check.Principal{Type: port.PrincipalServiceAccount, ID: "sa_robot"}
)

func TestRealmRoles(t *testing.T) {
	e := newEnv(t, nil)
	e.bind(role.RealmSupport, alice, "", "", "")
	r := e.role("", "app.project:read", "app.doc:*")
	e.bind(r.ID, robot, "", "", "")

	e.check(true, check.Request{Principal: alice, Action: role.PermOrgsRead})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgsUpdate})
	e.check(false, check.Request{Principal: alice})
	e.check(true, check.Request{Principal: robot, Action: "app.project:read"})
	e.check(true, check.Request{Principal: robot, Action: "app.doc:write"})
	e.check(false, check.Request{Principal: robot, Action: "app.project:write"})
	e.check(false, check.Request{Principal: bob, Action: "app.project:read"})
	// 組み込みの Org のロールとシステムのロール以外の、知らないロールは権限を持たない（fail-closed）。
	e.bind("no-such-role", bob, "", "", "")
	e.bind(role.OrgOwner, bob, "", "", "")
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgRead})
}

func TestResourceScope(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "app.project:read", "app.project:write")
	e.bind(r.ID, alice, "", "project", "p1")

	e.check(true, check.Request{Principal: alice, Action: "app.project:write", Resource: check.Resource{Type: "project", ID: "p1"}})
	e.check(false, check.Request{Principal: alice, Action: "app.project:write", Resource: check.Resource{Type: "project", ID: "p2"}})
	e.check(false, check.Request{Principal: alice, Action: "app.project:write"})
	// リソースを限った付与は Holds（範囲全体の権限）には数えない。
	e.tx(func(ctx context.Context, tx port.Tx) error {
		ok, err := e.c.Holds(ctx, tx, realm, alice, "", []string{"app.project:read"}, nil)
		if err != nil || ok {
			t.Errorf("Holds = %v, %v", ok, err)
		}
		return nil
	})
}

func TestOrgScope(t *testing.T) {
	m := members{alice.ID: {"o1": port.OrgAdmin}, bob.ID: {"o1": port.OrgMember}}
	e := newEnv(t, m)
	custom := e.role("o1", "app.project:read")
	other := e.role("o2", "app.project:write")
	shared := e.role("", "app.report:read")
	e.bind(custom.ID, bob, "o1", "", "")
	e.bind(other.ID, bob, "o1", "", "") // 別の Org のロールは効かない
	e.bind(shared.ID, bob, "o1", "", "")
	e.bind(role.RealmAdmin, bob, "o1", "", "") // 運営者ロールは Org の範囲では効かない

	// org_role の組み込みのロール。
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o1"})
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, Resource: check.Resource{Type: check.ResourceOrg, ID: "o1"}})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgDelete, OrgID: "o1"})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgRead, OrgID: "o2"})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgRead})
	// Org の範囲の付与。
	e.check(true, check.Request{Principal: bob, Action: "app.project:read", OrgID: "o1"})
	e.check(true, check.Request{Principal: bob, Action: "app.report:read", OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: "app.project:write", OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgsRead, OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: "app.project:read"})

	// 所属が使えなくなれば Org の範囲の付与は効かない（TTL の後）。
	delete(m, bob.ID)
	e.check(true, check.Request{Principal: bob, Action: "app.project:read", OrgID: "o1"})
	e.clk.Advance(time.Minute)
	e.check(false, check.Request{Principal: bob, Action: "app.project:read", OrgID: "o1"})
}

func TestOrgOff(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "app.project:read")
	e.bind(r.ID, alice, "o1", "", "")
	e.bind(role.RealmSupport, alice, "", "", "")
	// Org がオフなら、Org の範囲の付与と org_role は効かず、realm の範囲で判定する。
	e.check(false, check.Request{Principal: alice, Action: "app.project:read", OrgID: "o1"})
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgsRead, OrgID: "o1"})
}

func TestGroups(t *testing.T) {
	m := members{alice.ID: {"o1": port.OrgMember}, robot.ID: {"o1": port.OrgMember}}
	e := newEnv(t, m)
	r := e.role("", "app.project:read")
	g := e.group("", alice, robot)
	e.bind(r.ID, check.Principal{Type: port.PrincipalGroup, ID: g.ID}, "", "", "")
	og := e.group("o1", alice, bob)
	w := e.role("o1", "app.project:write")
	e.bind(w.ID, check.Principal{Type: port.PrincipalGroup, ID: og.ID}, "o1", "", "")

	e.check(true, check.Request{Principal: alice, Action: "app.project:read"})
	e.check(true, check.Request{Principal: robot, Action: "app.project:read"})
	e.check(false, check.Request{Principal: bob, Action: "app.project:read"})
	e.check(true, check.Request{Principal: alice, Action: "app.project:write", OrgID: "o1"})
	// Org の Group は、その Org の使える所属を持つ間だけ効く。
	e.check(false, check.Request{Principal: bob, Action: "app.project:write", OrgID: "o1"})
	e.check(false, check.Request{Principal: alice, Action: "app.project:write"})
}

func TestCacheInvalidate(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "app.project:read")
	e.check(false, check.Request{Principal: alice, Action: "app.project:read"})
	b := e.bind(r.ID, alice, "", "", "")
	// キャッシュの間は古い判定。Invalidate ですぐに反映する。
	e.check(false, check.Request{Principal: alice, Action: "app.project:read"})
	e.c.Invalidate(realm)
	e.check(true, check.Request{Principal: alice, Action: "app.project:read"})
	e.tx(func(ctx context.Context, tx port.Tx) error { return tx.RoleBindings().Delete(ctx, realm, b.ID) })
	e.check(true, check.Request{Principal: alice, Action: "app.project:read"})
	// TTL を過ぎれば反映する。
	e.clk.Advance(time.Minute)
	e.check(false, check.Request{Principal: alice, Action: "app.project:read"})
	// CheckTx はキャッシュを使わない。
	e.bind(r.ID, alice, "", "", "")
	e.tx(func(ctx context.Context, tx port.Tx) error {
		ok, err := e.c.CheckTx(ctx, tx, realm, check.Request{Principal: alice, Action: "app.project:read"})
		if err != nil || !ok {
			t.Errorf("CheckTx = %v, %v", ok, err)
		}
		return nil
	})
}

func TestPermissionMatching(t *testing.T) {
	for _, c := range []struct {
		granted, want string
		ok            bool
	}{
		{"a:read", "a:read", true},
		{"a:*", "a:read", true},
		{"a:*", "a:*", true},
		{"a:read", "a:*", false},
		{"a:*", "ab:read", false},
		{"a:read", "b:read", false},
	} {
		if got := role.Matches(c.granted, c.want); got != c.ok {
			t.Errorf("Matches(%q, %q) = %v", c.granted, c.want, got)
		}
	}
	for p, ok := range map[string]bool{"app.project:read": true, "app.project:*": true, "Project:read": false, "project": false, "app.project:": false, ":read": false, "a:b:c": false} {
		if role.ValidPermission(p) != ok {
			t.Errorf("ValidPermission(%q) != %v", p, ok)
		}
	}
}

// Org 階層（ADR 0078）：祖先の Org の付与と org_role は、祖先の使える所属を持つ間だけ、使える子の Org で効く。
func TestOrgHierarchy(t *testing.T) {
	m := members{alice.ID: {"o_root": port.OrgAdmin}, bob.ID: {"o_mid": port.OrgMember}, robot.ID: {}}
	e := newEnv(t, m)
	e.c.Hierarchy = true
	e.tx(func(ctx context.Context, tx port.Tx) error {
		for _, id := range []string{"o_root", "o_mid", "o_leaf", "o_other"} {
			if err := tx.Orgs().Create(ctx, port.Org{ID: id, PublicID: id + "_pub", RealmID: realm, Kind: port.OrgShared, Name: id,
				CreatedAt: e.clk.Now(), UpdatedAt: e.clk.Now()}); err != nil {
				return err
			}
		}
		if err := tx.Orgs().SetParent(ctx, realm, "o_mid", "o_root", e.clk.Now()); err != nil {
			return err
		}
		return tx.Orgs().SetParent(ctx, realm, "o_leaf", "o_mid", e.clk.Now())
	})
	r := e.role("o_mid", "app.doc:write")
	e.bind(r.ID, bob, "o_mid", "", "")

	// 根の admin は子孫で admin の権限を持つ。関係の無い Org では持たない。
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_mid"})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_other"})
	// 中間の Org の付与は子に効き、親には効かない。
	e.check(true, check.Request{Principal: bob, Action: "app.doc:write", OrgID: "o_leaf"})
	e.check(false, check.Request{Principal: bob, Action: "app.doc:write", OrgID: "o_root"})
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgInvite, OrgID: "o_leaf"})

	// 子の Org が使えなければ、祖先からは効かない。
	m[unusable] = map[string]port.OrgRole{"o_leaf": ""}
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	e.check(false, check.Request{Principal: bob, Action: "app.doc:write", OrgID: "o_leaf"})
	delete(m, unusable)
	// 祖先の所属が使えなければ効かない。
	delete(m[alice.ID], "o_root")
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	// 階層がオフなら祖先の付与は効かない。
	e.c.Hierarchy = false
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: bob, Action: "app.doc:write", OrgID: "o_leaf"})
	e.check(true, check.Request{Principal: bob, Action: "app.doc:write", OrgID: "o_mid"})
}

// bindIf は条件付きの付与を作る。
func (e *env) bindIf(roleKey string, p check.Principal, cond string) port.RoleBinding {
	b := port.RoleBinding{ID: e.next("rb_"), PublicID: e.next("rbd_"), RealmID: realm, Role: roleKey, PrincipalType: p.Type, PrincipalID: p.ID,
		Condition: []byte(cond), CreatedAt: e.clk.Now()}
	e.tx(func(ctx context.Context, tx port.Tx) error { return tx.RoleBindings().Create(ctx, b) })
	return b
}

func (e *env) decide(r check.Request) check.Decision {
	e.t.Helper()
	d, err := e.c.Decide(context.Background(), realm, r)
	if err != nil {
		e.t.Fatal(err)
	}
	var tx check.Decision
	e.tx(func(ctx context.Context, t port.Tx) error {
		tx, err = e.c.DecideTx(ctx, t, realm, r)
		return err
	})
	if !reflect.DeepEqual(d, tx) {
		e.t.Errorf("Decide = %+v, DecideTx = %+v", d, tx)
	}
	return d
}

// 付与の条件（ADR 0084）：条件を満たすときだけ効き、条件だけで拒んだときは理由を返す。
func TestConditionalGrants(t *testing.T) {
	e := newEnv(t, nil)
	approver := e.role("", "app.payment:approve", "app.payment:read")
	e.bindIf(approver.ID, alice, `{"all":[{"amr_has":["hwk"]},{"risk_at_most":{"type":"account","level":"low"}}]}`)
	reader := e.role("", "app.payment:read")
	e.bindIf(reader.ID, bob, `{"factors_at_least":2}`)
	e.bind(e.role("", "app.payment:read").ID, bob, "", "", "") // 条件なしの付与があれば、条件付きの付与は見ない
	e.bindIf(approver.ID, robot, `not json`)

	now := e.clk.Now()
	pwd := &check.AuthContext{AMR: []string{"pwd"}, Factors: 1, AuthTime: now, Attested: true}
	hwk := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now, Risk: map[string]int{"account": 10}, Attested: true}
	risky := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now, Risk: map[string]int{"account": 40}, Attested: true}
	for _, c := range []struct {
		name string
		r    check.Request
		want check.Decision
	}{
		{"no context", check.Request{Principal: alice, Action: "app.payment:approve"}, check.Decision{Unmet: []string{"condition.amr", "condition.risk.account"}}},
		{"password", check.Request{Principal: alice, Action: "app.payment:approve", Context: pwd}, check.Decision{Unmet: []string{"condition.amr", "condition.risk.account"}}},
		{"passkey", check.Request{Principal: alice, Action: "app.payment:approve", Context: hwk}, check.Decision{Allow: true}},
		{"risky", check.Request{Principal: alice, Action: "app.payment:approve", Context: risky}, check.Decision{Unmet: []string{"condition.risk.account"}}},
		// 境界を厳しくしなければ（既定の low < 30）通る。明示の境界は realm の一覧の境界に代わる。
		{"bands", check.Request{Principal: alice, Action: "app.payment:approve", Context: risky, Bands: check.Bands{"account": {Medium: 50, High: 80}}}, check.Decision{Allow: true}},
		// 付与の無い操作の拒否は理由なし。
		{"no grant", check.Request{Principal: alice, Action: "app.payment:send", Context: pwd}, check.Decision{}},
		{"unconditional", check.Request{Principal: bob, Action: "app.payment:read"}, check.Decision{Allow: true}},
		// 読めない条件の付与は効かない（理由も返さない）。
		{"broken", check.Request{Principal: robot, Action: "app.payment:approve", Context: hwk}, check.Decision{}},
	} {
		if got := e.decide(c.r); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Decide = %+v, want %+v", c.name, got, c.want)
		}
	}
	// realm の一覧の境界を使う。
	e.tx(func(ctx context.Context, tx port.Tx) error {
		return tx.RiskTypes().Put(ctx, port.RiskType{RealmID: realm, Name: "account", Enabled: true, BandMedium: 50, BandHigh: 80, CreatedAt: now, UpdatedAt: now})
	})
	if got := e.decide(check.Request{Principal: alice, Action: "app.payment:approve", Context: risky}); !got.Allow {
		t.Errorf("realm bands: %+v", got)
	}
	// Holds は今の文脈で条件を満たす付与だけを数える。
	e.tx(func(ctx context.Context, tx port.Tx) error {
		for _, c := range []struct {
			ac   *check.AuthContext
			want bool
		}{{nil, false}, {pwd, false}, {hwk, true}} {
			if ok, err := e.c.Holds(ctx, tx, realm, alice, "", []string{"app.payment:approve"}, c.ac); err != nil || ok != c.want {
				t.Errorf("Holds(%+v) = %v, %v", c.ac, ok, err)
			}
		}
		return nil
	})
}

// 名前空間の要件と Org の要件（ADR 0084）：付与で許した操作に、どの付与かに関係なく条件を求める。
func TestRequirements(t *testing.T) {
	m := members{alice.ID: {"o_root": port.OrgMember, "o_leaf": port.OrgMember}}
	e := newEnv(t, m)
	e.c.Hierarchy = true
	now := e.clk.Now()
	e.tx(func(ctx context.Context, tx port.Tx) error {
		for _, id := range []string{"o_root", "o_leaf"} {
			if err := tx.Orgs().Create(ctx, port.Org{ID: id, PublicID: id + "_pub", RealmID: realm, Kind: port.OrgShared, Name: id, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
		if err := tx.Orgs().SetParent(ctx, realm, "o_leaf", "o_root", now); err != nil {
			return err
		}
		if err := tx.Orgs().SetSettings(ctx, realm, "o_root", []byte(`{"requirements":{"app.payment:send":{"factors_at_least":2}}}`), now); err != nil {
			return err
		}
		return tx.ActionNamespaces().Put(ctx, port.ActionNamespace{RealmID: realm, Name: "app.payment", CreatedAt: now, UpdatedAt: now,
			Settings: []byte(`{"requirements":{"app.payment:*":{"auth_within":300},"app.payment:send":{"risk_at_most":{"type":"account","level":"low"}}},"bands":{"account":{"medium":20,"high":60}}}`)})
	})
	payer := e.role("", "app.payment:send", "app.payment:read", "app.doc:read")
	e.bind(payer.ID, alice, "", "", "")
	e.bind(payer.ID, bob, "", "", "")

	fresh := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now, Risk: map[string]int{"account": 10}, Attested: true}
	old := &check.AuthContext{AMR: []string{"pwd"}, Factors: 1, AuthTime: now.Add(-time.Hour), Risk: map[string]int{"account": 10}, Attested: true}
	// 名前空間の境界（medium 20）では 25 は medium。realm の既定（30）なら low。
	risky := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now, Risk: map[string]int{"account": 25}, Attested: true}
	declared := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now, Risk: map[string]int{"account": 10}}
	for _, c := range []struct {
		name string
		r    check.Request
		want check.Decision
	}{
		{"fresh", check.Request{Principal: alice, Action: "app.payment:send", Context: fresh}, check.Decision{Allow: true}},
		// 同じ操作に当たる要件（`payment:*` と `payment:send`）はすべて AND する。
		{"old", check.Request{Principal: alice, Action: "app.payment:read", Context: old}, check.Decision{Unmet: []string{"condition.auth_age"}, StepUp: check.StepUp{MaxAge: 300}}},
		{"no context", check.Request{Principal: alice, Action: "app.payment:send"}, check.Decision{Unmet: []string{"condition.attested", "condition.auth_age", "condition.risk.account"}, StepUp: check.StepUp{MaxAge: 300}}},
		{"namespace bands", check.Request{Principal: alice, Action: "app.payment:send", Context: risky}, check.Decision{Unmet: []string{"condition.risk.account"}}},
		// 要件は attested() を暗黙に AND する。
		{"declared", check.Request{Principal: alice, Action: "app.payment:read", Context: declared}, check.Decision{Unmet: []string{"condition.attested"}}},
		// 別の名前空間の操作には効かない。付与の無い操作は理由なし。
		{"other namespace", check.Request{Principal: alice, Action: "app.doc:read", Context: old}, check.Decision{Allow: true}},
		{"no grant", check.Request{Principal: alice, Action: "app.payment:approve", Context: old}, check.Decision{}},
		// Org の要件は判定の Org と祖先のもの。
		{"org leaf", check.Request{Principal: alice, Action: "app.payment:send", OrgID: "o_leaf", Context: &check.AuthContext{AMR: []string{"pwd"}, Factors: 1, AuthTime: now, Attested: true, Risk: map[string]int{"account": 1}}},
			check.Decision{Unmet: []string{"condition.factors"}}},
		{"org fresh", check.Request{Principal: alice, Action: "app.payment:send", OrgID: "o_leaf", Context: fresh}, check.Decision{Allow: true}},
	} {
		if got := e.decide(c.r); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Decide = %+v, want %+v", c.name, got, c.want)
		}
	}
	// 変更は Invalidate ですぐ効く（キャッシュした要件を捨てる）。
	e.tx(func(ctx context.Context, tx port.Tx) error {
		return tx.ActionNamespaces().Put(ctx, port.ActionNamespace{RealmID: realm, Name: "app.payment", Settings: []byte(`{}`), CreatedAt: now, UpdatedAt: now})
	})
	e.c.Invalidate(realm)
	if got := e.decide(check.Request{Principal: alice, Action: "app.payment:read", Context: old}); !got.Allow {
		t.Errorf("after clearing: %+v", got)
	}
	// 階層がオフなら祖先の要件は効かない。
	e.c.Hierarchy = false
	e.c.Invalidate(realm)
	if got := e.decide(check.Request{Principal: alice, Action: "app.payment:send", OrgID: "o_leaf", Context: old}); !got.Allow {
		t.Errorf("hierarchy off: %+v", got)
	}
}

func TestRequirementsValidate(t *testing.T) {
	cat := risk.CatalogOf([]port.RiskType{{Name: "device", Enabled: false}})
	ok := check.Namespace{Requirements: check.Requirements{"app.payment:*": {AuthWithin: 300}}, Bands: map[string]risk.Band{"account": {Medium: 20, High: 60}}}
	if err := ok.Validate("app.payment", cat); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		ns   check.Namespace
		code string
	}{
		{"Payment", check.Namespace{}, "invalid_namespace"},
		{"app.payment", check.Namespace{Requirements: check.Requirements{"app.doc:read": {AuthWithin: 300}}}, "invalid_requirement"},
		{"app.payment", check.Namespace{Requirements: check.Requirements{"app.payment": {AuthWithin: 300}}}, "invalid_requirement"},
		{"app.payment", check.Namespace{Requirements: check.Requirements{"app.payment:send": {}}}, "invalid_condition"},
		{"app.payment", check.Namespace{Requirements: check.Requirements{"app.payment:send": {RiskBelow: &check.RiskScore{Type: "device", Score: 10}}}}, "invalid_condition"},
		{"app.payment", check.Namespace{Bands: map[string]risk.Band{"device": {Medium: 10, High: 20}}}, "invalid_band"},
		{"app.payment", check.Namespace{Bands: map[string]risk.Band{"account": {Medium: 40, High: 60}}}, "invalid_band"},
		{"app.payment", check.Namespace{Bands: map[string]risk.Band{"account": {Medium: 20, High: 20}}}, "invalid_band"},
	} {
		if err := c.ns.Validate(c.name, cat); errs.KindOf(err) != errs.KindInvalid || !errors.Is(err, errs.WithCode(errs.KindInvalid, c.code, "")) {
			t.Errorf("%s %+v: %v, want %s", c.name, c.ns, err, c.code)
		}
	}
}

// step-up の手がかり（ADR 0093）：満たさなかった aal_at_least と auth_within から、求める AAL と経過の上限を返す。
func TestStepUp(t *testing.T) {
	e := newEnv(t, nil)
	now := e.clk.Now()
	e.tx(func(ctx context.Context, tx port.Tx) error {
		return tx.ActionNamespaces().Put(ctx, port.ActionNamespace{RealmID: realm, Name: "app.payment", CreatedAt: now, UpdatedAt: now,
			Settings: []byte(`{"requirements":{"app.payment:*":{"auth_within":600},"app.payment:send":{"all":[{"aal_at_least":2},{"auth_within":300}]}}}`)})
	})
	payer := e.role("", "app.payment:send", "app.payment:read")
	e.bind(payer.ID, alice, "", "", "")
	approver := e.role("", "app.payment:approve")
	e.bindIf(approver.ID, alice, `{"any":[{"aal_at_least":3},{"amr_has":["sc"]}]}`)

	pwd := &check.AuthContext{AMR: []string{"pwd"}, Factors: 1, AuthTime: now.Add(-time.Hour), Attested: true}
	mfa := &check.AuthContext{AMR: []string{"pwd", "otp", "mfa"}, Factors: 2, AuthTime: now, Attested: true}
	for _, c := range []struct {
		name string
		r    check.Request
		want check.Decision
	}{
		{"weak and old", check.Request{Principal: alice, Action: "app.payment:send", Context: pwd},
			check.Decision{Unmet: []string{"condition.aal", "condition.auth_age"}, StepUp: check.StepUp{AAL: 2, MaxAge: 300}}},
		{"strong", check.Request{Principal: alice, Action: "app.payment:send", Context: mfa}, check.Decision{Allow: true}},
		{"other action", check.Request{Principal: alice, Action: "app.payment:read", Context: pwd},
			check.Decision{Unmet: []string{"condition.auth_age"}, StepUp: check.StepUp{MaxAge: 600}}},
		// 付与の条件の any は、満たさなかった子をすべて集める（amr_has は手がかりにならない）。
		{"grant condition", check.Request{Principal: alice, Action: "app.payment:approve", Context: mfa},
			check.Decision{Unmet: []string{"condition.aal", "condition.amr"}, StepUp: check.StepUp{AAL: 3}}},
	} {
		if got := e.decide(c.r); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Decide = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// スコープで絞った文脈（本人の Personal Access Token。ADR 0109）は、付与で許す操作のうちスコープの内のものだけを許す。
// スコープは付与を広げない。Holds もスコープの外の権限は持たないとみなす。
func TestScopedContext(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "app.project:read", "app.project:write", "app.doc:*")
	e.bind(r.ID, alice, "", "", "")
	scoped := func(scopes ...string) *check.AuthContext {
		return &check.AuthContext{AMR: []string{"pat"}, Factors: 1, AuthTime: e.clk.Now(), Attested: true, Scoped: true, Scopes: scopes}
	}
	e.check(true, check.Request{Principal: alice, Action: "app.project:read", Context: scoped("app.project:read")})
	e.check(false, check.Request{Principal: alice, Action: "app.project:write", Context: scoped("app.project:read")})
	e.check(true, check.Request{Principal: alice, Action: "app.doc:write", Context: scoped("app.doc:*")})
	e.check(true, check.Request{Principal: alice, Action: "app.project:write", Context: scoped("app.project:*")})
	// 本人が持たない権限はスコープにあっても許さない。
	e.check(false, check.Request{Principal: alice, Action: "app.billing:read", Context: scoped("app.billing:read")})
	// 空のスコープは何も許さない（Scoped なら fail-closed）。
	e.check(false, check.Request{Principal: alice, Action: "app.project:read", Context: scoped()})
	// 絞っていない文脈は今までどおり。
	e.check(true, check.Request{Principal: alice, Action: "app.project:write", Context: &check.AuthContext{AMR: []string{"pwd"}}})

	e.tx(func(ctx context.Context, tx port.Tx) error {
		for _, c := range []struct {
			perms []string
			ac    *check.AuthContext
			want  bool
		}{
			{[]string{"app.project:read"}, scoped("app.project:read"), true},
			{[]string{"app.project:read", "app.project:write"}, scoped("app.project:read"), false},
			{[]string{"app.doc:*"}, scoped("app.doc:read"), false},
			{[]string{"app.doc:*"}, scoped("app.doc:*"), true},
			{[]string{"app.project:read", "app.project:write"}, nil, true},
		} {
			got, err := e.c.Holds(ctx, tx, realm, alice, "", c.perms, c.ac)
			if err != nil {
				return err
			}
			if got != c.want {
				t.Errorf("Holds(%v, %+v) = %v, want %v", c.perms, c.ac, got, c.want)
			}
		}
		return nil
	})
}

// TestDecideMany は、一括の判定が 1 件ずつの Decide と同じ結果を同じ順で返すこと（リソースを限った付与と Org を含む）。
func TestDecideMany(t *testing.T) {
	e := newEnv(t, members{"u_alice": {"org_a": port.OrgMember}})
	reader := e.role("", "app.doc:read")
	writer := e.role("", "app.doc:write")
	e.bind(reader.ID, alice, "", "", "")
	e.bind(writer.ID, alice, "", "doc", "d1")
	items := []check.Item{
		{Action: "app.doc:read"},
		{Action: "app.doc:write", Resource: check.Resource{Type: "doc", ID: "d1"}},
		{Action: "app.doc:write", Resource: check.Resource{Type: "doc", ID: "d2"}},
		{Action: "app.doc:delete"},
	}
	for _, orgID := range []string{"", "org_a"} {
		base := check.Request{Principal: alice, OrgID: orgID}
		got, err := e.c.DecideMany(context.Background(), realm, base, items)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(items) {
			t.Fatalf("len = %d", len(got))
		}
		for i, it := range items {
			r := base
			r.Action, r.Resource = it.Action, it.Resource
			want, err := e.c.Decide(context.Background(), realm, r)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got[i], want) {
				t.Errorf("org %q item %d: got %+v, want %+v", orgID, i, got[i], want)
			}
		}
		if !got[0].Allow || !got[1].Allow || got[2].Allow || got[3].Allow {
			t.Errorf("org %q: %+v", orgID, got)
		}
	}
	if got, err := e.c.DecideMany(context.Background(), realm, check.Request{Principal: alice}, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
