package check_test

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
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
	r := e.role("", "project:read", "doc:*")
	e.bind(r.ID, robot, "", "", "")

	e.check(true, check.Request{Principal: alice, Action: role.PermOrgsRead})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgsUpdate})
	e.check(false, check.Request{Principal: alice})
	e.check(true, check.Request{Principal: robot, Action: "project:read"})
	e.check(true, check.Request{Principal: robot, Action: "doc:write"})
	e.check(false, check.Request{Principal: robot, Action: "project:write"})
	e.check(false, check.Request{Principal: bob, Action: "project:read"})
	// 組み込みの Org のロールとシステムのロール以外の、知らないロールは権限を持たない（fail-closed）。
	e.bind("no-such-role", bob, "", "", "")
	e.bind(role.OrgOwner, bob, "", "", "")
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgRead})
}

func TestResourceScope(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "project:read", "project:write")
	e.bind(r.ID, alice, "", "project", "p1")

	e.check(true, check.Request{Principal: alice, Action: "project:write", Resource: check.Resource{Type: "project", ID: "p1"}})
	e.check(false, check.Request{Principal: alice, Action: "project:write", Resource: check.Resource{Type: "project", ID: "p2"}})
	e.check(false, check.Request{Principal: alice, Action: "project:write"})
	// リソースを限った付与は Holds（範囲全体の権限）には数えない。
	e.tx(func(ctx context.Context, tx port.Tx) error {
		ok, err := e.c.Holds(ctx, tx, realm, alice, "", []string{"project:read"})
		if err != nil || ok {
			t.Errorf("Holds = %v, %v", ok, err)
		}
		return nil
	})
}

func TestOrgScope(t *testing.T) {
	m := members{alice.ID: {"o1": port.OrgAdmin}, bob.ID: {"o1": port.OrgMember}}
	e := newEnv(t, m)
	custom := e.role("o1", "project:read")
	other := e.role("o2", "project:write")
	shared := e.role("", "report:read")
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
	e.check(true, check.Request{Principal: bob, Action: "project:read", OrgID: "o1"})
	e.check(true, check.Request{Principal: bob, Action: "report:read", OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: "project:write", OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgsRead, OrgID: "o1"})
	e.check(false, check.Request{Principal: bob, Action: "project:read"})

	// 所属が使えなくなれば Org の範囲の付与は効かない（TTL の後）。
	delete(m, bob.ID)
	e.check(true, check.Request{Principal: bob, Action: "project:read", OrgID: "o1"})
	e.clk.Advance(time.Minute)
	e.check(false, check.Request{Principal: bob, Action: "project:read", OrgID: "o1"})
}

func TestOrgOff(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "project:read")
	e.bind(r.ID, alice, "o1", "", "")
	e.bind(role.RealmSupport, alice, "", "", "")
	// Org がオフなら、Org の範囲の付与と org_role は効かず、realm の範囲で判定する。
	e.check(false, check.Request{Principal: alice, Action: "project:read", OrgID: "o1"})
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgsRead, OrgID: "o1"})
}

func TestGroups(t *testing.T) {
	m := members{alice.ID: {"o1": port.OrgMember}, robot.ID: {"o1": port.OrgMember}}
	e := newEnv(t, m)
	r := e.role("", "project:read")
	g := e.group("", alice, robot)
	e.bind(r.ID, check.Principal{Type: port.PrincipalGroup, ID: g.ID}, "", "", "")
	og := e.group("o1", alice, bob)
	w := e.role("o1", "project:write")
	e.bind(w.ID, check.Principal{Type: port.PrincipalGroup, ID: og.ID}, "o1", "", "")

	e.check(true, check.Request{Principal: alice, Action: "project:read"})
	e.check(true, check.Request{Principal: robot, Action: "project:read"})
	e.check(false, check.Request{Principal: bob, Action: "project:read"})
	e.check(true, check.Request{Principal: alice, Action: "project:write", OrgID: "o1"})
	// Org の Group は、その Org の使える所属を持つ間だけ効く。
	e.check(false, check.Request{Principal: bob, Action: "project:write", OrgID: "o1"})
	e.check(false, check.Request{Principal: alice, Action: "project:write"})
}

func TestCacheInvalidate(t *testing.T) {
	e := newEnv(t, nil)
	r := e.role("", "project:read")
	e.check(false, check.Request{Principal: alice, Action: "project:read"})
	b := e.bind(r.ID, alice, "", "", "")
	// キャッシュの間は古い判定。Invalidate ですぐに反映する。
	e.check(false, check.Request{Principal: alice, Action: "project:read"})
	e.c.Invalidate(realm)
	e.check(true, check.Request{Principal: alice, Action: "project:read"})
	e.tx(func(ctx context.Context, tx port.Tx) error { return tx.RoleBindings().Delete(ctx, realm, b.ID) })
	e.check(true, check.Request{Principal: alice, Action: "project:read"})
	// TTL を過ぎれば反映する。
	e.clk.Advance(time.Minute)
	e.check(false, check.Request{Principal: alice, Action: "project:read"})
	// CheckTx はキャッシュを使わない。
	e.bind(r.ID, alice, "", "", "")
	e.tx(func(ctx context.Context, tx port.Tx) error {
		ok, err := e.c.CheckTx(ctx, tx, realm, check.Request{Principal: alice, Action: "project:read"})
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
	for p, ok := range map[string]bool{"project:read": true, "project:*": true, "Project:read": false, "project": false, "project:": false, ":read": false, "a:b:c": false} {
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
	r := e.role("o_mid", "doc:write")
	e.bind(r.ID, bob, "o_mid", "", "")

	// 根の admin は子孫で admin の権限を持つ。関係の無い Org では持たない。
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	e.check(true, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_mid"})
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_other"})
	// 中間の Org の付与は子に効き、親には効かない。
	e.check(true, check.Request{Principal: bob, Action: "doc:write", OrgID: "o_leaf"})
	e.check(false, check.Request{Principal: bob, Action: "doc:write", OrgID: "o_root"})
	e.check(false, check.Request{Principal: bob, Action: role.PermOrgInvite, OrgID: "o_leaf"})

	// 子の Org が使えなければ、祖先からは効かない。
	m[unusable] = map[string]port.OrgRole{"o_leaf": ""}
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	e.check(false, check.Request{Principal: bob, Action: "doc:write", OrgID: "o_leaf"})
	delete(m, unusable)
	// 祖先の所属が使えなければ効かない。
	delete(m[alice.ID], "o_root")
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: alice, Action: role.PermOrgInvite, OrgID: "o_leaf"})
	// 階層がオフなら祖先の付与は効かない。
	e.c.Hierarchy = false
	e.c.Invalidate(realm)
	e.check(false, check.Request{Principal: bob, Action: "doc:write", OrgID: "o_leaf"})
	e.check(true, check.Request{Principal: bob, Action: "doc:write", OrgID: "o_mid"})
}
