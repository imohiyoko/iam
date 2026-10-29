package manage_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

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
	t *testing.T
	k *testkit.Kit
	s *manage.Service
}

func newEnv(t *testing.T, m members) *env {
	k := testkit.New(t)
	c := &check.Checker{Storage: k.Storage, Clock: k.Clock, Members: m}
	return &env{t: t, k: k, s: &manage.Service{Checker: c, Clock: k.Clock}}
}

func user(id string) check.Principal { return check.Principal{Type: port.PrincipalUser, ID: id} }

func actor(id string) manage.Actor {
	return manage.Actor{Principal: user(id), Audit: audit.Actor{Type: "user", ID: "pub_" + id}}
}

func target(id string) manage.Target {
	return manage.Target{Principal: user(id), PublicID: "pub_" + id}
}

func (e *env) realm() manage.Scope { return manage.Scope{RealmID: e.k.RealmID} }

func (e *env) org(id string) manage.Scope {
	return manage.Scope{RealmID: e.k.RealmID, OrgID: id, OrgPublicID: "org_" + id}
}

// run は fn を1つのトランザクションで実行し、その誤りを返す。
func (e *env) run(fn func(ctx context.Context, tx port.Tx) error) error {
	return e.k.Storage.Tx(context.Background(), fn)
}

func (e *env) grant(name, uid string) {
	e.k.Tx(e.t, func(ctx context.Context, tx port.Tx) error {
		// 最後の realm:owner の判定はユーザーが使えるかを見るので、ユーザーも作る。
		if _, err := tx.Users().Get(ctx, e.k.RealmID, uid); errors.Is(err, errs.NotFound) {
			now := e.k.Clock.Now()
			if err := tx.Users().Create(ctx, port.User{ID: uid, PublicID: "pub_" + uid, RealmID: e.k.RealmID, Status: port.UserActive, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
		return role.Grant(ctx, tx, e.k.RealmID, name, port.PrincipalUser, uid, e.k.Clock.Now())
	})
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *errs.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

func TestRealmRolesAndEscalation(t *testing.T) {
	e := newEnv(t, nil)
	e.grant(role.RealmOwner, "owner")
	e.grant(role.RealmAdmin, "admin")

	var r port.Role
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		var err error
		r, err = e.s.CreateRole(ctx, tx, e.realm(), actor("owner"), " Auditor ", []string{"users:update", "users:update", "orgs:read"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r.Name != "Auditor" || len(r.Permissions) != 2 {
		t.Fatalf("role = %+v", r)
	}
	// 管理の権限が無ければ作れない。名前空間と権限の形を確かめる。
	err := e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, e.realm(), actor("admin"), "x", []string{"orgs:read"})
		return err
	})
	wantCode(t, err, errs.CodePermissionDenied)
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, e.realm(), actor("owner"), "realm:fake", nil)
		return err
	})
	wantCode(t, err, "invalid_name")
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, e.realm(), actor("owner"), "bad", []string{"Users:Read"})
		return err
	})
	wantCode(t, err, "invalid_permission")
	// 連携先の権限は自由に渡せる。IAM 自身の権限は、持たなければ渡せない（owner も users:* は持たない）。
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, e.realm(), actor("owner"), "app", []string{"project:read"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, e.realm(), actor("owner"), "users-all", []string{"users:*"})
		return err
	})
	wantCode(t, err, errs.CodePermissionDenied)

	// owner は admin に Auditor を付与できる。
	var b port.RoleBinding
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		var err error
		b, err = e.s.Bind(ctx, tx, e.realm(), actor("owner"), r.PublicID, target("admin"), check.Resource{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if b.Role != r.ID || b.PublicID == "" {
		t.Fatalf("binding = %+v", b)
	}
	// 組み込みの Org・システムのロールは付与できない。
	for _, ref := range []string{role.OrgOwner, role.NotificationDelivery, "rol_none"} {
		err = e.run(func(ctx context.Context, tx port.Tx) error {
			_, err := e.s.Bind(ctx, tx, e.realm(), actor("owner"), ref, target("admin"), check.Resource{})
			return err
		})
		wantCode(t, err, "unknown_role")
	}
	// ロールを消すと付与も消える。
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.DeleteRole(ctx, tx, e.realm(), actor("owner"), r)
	}); err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if _, err := tx.RoleBindings().GetByPublicID(ctx, e.k.RealmID, b.PublicID); !errors.Is(err, errs.NotFound) {
			t.Errorf("binding after role delete: %v", err)
		}
		recs, err := tx.Audit().ListByRealm(ctx, e.k.RealmID, 0, 100)
		if err != nil {
			return err
		}
		types := map[string]bool{}
		for _, rec := range recs {
			var ev audit.Event
			if err := json.Unmarshal(rec.Payload, &ev); err != nil {
				return err
			}
			types[ev.Type] = true
		}
		for _, typ := range []string{"role.created", "role.granted", "role.deleted"} {
			if !types[typ] {
				t.Errorf("audit missing %s: %v", typ, types)
			}
		}
		return nil
	})
}

func TestLastOwner(t *testing.T) {
	e := newEnv(t, nil)
	e.grant(role.RealmOwner, "owner")
	var b port.RoleBinding
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		bs, err := tx.RoleBindings().ListByPrincipal(ctx, e.k.RealmID, port.PrincipalUser, "owner")
		b = bs[0]
		return err
	})
	err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.Unbind(ctx, tx, e.realm(), actor("owner"), b, "pub_owner")
	})
	wantCode(t, err, "last_owner")
	// 有効期間の外と停止中の owner は使えないので数えない。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		now := e.k.Clock.Now()
		past := now.Add(-time.Hour)
		if err := tx.Users().Create(ctx, port.User{ID: "expired", PublicID: "pub_expired", RealmID: e.k.RealmID, Status: port.UserActive,
			ValidUntil: &past, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, port.User{ID: "stopped", PublicID: "pub_stopped", RealmID: e.k.RealmID, Status: port.UserActive,
			CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		return tx.Suspensions().Create(ctx, port.Suspension{ID: "sp1", PublicID: "sus_1", RealmID: e.k.RealmID, TargetType: port.SuspensionTargetUser,
			TargetID: "stopped", Category: "tos_violation", StartsAt: past, CreatedBy: "pub_owner", CreatedAt: now})
	})
	e.grant(role.RealmOwner, "expired")
	e.grant(role.RealmOwner, "stopped")
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.Unbind(ctx, tx, e.realm(), actor("owner"), b, "pub_owner")
	})
	wantCode(t, err, "last_owner")
	e.grant(role.RealmOwner, "owner2")
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.Unbind(ctx, tx, e.realm(), actor("owner2"), b, "pub_owner")
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOrgScope(t *testing.T) {
	m := members{"alice": {"o1": port.OrgAdmin}, "bob": {"o1": port.OrgMember}, "carol": {"o2": port.OrgOwner}}
	e := newEnv(t, m)
	sc := e.org("o1")

	// Org の範囲では realm の管理の権限は使えない。org_role の権限は渡せる。
	err := e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, sc, actor("alice"), "ops", []string{"users:update"})
		return err
	})
	wantCode(t, err, "invalid_permission")
	// org:admin が持たない権限（org:delete）は渡せない。
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.CreateRole(ctx, tx, sc, actor("alice"), "deleter", []string{role.PermOrgDelete})
		return err
	})
	wantCode(t, err, errs.CodePermissionDenied)
	var inviter port.Role
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		var err error
		inviter, err = e.s.CreateRole(ctx, tx, sc, actor("alice"), "inviter", []string{role.PermOrgInvite})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// 所属の無い主体には付与できない。member は管理できない。別の Org のオーナーも。
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.Bind(ctx, tx, sc, actor("alice"), inviter.PublicID, target("carol"), check.Resource{})
		return err
	})
	wantCode(t, err, "not_member")
	for _, who := range []string{"bob", "carol"} {
		err = e.run(func(ctx context.Context, tx port.Tx) error {
			_, err := e.s.Bind(ctx, tx, sc, actor(who), inviter.PublicID, target("bob"), check.Resource{})
			return err
		})
		wantCode(t, err, errs.CodePermissionDenied)
	}
	// 運営者ロールは Org の範囲で付与できない。別の Org のロールも。
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.Bind(ctx, tx, sc, actor("alice"), role.RealmAdmin, target("bob"), check.Resource{})
		return err
	})
	wantCode(t, err, "unknown_role")
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.Bind(ctx, tx, e.org("o2"), actor("carol"), inviter.PublicID, target("carol"), check.Resource{})
		return err
	})
	wantCode(t, err, "unknown_role")

	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.Bind(ctx, tx, sc, actor("alice"), inviter.PublicID, target("bob"), check.Resource{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ok, err := e.s.Checker.Check(context.Background(), e.k.RealmID, check.Request{Principal: user("bob"), Action: role.PermOrgInvite, OrgID: "o1"})
	if err != nil || !ok {
		t.Fatalf("bob invite after bind = %v, %v", ok, err)
	}
}

func TestGroups(t *testing.T) {
	m := members{"alice": {"o1": port.OrgAdmin}, "bob": {"o1": port.OrgMember}}
	e := newEnv(t, m)
	e.grant(role.RealmOwner, "owner")
	e.grant(role.RealmAdmin, "admin")
	sc := e.org("o1")

	var g port.Group
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		var err error
		g, err = e.s.CreateGroup(ctx, tx, sc, actor("alice"), "Team")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gp := manage.Target{Principal: check.Principal{Type: port.PrincipalGroup, ID: g.ID}, PublicID: g.PublicID}
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		_, err := e.s.Bind(ctx, tx, sc, actor("alice"), role.RealmAdmin, gp, check.Resource{})
		return err
	}); err == nil {
		t.Fatal("operator role bound to org group")
	}
	// Org の Group には、所属の無い主体を入れられない。
	err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.AddMember(ctx, tx, sc, actor("alice"), g, target("zed"))
	})
	wantCode(t, err, "not_member")
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.AddMember(ctx, tx, sc, actor("alice"), g, target("bob"))
	}); err != nil {
		t.Fatal(err)
	}
	// Org の Group は realm の範囲からは見えない（別の範囲は無いものとして扱う）。
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.DeleteGroup(ctx, tx, e.realm(), actor("owner"), g)
	})
	if !errors.Is(err, errs.NotFound) {
		t.Fatalf("delete from realm scope: %v", err)
	}

	// realm の Group：owner のロールを付与した Group には、admin は人を入れられない（権限の引き上げ）。
	var rg port.Group
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		var err error
		if rg, err = e.s.CreateGroup(ctx, tx, e.realm(), actor("admin"), "Owners"); err != nil {
			return err
		}
		_, err = e.s.Bind(ctx, tx, e.realm(), actor("owner"), role.RealmOwner,
			manage.Target{Principal: check.Principal{Type: port.PrincipalGroup, ID: rg.ID}, PublicID: rg.PublicID}, check.Resource{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Org の範囲からは realm の Group に付与できない。
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		inviter, err := e.s.CreateRole(ctx, tx, sc, actor("alice"), "inviter", []string{role.PermOrgInvite})
		if err != nil {
			return err
		}
		_, err = e.s.Bind(ctx, tx, sc, actor("alice"), inviter.PublicID,
			manage.Target{Principal: check.Principal{Type: port.PrincipalGroup, ID: rg.ID}, PublicID: rg.PublicID}, check.Resource{})
		return err
	})
	wantCode(t, err, "invalid_principal")
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.AddMember(ctx, tx, e.realm(), actor("admin"), rg, target("admin"))
	})
	wantCode(t, err, errs.CodePermissionDenied)
	err = e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.DeleteGroup(ctx, tx, e.realm(), actor("admin"), rg)
	})
	wantCode(t, err, errs.CodePermissionDenied)
	if err := e.run(func(ctx context.Context, tx port.Tx) error {
		return e.s.DeleteGroup(ctx, tx, e.realm(), actor("owner"), rg)
	}); err != nil {
		t.Fatal(err)
	}
}
