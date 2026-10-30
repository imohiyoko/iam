package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可側の契約（design.md 3.2、ADR 0064）。

func newBinding(r, role string, t port.PrincipalType, principal, org string, at time.Time) port.RoleBinding {
	return port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: r, Role: role,
		PrincipalType: t, PrincipalID: principal, OrgID: org, CreatedAt: at}
}

func testRoleBindings(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, org := id.New(id.Realm), id.New(id.User), id.New(id.Org)
	b := newBinding(r, "realm:owner", port.PrincipalUser, u, "", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.RoleBindings()
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		dup := b
		dup.ID, dup.PublicID = id.New(id.RoleBinding), id.NewExternal(id.RoleBinding)
		if err := conflict("same binding", repo.Create(ctx, dup)); err != nil {
			return err
		}
		samePublic := newBinding(r, "realm:admin", port.PrincipalUser, u, "", T0)
		samePublic.PublicID = b.PublicID
		if err := conflict("same public id", repo.Create(ctx, samePublic)); err != nil {
			return err
		}
		// 範囲（Org・リソース）が違えば別の付与。
		inOrg := newBinding(r, "realm:owner", port.PrincipalUser, u, org, T0.Add(time.Minute))
		onResource := inOrg
		onResource.ID, onResource.PublicID, onResource.ResourceType, onResource.ResourceID = id.New(id.RoleBinding), id.NewExternal(id.RoleBinding), "project", "p1"
		onResource.CreatedAt = T0.Add(2 * time.Minute)
		onResource.Condition = []byte(`{"amr_has":["hwk"]}`)
		for _, x := range []port.RoleBinding{inOrg, onResource} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		list, err := repo.ListByPrincipal(ctx, r, port.PrincipalUser, u)
		if err != nil || len(list) != 3 || !reflect.DeepEqual(list[0], b) || !reflect.DeepEqual(list[2], onResource) {
			return fmt.Errorf("ListByPrincipal = %+v, %v", list, err)
		}
		if list, err = repo.ListByRole(ctx, r, "realm:owner"); err != nil || len(list) != 3 {
			return fmt.Errorf("ListByRole = %+v, %v", list, err)
		}
		if list, err = repo.ListConditional(ctx, r); err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], onResource) {
			return fmt.Errorf("ListConditional = %+v, %v", list, err)
		}
		if list, err = repo.ListByOrg(ctx, r, org); err != nil || len(list) != 2 || list[0].ID != inOrg.ID {
			return fmt.Errorf("ListByOrg = %+v, %v", list, err)
		}
		if list, err = repo.ListByOrg(ctx, r, ""); err != nil || len(list) != 1 || list[0].ID != b.ID {
			return fmt.Errorf("ListByOrg(realm) = %+v, %v", list, err)
		}
		if got, err := repo.GetByPublicID(ctx, r, onResource.PublicID); err != nil || !reflect.DeepEqual(got, onResource) {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		if err := notFound("get in another realm", second(repo.GetByPublicID(ctx, id.New(id.Realm), b.PublicID))); err != nil {
			return err
		}
		if err := notFound("delete in another realm", repo.Delete(ctx, id.New(id.Realm), b.ID)); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, b.ID); err != nil {
			return err
		}
		if err := notFound("deleted", second(repo.GetByPublicID(ctx, r, b.PublicID))); err != nil {
			return err
		}
		return notFound("delete twice", repo.Delete(ctx, r, b.ID))
	})
}

func testRoles(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, org := id.New(id.Realm), id.New(id.Org)
	mk := func(name, orgID string) port.Role {
		return port.Role{ID: id.New(id.Role), PublicID: id.NewExternal(id.Role), RealmID: r, OrgID: orgID, Name: name,
			Permissions: []string{"project:read", "project:write"}, CreatedAt: T0, UpdatedAt: T0}
	}
	editor, viewer, orgEditor := mk("editor", ""), mk("viewer", ""), mk("editor", org)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Roles()
		for _, x := range []port.Role{viewer, editor, orgEditor} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("same name", repo.Create(ctx, mk("editor", ""))); err != nil {
			return err
		}
		got, err := repo.Get(ctx, r, editor.ID)
		if err != nil || !reflect.DeepEqual(got, editor) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if got, err = repo.GetByPublicID(ctx, r, orgEditor.PublicID); err != nil || got.ID != orgEditor.ID {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		list, err := repo.ListByOrg(ctx, r, "")
		if err != nil || len(list) != 2 || list[0].Name != "editor" || list[1].Name != "viewer" {
			return fmt.Errorf("ListByOrg(realm) = %+v, %v", list, err)
		}
		if list, err = repo.ListByOrg(ctx, r, org); err != nil || len(list) != 1 {
			return fmt.Errorf("ListByOrg = %+v, %v", list, err)
		}
		// 権限の並びは保存した順。空にもできる。
		editor.Name, editor.Permissions, editor.UpdatedAt = "writer", []string{"project:write", "doc:read"}, T0.Add(time.Hour)
		if err := repo.Update(ctx, editor); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, editor.ID); !slices.Equal(got.Permissions, editor.Permissions) || got.Name != "writer" || !got.UpdatedAt.Equal(editor.UpdatedAt) {
			return fmt.Errorf("after Update = %+v", got)
		}
		viewer.Name = "writer"
		if err := conflict("rename to an existing name", repo.Update(ctx, viewer)); err != nil {
			return err
		}
		viewer.Name, viewer.Permissions = "viewer", nil
		if err := repo.Update(ctx, viewer); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, viewer.ID); len(got.Permissions) != 0 {
			return fmt.Errorf("empty permissions = %+v", got.Permissions)
		}
		other := editor
		other.RealmID = id.New(id.Realm)
		if err := notFound("update in another realm", repo.Update(ctx, other)); err != nil {
			return err
		}
		if err := notFound("get in another realm", second(repo.Get(ctx, other.RealmID, editor.ID))); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, editor.ID); err != nil {
			return err
		}
		return notFound("delete twice", repo.Delete(ctx, r, editor.ID))
	})
}

func testGroups(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, org := id.New(id.Realm), id.New(id.Org)
	mk := func(name, orgID string) port.Group {
		return port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, OrgID: orgID, Name: name, CreatedAt: T0, UpdatedAt: T0}
	}
	eng, ops := mk("eng", org), mk("ops", org)
	u, sa := id.New(id.User), id.New(id.ServiceAccount)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Groups()
		for _, g := range []port.Group{ops, eng, mk("eng", "")} {
			if err := repo.Create(ctx, g); err != nil {
				return err
			}
		}
		if err := conflict("same name in org", repo.Create(ctx, mk("eng", org))); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, eng.PublicID); err != nil || !reflect.DeepEqual(got, eng) {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		list, err := repo.ListByOrg(ctx, r, org)
		if err != nil || len(list) != 2 || list[0].ID != eng.ID {
			return fmt.Errorf("ListByOrg = %+v, %v", list, err)
		}
		if err := conflict("rename to an existing name", repo.Rename(ctx, r, ops.ID, "eng", T0)); err != nil {
			return err
		}
		if err := repo.Rename(ctx, r, ops.ID, "sre", T0.Add(time.Hour)); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, ops.ID); got.Name != "sre" || !got.UpdatedAt.Equal(T0.Add(time.Hour)) {
			return fmt.Errorf("after Rename = %+v", got)
		}
		members := []port.GroupMember{
			{GroupID: eng.ID, MemberType: port.PrincipalUser, MemberID: u, CreatedAt: T0},
			{GroupID: eng.ID, MemberType: port.PrincipalServiceAccount, MemberID: sa, CreatedAt: T0.Add(time.Minute)},
			{GroupID: ops.ID, MemberType: port.PrincipalUser, MemberID: u, CreatedAt: T0.Add(2 * time.Minute)},
		}
		for _, m := range members {
			if err := repo.AddMember(ctx, r, m); err != nil {
				return err
			}
		}
		if err := conflict("same member", repo.AddMember(ctx, r, members[0])); err != nil {
			return err
		}
		if err := notFound("member of a missing group", repo.AddMember(ctx, r, port.GroupMember{GroupID: id.New(id.Group), MemberType: port.PrincipalUser, MemberID: u, CreatedAt: T0})); err != nil {
			return err
		}
		if err := notFound("member in another realm", repo.AddMember(ctx, id.New(id.Realm), members[0])); err != nil {
			return err
		}
		ms, err := repo.ListMembers(ctx, r, eng.ID)
		if err != nil || !reflect.DeepEqual(ms, members[:2]) {
			return fmt.Errorf("ListMembers = %+v, %v", ms, err)
		}
		gs, err := repo.ListByMember(ctx, r, port.PrincipalUser, u)
		if err != nil || len(gs) != 2 || gs[0].ID != eng.ID || gs[1].ID != ops.ID {
			return fmt.Errorf("ListByMember = %+v, %v", gs, err)
		}
		if gs, err = repo.ListByMember(ctx, id.New(id.Realm), port.PrincipalUser, u); err != nil || len(gs) != 0 {
			return fmt.Errorf("ListByMember in another realm = %+v, %v", gs, err)
		}
		if err := repo.RemoveMember(ctx, r, eng.ID, port.PrincipalUser, u); err != nil {
			return err
		}
		if err := notFound("remove twice", repo.RemoveMember(ctx, r, eng.ID, port.PrincipalUser, u)); err != nil {
			return err
		}
		// 消した Group の所属も消える。
		if err := repo.Delete(ctx, r, ops.ID); err != nil {
			return err
		}
		if gs, err = repo.ListByMember(ctx, r, port.PrincipalUser, u); err != nil || len(gs) != 0 {
			return fmt.Errorf("after deleting the group = %+v, %v", gs, err)
		}
		if err := notFound("delete twice", repo.Delete(ctx, r, ops.ID)); err != nil {
			return err
		}
		return notFound("members of a deleted group", second(repo.ListMembers(ctx, r, ops.ID)))
	})
}

func testEffectiveBindings(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other, org := id.New(id.Realm), id.New(id.Realm), id.New(id.Org)
	u, v := id.New(id.User), id.New(id.User)
	custom := port.Role{ID: id.New(id.Role), PublicID: id.NewExternal(id.Role), RealmID: r, OrgID: org, Name: "viewer",
		Permissions: []string{"doc:read"}, CreatedAt: T0, UpdatedAt: T0}
	og := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, OrgID: org, Name: "team", CreatedAt: T0, UpdatedAt: T0}
	rg := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, Name: "all", CreatedAt: T0, UpdatedAt: T0}
	direct := newBinding(r, "realm:support", port.PrincipalUser, u, "", T0)
	direct.Condition = []byte(`{"factors_at_least":2}`)
	viaOrg := newBinding(r, custom.ID, port.PrincipalGroup, og.ID, org, T0.Add(time.Second))
	viaRealm := newBinding(r, "gone-role", port.PrincipalGroup, rg.ID, "", T0.Add(2*time.Second))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Roles().Create(ctx, custom); err != nil {
			return err
		}
		for _, g := range []port.Group{og, rg} {
			if err := tx.Groups().Create(ctx, g); err != nil {
				return err
			}
			if err := tx.Groups().AddMember(ctx, r, port.GroupMember{GroupID: g.ID, MemberType: port.PrincipalUser, MemberID: u, CreatedAt: T0}); err != nil {
				return err
			}
		}
		for _, b := range []port.RoleBinding{viaRealm, direct, viaOrg, newBinding(r, "realm:admin", port.PrincipalUser, v, "", T0),
			newBinding(other, "realm:admin", port.PrincipalUser, u, "", T0)} {
			if err := tx.RoleBindings().Create(ctx, b); err != nil {
				return err
			}
		}
		got, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, u, false)
		if err != nil {
			return err
		}
		if len(got) != 3 || got[0].ID != direct.ID || got[1].ID != viaOrg.ID || got[2].ID != viaRealm.ID {
			return fmt.Errorf("ListEffective = %+v", got)
		}
		if got[0].GroupOrgID != "" || got[0].Custom != nil || !reflect.DeepEqual(got[0].RoleBinding, direct) {
			return fmt.Errorf("direct = %+v", got[0])
		}
		if got[1].GroupOrgID != org || got[1].Custom == nil || !reflect.DeepEqual(*got[1].Custom, custom) {
			return fmt.Errorf("via org group = %+v (custom %+v)", got[1], got[1].Custom)
		}
		if got[2].GroupOrgID != "" || got[2].Custom != nil {
			return fmt.Errorf("via realm group = %+v", got[2])
		}
		if none, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, id.New(id.User), true); err != nil || len(none) != 0 {
			return fmt.Errorf("ListEffective(stranger) = %+v, %v", none, err)
		}
		return nil
	})
}

// testNestedGroups は Group のネスト（design.md 11.5）の閉包と、それを使う ListEffective。閉包の計算は呼び出し側がする。
func testNestedGroups(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, org := id.New(id.Realm), id.New(id.Org)
	mk := func(name string) port.Group {
		return port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, OrgID: org, Name: name, CreatedAt: T0, UpdatedAt: T0}
	}
	a, b, c, d := mk("all"), mk("eng"), mk("backend"), mk("other")
	u := id.New(id.User)
	member := func(g string, typ port.PrincipalType, m string) port.GroupMember {
		return port.GroupMember{GroupID: g, MemberType: typ, MemberID: m, CreatedAt: T0}
	}
	onA := newBinding(r, "realm:support", port.PrincipalGroup, a.ID, org, T0)
	onB := newBinding(r, "realm:support", port.PrincipalGroup, b.ID, org, T0.Add(time.Second))
	onC := newBinding(r, "realm:support", port.PrincipalGroup, c.ID, org, T0.Add(2*time.Second))
	onD := newBinding(r, "realm:support", port.PrincipalGroup, d.ID, org, T0.Add(3*time.Second))
	ids := func(bs []port.EffectiveBinding) []string {
		var out []string
		for _, b := range bs {
			out = append(out, b.ID)
		}
		return out
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Groups()
		for _, g := range []port.Group{a, b, c, d} {
			if err := repo.Create(ctx, g); err != nil {
				return err
			}
		}
		for _, m := range []port.GroupMember{member(a.ID, port.PrincipalGroup, b.ID), member(b.ID, port.PrincipalGroup, c.ID),
			member(c.ID, port.PrincipalUser, u)} {
			if err := repo.AddMember(ctx, r, m); err != nil {
				return err
			}
		}
		if err := repo.SetAncestors(ctx, r, c.ID, []port.GroupLink{{GroupID: a.ID, Depth: 2}, {GroupID: b.ID, Depth: 1}}); err != nil {
			return err
		}
		if err := repo.SetAncestors(ctx, r, b.ID, []port.GroupLink{{GroupID: a.ID, Depth: 1}}); err != nil {
			return err
		}
		for _, x := range []port.RoleBinding{onD, onC, onB, onA} {
			if err := tx.RoleBindings().Create(ctx, x); err != nil {
				return err
			}
		}
		if got, err := repo.Ancestors(ctx, r, c.ID); err != nil || !reflect.DeepEqual(got, []port.GroupLink{{GroupID: b.ID, Depth: 1}, {GroupID: a.ID, Depth: 2}}) {
			return fmt.Errorf("repo.Ancestors = %+v, %v", got, err)
		}
		if got, err := repo.Descendants(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, []port.GroupLink{{GroupID: b.ID, Depth: 1}, {GroupID: c.ID, Depth: 2}}) {
			return fmt.Errorf("repo.Descendants = %+v, %v", got, err)
		}
		if got, err := repo.Ancestors(ctx, id.New(id.Realm), c.ID); err != nil || len(got) != 0 {
			return fmt.Errorf("repo.Ancestors in another realm = %+v, %v", got, err)
		}
		if gs, err := repo.ListByMember(ctx, r, port.PrincipalGroup, b.ID); err != nil || len(gs) != 1 || gs[0].ID != a.ID {
			return fmt.Errorf("ListByMember(group) = %+v, %v", gs, err)
		}
		// nested でなければ直接の Group だけ。nested なら祖先の Group の付与も、その Group の Org とともに返す。
		if got, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, u, false); err != nil || !slices.Equal(ids(got), []string{onC.ID}) {
			return fmt.Errorf("ListEffective(not nested) = %+v, %v", got, err)
		}
		got, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, u, true)
		if err != nil || !slices.Equal(ids(got), []string{onA.ID, onB.ID, onC.ID}) || got[0].GroupOrgID != org {
			return fmt.Errorf("ListEffective(nested) = %+v, %v", got, err)
		}
		if got, err := tx.RoleBindings().ListEffective(ctx, id.New(id.Realm), port.PrincipalUser, u, true); err != nil || len(got) != 0 {
			return fmt.Errorf("ListEffective in another realm = %+v, %v", got, err)
		}
		// SetAncestors は置き換える。
		if err := repo.SetAncestors(ctx, r, c.ID, []port.GroupLink{{GroupID: b.ID, Depth: 1}}); err != nil {
			return err
		}
		if got, err := repo.Ancestors(ctx, r, c.ID); err != nil || !reflect.DeepEqual(got, []port.GroupLink{{GroupID: b.ID, Depth: 1}}) {
			return fmt.Errorf("repo.Ancestors after replace = %+v, %v", got, err)
		}
		// 2 つの所属と 2 つの閉包の行。片付けは閉包の行から。
		if n, err := repo.CountNested(ctx); err != nil || n != 4 {
			return fmt.Errorf("CountNested = %d, %v", n, err)
		}
		if n, err := repo.PurgeNested(ctx, 3); err != nil || n != 3 {
			return fmt.Errorf("PurgeNested(3) = %d, %v", n, err)
		}
		if got, err := repo.Ancestors(ctx, r, c.ID); err != nil || len(got) != 0 {
			return fmt.Errorf("repo.Ancestors after purge = %+v, %v", got, err)
		}
		if n, err := repo.PurgeNested(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("PurgeNested(10) = %d, %v", n, err)
		}
		if n, err := repo.CountNested(ctx); err != nil || n != 0 {
			return fmt.Errorf("CountNested after purge = %d, %v", n, err)
		}
		if gs, err := repo.ListByMember(ctx, r, port.PrincipalUser, u); err != nil || len(gs) != 1 {
			return fmt.Errorf("user membership after purge = %+v, %v", gs, err)
		}
		// Group を消すと、Group としての所属と閉包の行も消える。
		if err := repo.AddMember(ctx, r, member(a.ID, port.PrincipalGroup, b.ID)); err != nil {
			return err
		}
		if err := repo.AddMember(ctx, r, member(b.ID, port.PrincipalGroup, c.ID)); err != nil {
			return err
		}
		if err := repo.SetAncestors(ctx, r, b.ID, []port.GroupLink{{GroupID: a.ID, Depth: 1}}); err != nil {
			return err
		}
		if err := repo.SetAncestors(ctx, r, c.ID, []port.GroupLink{{GroupID: b.ID, Depth: 1}, {GroupID: a.ID, Depth: 2}}); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, b.ID); err != nil {
			return err
		}
		if gs, err := repo.ListByMember(ctx, r, port.PrincipalGroup, b.ID); err != nil || len(gs) != 0 {
			return fmt.Errorf("memberships of a deleted group = %+v, %v", gs, err)
		}
		if got, err := repo.Ancestors(ctx, r, c.ID); err != nil || !reflect.DeepEqual(got, []port.GroupLink{{GroupID: a.ID, Depth: 2}}) {
			return fmt.Errorf("repo.Ancestors after deleting the middle = %+v, %v", got, err)
		}
		if got, err := repo.Descendants(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, []port.GroupLink{{GroupID: c.ID, Depth: 2}}) {
			return fmt.Errorf("repo.Descendants after deleting the middle = %+v, %v", got, err)
		}
		return nil
	})
}

// testRiskTypes は realm のリスクの種類の一覧（ADR 0084）。
func testRiskTypes(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	ip := port.RiskType{RealmID: r, Name: "ip", Enabled: false, BandMedium: 30, BandHigh: 70, CreatedAt: T0, UpdatedAt: T0}
	fraud := port.RiskType{RealmID: r, Name: "payment.fraud", Enabled: true, BandMedium: 20, BandHigh: 50, CreatedAt: T0, UpdatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.RiskTypes()
		for _, x := range []port.RiskType{fraud, ip, {RealmID: other, Name: "ip", Enabled: true, BandMedium: 1, BandHigh: 2, CreatedAt: T0, UpdatedAt: T0}} {
			if err := repo.Put(ctx, x); err != nil {
				return err
			}
		}
		// 置き直しは作成時刻を保つ。
		upd := fraud
		upd.Enabled, upd.BandMedium, upd.BandHigh, upd.CreatedAt, upd.UpdatedAt = false, 10, 40, T0.Add(time.Hour), T0.Add(time.Hour)
		if err := repo.Put(ctx, upd); err != nil {
			return err
		}
		got, err := repo.List(ctx, r)
		want := upd
		want.CreatedAt = T0
		if err != nil || !reflect.DeepEqual(got, []port.RiskType{ip, want}) {
			return fmt.Errorf("riskTypes.List = %+v, %v", got, err)
		}
		if got, err := repo.List(ctx, id.New(id.Realm)); err != nil || len(got) != 0 {
			return fmt.Errorf("riskTypes.List of another realm = %+v, %v", got, err)
		}
		return nil
	})
}

// testActionNamespaces は realm の操作の名前空間ごとの設定（ADR 0084）。
func testActionNamespaces(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	pay := port.ActionNamespace{RealmID: r, Name: "payment", Settings: []byte(`{"requirements":{"payment:send":{"auth_within":300}}}`), CreatedAt: T0, UpdatedAt: T0}
	orgs := port.ActionNamespace{RealmID: r, Name: "orgs", Settings: []byte(`{}`), CreatedAt: T0, UpdatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.ActionNamespaces()
		if _, err := repo.Get(ctx, r, "payment"); notFound("actionNamespaces.Get before Put", err) != nil {
			return notFound("actionNamespaces.Get before Put", err)
		}
		for _, x := range []port.ActionNamespace{pay, orgs, {RealmID: other, Name: "payment", Settings: []byte(`{}`), CreatedAt: T0, UpdatedAt: T0}} {
			if err := repo.Put(ctx, x); err != nil {
				return err
			}
		}
		// 置き直しは作成時刻を保つ。
		upd := pay
		upd.Settings, upd.CreatedAt, upd.UpdatedAt = []byte(`{"bands":{"account":{"medium":10,"high":40}}}`), T0.Add(time.Hour), T0.Add(time.Hour)
		if err := repo.Put(ctx, upd); err != nil {
			return err
		}
		want := upd
		want.CreatedAt = T0
		if got, err := repo.Get(ctx, r, "payment"); err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("actionNamespaces.Get = %+v, %v", got, err)
		}
		if got, err := repo.List(ctx, r); err != nil || !reflect.DeepEqual(got, []port.ActionNamespace{orgs, want}) {
			return fmt.Errorf("actionNamespaces.List = %+v, %v", got, err)
		}
		if got, err := repo.List(ctx, id.New(id.Realm)); err != nil || len(got) != 0 {
			return fmt.Errorf("actionNamespaces.List of another realm = %+v, %v", got, err)
		}
		return nil
	})
}
