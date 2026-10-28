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
		got, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, u)
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
		if none, err := tx.RoleBindings().ListEffective(ctx, r, port.PrincipalUser, id.New(id.User)); err != nil || len(none) != 0 {
			return fmt.Errorf("ListEffective(stranger) = %+v, %v", none, err)
		}
		return nil
	})
}
