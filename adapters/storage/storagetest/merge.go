package storagetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウント統合（design.md 11.6、ADR 0082）の保存。

func testAccountMerge(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	a, b := newUser(r), newUser(r)
	other := newCredential(r, a.ID, "passkey", []byte("cred-a"))
	personal := newOrg(r, port.OrgPersonal, b.ID)
	groupID := id.NewExternal(id.Group)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, u := range []port.User{a, b} {
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
		}
		if err := tx.Credentials().Create(ctx, other); err != nil {
			return err
		}
		if err := tx.Orgs().Create(ctx, personal); err != nil {
			return err
		}
		// ユーザー：active なユーザーだけを統合済みにする。
		at := T0.Add(1)
		if err := tx.Users().SetMerged(ctx, r, b.ID, a.ID, at); err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, r, b.ID)
		if err != nil || u.Status != port.UserMerged || u.MergedInto != a.ID || !u.UpdatedAt.Equal(at) {
			return fmt.Errorf("merged user = %+v, %v", u, err)
		}
		if err := notFound("merge twice", tx.Users().SetMerged(ctx, r, b.ID, a.ID, at)); err != nil {
			return err
		}
		if u, _ := tx.Users().Get(ctx, r, a.ID); u.MergedInto != "" || u.Status != port.UserActive {
			return fmt.Errorf("target user = %+v", u)
		}

		// Org の中身（ロールの付与を除く）を別の Org に移す。ID は変えない。
		target := newOrg(r, port.OrgShared, "")
		if err := tx.Orgs().Create(ctx, target); err != nil {
			return err
		}
		g := port.Group{ID: id.New(id.Group), PublicID: groupID, RealmID: r, OrgID: personal.ID, Name: "team", CreatedAt: T0, UpdatedAt: T0}
		ro := port.Role{ID: id.New(id.Role), PublicID: id.NewExternal(id.Role), RealmID: r, OrgID: personal.ID, Name: "viewer",
			Permissions: []string{"docs.doc:read"}, CreatedAt: T0, UpdatedAt: T0}
		rb := port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: r, Role: "org:admin",
			PrincipalType: port.PrincipalUser, PrincipalID: a.ID, OrgID: personal.ID, CreatedAt: T0}
		for _, err := range []error{tx.Groups().Create(ctx, g), tx.Roles().Create(ctx, ro), tx.RoleBindings().Create(ctx, rb),
			tx.Credentials().SetPreferredOrg(ctx, r, other.ID, personal.ID)} {
			if err != nil {
				return err
			}
		}
		if err := tx.Orgs().MoveContents(ctx, r, personal.ID, target.ID); err != nil {
			return err
		}
		if got, err := tx.Groups().GetByPublicID(ctx, r, g.PublicID); err != nil || got.ID != g.ID || got.OrgID != target.ID {
			return fmt.Errorf("moved group = %+v, %v", got, err)
		}
		if got, err := tx.Roles().GetByPublicID(ctx, r, ro.PublicID); err != nil || got.OrgID != target.ID {
			return fmt.Errorf("moved role = %+v, %v", got, err)
		}
		if got, err := tx.RoleBindings().GetByPublicID(ctx, r, rb.PublicID); err != nil || got.OrgID != personal.ID {
			return fmt.Errorf("binding = %+v, %v (bindings stay)", got, err)
		}
		if got, err := tx.Credentials().Get(ctx, r, other.ID); err != nil || got.PreferredOrgID != target.ID {
			return fmt.Errorf("credential preference = %+v, %v", got, err)
		}
		return nil
	})
	// 移す先に同じ名前の Group があれば移さない。
	err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		dup := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, OrgID: personal.ID, Name: "team", CreatedAt: T0, UpdatedAt: T0}
		if err := tx.Groups().Create(ctx, dup); err != nil {
			return err
		}
		target, err := tx.Groups().GetByPublicID(ctx, r, groupID)
		if err != nil {
			return err
		}
		return tx.Orgs().MoveContents(ctx, r, personal.ID, target.OrgID)
	})
	if err := conflict("duplicate group name", err); err != nil {
		t.Fatal(err)
	}
}
