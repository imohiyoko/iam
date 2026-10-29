package storagetest

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// testAttributes はカスタム属性（design.md 11.7、ADR 0080）の定義と値。
func testAttributes(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	dept := port.AttributeDef{RealmID: r, Key: "department", Type: port.AttributeString, Values: []string{}, MaxLength: 64, UserEditable: true,
		InToken: true, CreatedAt: T0, UpdatedAt: T0}
	tier := port.AttributeDef{RealmID: r, Key: "tier", Type: port.AttributeEnum, Values: []string{"gold", "silver"}, Encrypted: true,
		CreatedAt: T0, UpdatedAt: T0}
	u, v := newUser(r), newUser(r)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Attributes()
		for _, d := range []port.AttributeDef{tier, dept, {RealmID: other, Key: "tier", Type: port.AttributeBoolean, Values: []string{}, CreatedAt: T0, UpdatedAt: T0}} {
			if err := repo.CreateDef(ctx, d); err != nil {
				return err
			}
		}
		if err := conflict("same key", repo.CreateDef(ctx, dept)); err != nil {
			return err
		}
		ds, err := repo.ListDefs(ctx, r)
		if err != nil || !reflect.DeepEqual(ds, []port.AttributeDef{dept, tier}) {
			return fmt.Errorf("ListDefs = %+v, %v", ds, err)
		}
		if err := notFound("get in another realm", second(repo.GetDef(ctx, id.New(id.Realm), "department"))); err != nil {
			return err
		}
		upd := tier
		upd.Values, upd.MaxLength, upd.UserEditable, upd.InToken, upd.UpdatedAt = []string{"gold"}, 0, true, true, T0.Add(time.Hour)
		upd.Type, upd.Encrypted = port.AttributeString, false // 型と暗号化は変わらない
		if err := repo.UpdateDef(ctx, upd); err != nil {
			return err
		}
		got, err := repo.GetDef(ctx, r, "tier")
		want := tier
		want.Values, want.UserEditable, want.InToken, want.UpdatedAt = []string{"gold"}, true, true, T0.Add(time.Hour)
		if err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("GetDef after update = %+v, %v", got, err)
		}
		if err := notFound("update missing", repo.UpdateDef(ctx, port.AttributeDef{RealmID: r, Key: "nope", Values: []string{}})); err != nil {
			return err
		}

		for _, x := range []port.User{u, v} {
			if err := tx.Users().Create(ctx, x); err != nil {
				return err
			}
		}
		vals := []port.UserAttribute{
			{RealmID: r, UserID: u.ID, Key: "tier", Value: []byte("ct"), UpdatedAt: T0},
			{RealmID: r, UserID: u.ID, Key: "department", Value: []byte(`"sales"`), UpdatedAt: T0},
			{RealmID: r, UserID: v.ID, Key: "department", Value: []byte(`"eng"`), UpdatedAt: T0},
		}
		for _, a := range vals {
			if err := repo.SetValue(ctx, a); err != nil {
				return err
			}
		}
		// 置き換え。
		vals[1].Value, vals[1].UpdatedAt = []byte(`"support"`), T0.Add(time.Minute)
		if err := repo.SetValue(ctx, vals[1]); err != nil {
			return err
		}
		vs, err := repo.ListValues(ctx, r, u.ID)
		if err != nil || len(vs) != 2 || vs[0].Key != "department" || !bytes.Equal(vs[0].Value, []byte(`"support"`)) || !vs[0].UpdatedAt.Equal(T0.Add(time.Minute)) || vs[1].Key != "tier" {
			return fmt.Errorf("ListValues = %+v, %v", vs, err)
		}
		if vs, err := repo.ListValues(ctx, other, u.ID); err != nil || len(vs) != 0 {
			return fmt.Errorf("ListValues in another realm = %+v, %v", vs, err)
		}
		if err := repo.DeleteValue(ctx, r, u.ID, "tier"); err != nil {
			return err
		}
		if err := repo.DeleteValue(ctx, r, u.ID, "tier"); err != nil {
			return fmt.Errorf("delete missing value: %v", err)
		}
		// 定義を消すと、その値も消える。
		if err := repo.DeleteDef(ctx, r, "department"); err != nil {
			return err
		}
		if err := notFound("delete twice", repo.DeleteDef(ctx, r, "department")); err != nil {
			return err
		}
		if vs, err := repo.ListValues(ctx, r, v.ID); err != nil || len(vs) != 0 {
			return fmt.Errorf("values after deleting the def = %+v, %v", vs, err)
		}
		// ユーザーの消去で値が消える。
		if err := repo.SetValue(ctx, port.UserAttribute{RealmID: r, UserID: u.ID, Key: "tier", Value: []byte("ct2"), UpdatedAt: T0}); err != nil {
			return err
		}
		if err := tx.Users().Erase(ctx, r, u.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if vs, err := repo.ListValues(ctx, r, u.ID); err != nil || len(vs) != 0 {
			return fmt.Errorf("values after erase = %+v, %v", vs, err)
		}
		// 片付けは値から。
		if err := repo.SetValue(ctx, port.UserAttribute{RealmID: r, UserID: v.ID, Key: "tier", Value: []byte("ct3"), UpdatedAt: T0}); err != nil {
			return err
		}
		if n, err := repo.Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("repo.Count = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 1); err != nil || n != 1 {
			return fmt.Errorf("Purge(1) = %d, %v", n, err)
		}
		if vs, err := repo.ListValues(ctx, r, v.ID); err != nil || len(vs) != 0 {
			return fmt.Errorf("values after purge = %+v, %v", vs, err)
		}
		if n, err := repo.Purge(ctx, 10); err != nil || n != 2 {
			return fmt.Errorf("Purge(10) = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("repo.Count after purge = %d, %v", n, err)
		}
		return nil
	})
}
