package storagetest

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// testLegacyListAllDelete は、authn_credentials への移行（ADR 0101）で使う、方式専用の表の全 realm の列挙と削除を確かめる。
func testLegacyListAllDelete(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	ts := []port.TOTPCredential{newTOTP(r1, id.New(id.User)), newTOTP(r2, id.New(id.User)), newTOTP(r2, id.New(id.User))}
	ps := []port.PasswordCredential{newPassword(r1, id.New(id.User)), newPassword(r2, id.New(id.User))}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, c := range ts {
			if err := tx.TOTP().Create(ctx, c); err != nil {
				return err
			}
		}
		for _, c := range ps {
			if err := tx.Passwords().Create(ctx, c); err != nil {
				return err
			}
		}
		ids := func(xs []port.TOTPCredential) []string {
			var out []string
			for _, x := range xs {
				out = append(out, x.ID)
			}
			return out
		}
		want := ids(ts)
		slices.Sort(want)
		all, err := tx.TOTP().ListAll(ctx, 10)
		if err != nil || !slices.Equal(ids(all), want) {
			return fmt.Errorf("totp.ListAll = %v, %v; want %v", ids(all), err, want)
		}
		if first, err := tx.TOTP().ListAll(ctx, 2); err != nil || !slices.Equal(ids(first), want[:2]) {
			return fmt.Errorf("totp.ListAll(2) = %v, %v", ids(first), err)
		}
		// 別の realm の ID では消さない。無いものは何もしない。
		if err := tx.TOTP().Delete(ctx, r1, ts[1].ID); err != nil {
			return err
		}
		if err := tx.TOTP().Delete(ctx, r1, id.New(id.TOTP)); err != nil {
			return err
		}
		if err := tx.TOTP().Delete(ctx, r2, ts[1].ID); err != nil {
			return err
		}
		if left, err := tx.TOTP().ListAll(ctx, 10); err != nil || len(left) != 2 || slices.Contains(ids(left), ts[1].ID) {
			return fmt.Errorf("totp after delete = %v, %v", ids(left), err)
		}
		pa, err := tx.Passwords().ListAll(ctx, 10)
		if err != nil || len(pa) != 2 || pa[0].ID > pa[1].ID {
			return fmt.Errorf("passwords.ListAll = %+v, %v", pa, err)
		}
		if err := tx.Passwords().Delete(ctx, r2, ps[0].ID); err != nil {
			return err
		}
		if err := tx.Passwords().Delete(ctx, r1, ps[0].ID); err != nil {
			return err
		}
		if pa, err := tx.Passwords().ListAll(ctx, 10); err != nil || len(pa) != 1 || pa[0].ID != ps[1].ID {
			return fmt.Errorf("passwords after delete = %+v, %v", pa, err)
		}
		return nil
	})
}
