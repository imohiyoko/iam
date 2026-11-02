package storagetest

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// testRetiredLookups は、退役した検索キー（ADR 0106）と、認証情報の Org の指定を確かめる。
func testRetiredLookups(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	owner := newUser(r)
	u := owner.ID
	keep := newCredential(r, u, "passkey", []byte("cred-1"))
	keep.ReserveLookup, keep.LookupKeyID = true, "ik_1"
	plain := newCredential(r, u, "x509", []byte("cert-1"))
	at := T0.Add(time.Hour)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		for _, x := range []port.Credential{keep, plain} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if got, err := repo.Get(ctx, r, keep.ID); err != nil || !got.ReserveLookup || got.PreferredOrgID != "" {
			return fmt.Errorf("reserved credential = %+v, %v", got, err)
		}
		org := id.New(id.Org)
		if err := repo.SetPreferredOrg(ctx, r, keep.ID, org); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, keep.ID); err != nil || got.PreferredOrgID != org {
			return fmt.Errorf("preferred org = %+v, %v", got, err)
		}
		for name, err := range map[string]error{
			"org in another realm": repo.SetPreferredOrg(ctx, id.New(id.Realm), keep.ID, ""),
			"org of missing":       repo.SetPreferredOrg(ctx, r, id.New(id.Credential), ""),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		// 無効化：印のあるものは検索キーを退役させ、同じ方式では作り直せない。印の無いものは作り直せる。
		for _, x := range []port.Credential{keep, plain} {
			if err := repo.Revoke(ctx, r, x.ID, at, "revoked_by_user"); err != nil {
				return err
			}
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", []byte("cred-1")); err != nil || !ok {
			return fmt.Errorf("retired = %v, %v", ok, err)
		}
		for name, q := range map[string][3]string{"plain": {r, "x509", "cert-1"}, "other method": {r, "x509", "cred-1"},
			"other realm": {id.New(id.Realm), "passkey", "cred-1"}, "other value": {r, "passkey", "cred-2"}} {
			if ok, err := repo.LookupRetired(ctx, q[0], q[1], []byte(q[2])); err != nil || ok {
				return fmt.Errorf("%s retired = %v, %v", name, ok, err)
			}
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", nil); err != nil || ok {
			return fmt.Errorf("empty lookup retired = %v, %v", ok, err)
		}
		if err := conflict("re-create retired", repo.Create(ctx, newCredential(r, id.New(id.User), "passkey", []byte("cred-1")))); err != nil {
			return err
		}
		// 無効化した行としてなら作れる（履歴。退役の確認は有効なものだけ）。
		hist := newCredential(r, u, "passkey", []byte("cred-1"))
		hist.RevokedAt = &at
		if err := repo.Create(ctx, hist); err != nil {
			return fmt.Errorf("revoked history: %w", err)
		}
		for _, x := range []port.Credential{newCredential(r, u, "x509", []byte("cert-1")), newCredential(r, u, "other", []byte("cred-1"))} {
			if err := repo.Create(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.Method, err)
			}
		}
		// 別の鍵で作ったものを退役させる。無効化を重ねても何もしない。検索キーの無いものは退役させない。
		old := newCredential(r, u, "passkey", []byte("cred-9"))
		old.ReserveLookup, old.LookupKeyID = true, "ik_0"
		bare := newCredential(r, u, "passkey", nil)
		bare.ReserveLookup, bare.LookupKeyID = true, "ik_bare"
		for _, x := range []port.Credential{old, bare} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
			for range 2 {
				if err := repo.Revoke(ctx, r, x.ID, at, "revoked_by_user"); err != nil {
					return err
				}
			}
		}
		if ids, err := repo.RetiredLookupKeyIDs(ctx, r, "passkey"); err != nil || !slices.Equal(ids, []string{"ik_0", "ik_1"}) {
			return fmt.Errorf("retired key ids = %v, %v", ids, err)
		}
		if ids, err := repo.RetiredLookupKeyIDs(ctx, r, "x509"); err != nil || len(ids) != 0 {
			return fmt.Errorf("retired key ids of x509 = %v, %v", ids, err)
		}
		// 持ち主を消しても退役は残る（4.6）。
		if err := tx.Users().Create(ctx, owner); err != nil {
			return err
		}
		if err := tx.Users().Erase(ctx, r, u, at); err != nil {
			return err
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", []byte("cred-1")); err != nil || !ok {
			return fmt.Errorf("retired after erase = %v, %v", ok, err)
		}
		return nil
	})
}

var passkeyIsolationCase = IsolationCase{
	Name: "Credentials.LookupRetired+RetiredLookupKeyIDs",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		c := newCredential(r, isoUser, "passkey", []byte("iso-cred"))
		c.ReserveLookup, c.LookupKeyID = true, "ik_iso"
		if err := tx.Credentials().Create(ctx, c); err != nil {
			return err
		}
		return tx.Credentials().Revoke(ctx, r, c.ID, T0, "revoked_by_user")
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		ok, err := tx.Credentials().LookupRetired(ctx, r, "passkey", []byte("iso-cred"))
		if err != nil {
			return 0, err
		}
		n := 0
		if ok {
			n++
		}
		ids, err := tx.Credentials().RetiredLookupKeyIDs(ctx, r, "passkey")
		return n + len(ids), err
	},
}
