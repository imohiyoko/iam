package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 汎用の認証情報（authn_credentials。ADR 0090、0092）の契約。

const isoCredential = "crd_00000000000000000000000009"

func newCredential(realmID, userID, method string, lookup []byte) port.Credential {
	return port.Credential{ID: id.New(id.Credential), PublicID: id.NewExternal(id.Credential), RealmID: realmID, UserID: userID,
		Method: method, Lookup: lookup, Data: []byte("data-ct"), DataVersion: 1, CreatedAt: T0}
}

func testCredentials(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, other := id.New(id.Realm), id.New(id.User), id.New(id.User)
	c := newCredential(r, u, "hotp", nil)
	keyed := newCredential(r, u, "x509", []byte("lookup-1"))
	keyed.CreatedAt, keyed.LookupKeyID = T0.Add(time.Second), "ik_1"
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		for _, x := range []port.Credential{c, keyed} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		dup := newCredential(r, u, "hotp", nil)
		dup.PublicID = c.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		// 検索キーは realm と方式の中で一意。別の方式・別の realm なら同じ値でよい。検索キーの無いものは重ならない。
		if err := conflict("same lookup", repo.Create(ctx, newCredential(r, other, "x509", []byte("lookup-1")))); err != nil {
			return err
		}
		for _, x := range []port.Credential{newCredential(r, other, "piv", []byte("lookup-1")), newCredential(id.New(id.Realm), other, "x509", []byte("lookup-1")),
			newCredential(r, other, "hotp", nil)} {
			if err := repo.Create(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.Method, err)
			}
		}
		got, err := repo.Get(ctx, r, c.ID)
		if err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("credentials.Get = %+v, %v", got, err)
		}
		if got, err = repo.GetByPublicID(ctx, r, keyed.PublicID); err != nil || !reflect.DeepEqual(got, keyed) {
			return fmt.Errorf("credentials.GetByPublicID = %+v, %v", got, err)
		}
		if got, err = repo.GetByLookup(ctx, r, "x509", []byte("lookup-1")); err != nil || got.ID != keyed.ID {
			return fmt.Errorf("credentials.GetByLookup = %+v, %v", got, err)
		}
		// 検索キーを作った鍵の ID は、別の方式・別の realm・無効化したものを数えない。
		rotated := newCredential(r, other, "x509", []byte("lookup-2"))
		rotated.LookupKeyID = "ik_0"
		if err := repo.Create(ctx, rotated); err != nil {
			return err
		}
		if ids, err := repo.LookupKeyIDs(ctx, r, "x509"); err != nil || !reflect.DeepEqual(ids, []string{"ik_0", "ik_1"}) {
			return fmt.Errorf("credentials.LookupKeyIDs = %v, %v", ids, err)
		}
		if ids, err := repo.LookupKeyIDs(ctx, r, "hotp"); err != nil || len(ids) != 0 {
			return fmt.Errorf("credentials.LookupKeyIDs(hotp) = %v, %v", ids, err)
		}
		if err := repo.Revoke(ctx, r, rotated.ID, T0, "test"); err != nil {
			return err
		}
		if ids, err := repo.LookupKeyIDs(ctx, r, "x509"); err != nil || !reflect.DeepEqual(ids, []string{"ik_1"}) {
			return fmt.Errorf("credentials.LookupKeyIDs after revoke = %v, %v", ids, err)
		}
		for name, err := range map[string]error{
			"lookup of another method": second(repo.GetByLookup(ctx, r, "hotp", []byte("lookup-1"))),
			"empty lookup":             second(repo.GetByLookup(ctx, r, "hotp", nil)),
			"get in another realm":     second(repo.Get(ctx, id.New(id.Realm), c.ID)),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		list, err := repo.ListByUser(ctx, r, u, "")
		if err != nil || len(list) != 2 || list[0].ID != c.ID || list[1].ID != keyed.ID {
			return fmt.Errorf("credentials.ListByUser = %+v, %v", list, err)
		}
		if list, err = repo.ListByUser(ctx, r, u, "hotp"); err != nil || len(list) != 1 || list[0].ID != c.ID {
			return fmt.Errorf("credentials.ListByUser(hotp) = %+v, %v", list, err)
		}

		// データの置き換えは、読んだときのデータと同じときだけ（再利用の拒否）。
		if err := repo.UpdateData(ctx, r, c.ID, c.Data, []byte("data-2"), 2); err != nil {
			return err
		}
		if err := conflict("stale data", repo.UpdateData(ctx, r, c.ID, c.Data, []byte("data-3"), 2)); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, c.ID); string(got.Data) != "data-2" || got.DataVersion != 2 {
			return fmt.Errorf("after UpdateData = %+v", got)
		}
		at := T0.Add(time.Minute)
		if err := repo.Used(ctx, r, c.ID, at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, c.ID); got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
			return fmt.Errorf("after Used = %+v", got)
		}
		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"update in another realm": repo.UpdateData(ctx, other, c.ID, []byte("data-2"), []byte("x"), 2),
			"used in another realm":   repo.Used(ctx, other, c.ID, at),
			"revoke in another realm": repo.Revoke(ctx, other, c.ID, at, "x"),
			"update missing":          repo.UpdateData(ctx, r, id.New(id.Credential), nil, []byte("x"), 1),
			"used missing":            repo.Used(ctx, r, id.New(id.Credential), at),
			"revoke missing":          repo.Revoke(ctx, r, id.New(id.Credential), at, "x"),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}

		// 無効化は1回だけ記録し、無効化したものはデータを置き換えられず、検索キーで引けない。同じ検索キーで作り直せる。
		if err := repo.Revoke(ctx, r, keyed.ID, at, "revoked_by_user"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, keyed.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, err = repo.Get(ctx, r, keyed.ID)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "revoked_by_user" {
			return fmt.Errorf("revoked credential = %+v, %v", got, err)
		}
		if err := conflict("update revoked", repo.UpdateData(ctx, r, keyed.ID, keyed.Data, []byte("x"), 1)); err != nil {
			return err
		}
		if err := notFound("lookup of revoked", second(repo.GetByLookup(ctx, r, "x509", []byte("lookup-1")))); err != nil {
			return err
		}
		if err := repo.Create(ctx, newCredential(r, u, "x509", []byte("lookup-1"))); err != nil {
			return fmt.Errorf("re-create after revoke: %w", err)
		}

		// 統合：無効化したものも含めて移す。
		into := id.New(id.User)
		if n, err := repo.MoveUser(ctx, r, u, into); err != nil || n != 3 {
			return fmt.Errorf("credentials.MoveUser = %d, %v", n, err)
		}
		if n, err := count(repo.ListByUser(ctx, r, u, "")); err != nil || n != 0 {
			return fmt.Errorf("after move, from = %d, %v", n, err)
		}
		if n, err := count(repo.ListByUser(ctx, r, into, "")); err != nil || n != 3 {
			return fmt.Errorf("after move, into = %d, %v", n, err)
		}
		if n, err := repo.MoveUser(ctx, id.New(id.Realm), into, u); err != nil || n != 0 {
			return fmt.Errorf("move in another realm = %d, %v", n, err)
		}
		return nil
	})
}

// testCredentialUpdateConcurrent は同じデータからの置き換えを同時に行っても1つしか通らないことを確かめる（再利用の拒否）。
func testCredentialUpdateConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	c := newCredential(r, id.New(id.User), "hotp", nil)
	tx(t, s, func(ctx context.Context, tx port.Tx) error { return tx.Credentials().Create(ctx, c) })
	ExactlyOneSucceeds(t, Concurrent(16, func(i int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Credentials().UpdateData(ctx, r, c.ID, c.Data, fmt.Appendf(nil, "next-%d", i), 1)
		})
	}))
}

// testCredentialLookupConcurrent は同じ検索キーを同時に作っても1つしか通らないことを確かめる。
func testCredentialLookupConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Credentials().Create(ctx, newCredential(r, id.New(id.User), "x509", []byte("same")))
		})
	}))
}

// testCredentialCountPurge はフィーチャーの無効化（11.12）での数え上げと片付け。方式ごとに全 realm を数える。
func testCredentialCountPurge(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, r := range []string{r1, r2, r2} {
			c := newCredential(r, id.New(id.User), "hotp", nil)
			if err := tx.Credentials().Create(ctx, c); err != nil {
				return err
			}
			if err := tx.Credentials().Revoke(ctx, r, c.ID, T0, "x"); err != nil {
				return err
			}
			if err := tx.Credentials().Create(ctx, newCredential(r, id.New(id.User), "other", nil)); err != nil {
				return err
			}
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		if n, err := repo.Count(ctx, "hotp"); err != nil || n != 3 {
			return fmt.Errorf("credentials.Count = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, "hotp", 2); err != nil || n != 2 {
			return fmt.Errorf("credentials.Purge(2) = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, "hotp", 10); err != nil || n != 1 {
			return fmt.Errorf("credentials.Purge = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx, "hotp"); err != nil || n != 0 {
			return fmt.Errorf("credentials.Count after purge = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx, "other"); err != nil || n != 3 {
			return fmt.Errorf("other method after purge = %d, %v", n, err)
		}
		return nil
	})
}

var credentialIsolationCase = IsolationCase{
	Name: "Credentials.Get+GetByPublicID+GetByLookup+ListByUser",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		c := newCredential(r, isoUser, "iso", []byte("iso-lookup"))
		c.ID, c.PublicID = isoCredential, isoCredential
		return tx.Credentials().Create(ctx, c)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		repo := tx.Credentials()
		a, err := countOne(repo.Get(ctx, r, isoCredential))
		if err != nil {
			return 0, err
		}
		b, err := countOne(repo.GetByPublicID(ctx, r, isoCredential))
		if err != nil {
			return 0, err
		}
		c, err := countOne(repo.GetByLookup(ctx, r, "iso", []byte("iso-lookup")))
		if err != nil {
			return 0, err
		}
		d, err := count(repo.ListByUser(ctx, r, isoUser, ""))
		return a + b + c + d, err
	},
}
