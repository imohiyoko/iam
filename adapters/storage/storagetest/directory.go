package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// ディレクトリの同期（ADR 0102）の契約：Group の対応と、connection の有効な外部 ID の一覧。

func testDirectoryGroups(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	conn, conn2 := id.New(id.Connection), id.New(id.Connection)
	g := func(realm, c, key string) port.DirectoryGroup {
		return port.DirectoryGroup{RealmID: realm, ConnectionID: c, ExternalKey: key, GroupID: id.New(id.Group), CreatedAt: T0}
	}
	a, b := g(r, conn, "cn=b,ou=groups"), g(r, conn, "cn=a,ou=groups")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.DirectoryGroups()
		for _, x := range []port.DirectoryGroup{a, b, g(r, conn2, "cn=a,ou=groups"), g(other, conn, "cn=a,ou=groups")} {
			if err := repo.Create(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.ExternalKey, err)
			}
		}
		if err := conflict("same key", repo.Create(ctx, g(r, conn, "cn=a,ou=groups"))); err != nil {
			return err
		}
		dup := g(r, conn, "cn=c,ou=groups")
		dup.GroupID = a.GroupID
		if err := conflict("same group", repo.Create(ctx, dup)); err != nil {
			return err
		}
		got, err := repo.ListByConnection(ctx, r, conn)
		if err != nil || !reflect.DeepEqual(got, []port.DirectoryGroup{b, a}) {
			return fmt.Errorf("ListByConnection = %+v, %v", got, err)
		}
		if err := repo.Delete(ctx, r, conn, a.ExternalKey); err != nil {
			return err
		}
		if err := notFound("delete twice", repo.Delete(ctx, r, conn, a.ExternalKey)); err != nil {
			return err
		}
		if err := notFound("delete other realm", repo.Delete(ctx, other, conn2, "cn=a,ou=groups")); err != nil {
			return err
		}
		if n, err := repo.Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if n, err := repo.DeleteByConnection(ctx, r, conn); err != nil || n != 1 {
			return fmt.Errorf("deleteByConnection = %d, %v", n, err)
		}
		if got, err := repo.ListByConnection(ctx, other, conn); err != nil || len(got) != 1 {
			return fmt.Errorf("other realm = %+v, %v", got, err)
		}
		if n, err := repo.Purge(ctx, 1); err != nil || n != 1 {
			return fmt.Errorf("purge = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("purge = %d, %v", n, err)
		}
		n, err := repo.Count(ctx)
		if err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		return nil
	})
}

func testIdentitiesByConnection(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	conn := id.New(id.Connection)
	var made []port.Identity
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for i := range 5 {
			x := port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: id.New(id.User),
				ConnectionID: conn, ProviderSubject: fmt.Sprintf("sub-%d", i), CreatedAt: T0.Add(time.Duration(i) * time.Second)}
			if err := tx.Identities().Create(ctx, x); err != nil {
				return err
			}
			made = append(made, x)
		}
		// 別の connection・別の realm は出ない。
		for _, x := range []port.Identity{
			{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: id.New(id.User), ConnectionID: id.New(id.Connection), ProviderSubject: "x", CreatedAt: T0},
			{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: id.New(id.Realm), UserID: id.New(id.User), ConnectionID: conn, ProviderSubject: "y", CreatedAt: T0},
		} {
			if err := tx.Identities().Create(ctx, x); err != nil {
				return err
			}
		}
		return tx.Identities().Revoke(ctx, r, made[2].ID, T0, "test")
	})
	var seen []string
	after := ""
	for {
		var page []port.Identity
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			var err error
			page, err = tx.Identities().ListActiveByConnection(ctx, r, conn, after, 2)
			return err
		})
		if len(page) == 0 {
			break
		}
		for _, x := range page {
			if x.RevokedAt != nil || x.ConnectionID != conn || x.RealmID != r {
				t.Fatalf("unexpected identity %+v", x)
			}
			if x.ID <= after {
				t.Fatalf("not in id order: %s after %s", x.ID, after)
			}
			seen = append(seen, x.ProviderSubject)
			after = x.ID
		}
	}
	if len(seen) != 4 {
		t.Fatalf("seen = %v, want 4 active", seen)
	}
}
