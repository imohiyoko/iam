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

// 自前の API（リソースサーバー）の登録（RFC 8707、ADR 0112）の契約。

func testOAuthResources(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	mk := func(realm, uri string, at time.Time) port.OAuthResource {
		return port.OAuthResource{ID: id.NewExternal(id.OAuthResource), RealmID: realm, URI: uri, Name: "API " + uri,
			Scopes: []string{"orders:read", "orders:write"}, Clients: []string{"cli_a"}, ServiceAccounts: []string{"sva_a", "sva_b"},
			CreatedAt: at, UpdatedAt: at}
	}
	a, b := mk(r, "https://b.example.com/", T0.Add(time.Second)), mk(r, "https://a.example.com/", T0)
	b.Clients, b.ServiceAccounts = []string{}, []string{}
	o := mk(other, "https://a.example.com/", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.OAuthResources()
		for _, x := range []port.OAuthResource{a, b, o} {
			if err := repo.Create(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.URI, err)
			}
		}
		if err := conflict("same uri", repo.Create(ctx, mk(r, "https://a.example.com/", T0))); err != nil {
			return err
		}
		dup := mk(r, "https://c.example.com/", T0)
		dup.ID = a.ID
		if err := conflict("same id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("get other realm", second(repo.Get(ctx, other, a.ID))); err != nil {
			return err
		}
		if got, err := repo.GetByURI(ctx, r, "https://a.example.com/"); err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("by uri = %+v, %v", got, err)
		}
		if err := notFound("by uri prefix", second(repo.GetByURI(ctx, r, "https://a.example.com"))); err != nil {
			return err
		}
		if list, err := repo.List(ctx, r); err != nil || !reflect.DeepEqual(list, []port.OAuthResource{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		// 置き換え。作成時刻は変えない。URI の重複は errs.Conflict。
		up := a
		up.URI, up.Name, up.Scopes, up.Clients, up.ServiceAccounts = "https://b2.example.com/", "B2", []string{"x"}, []string{}, []string{"sva_c"}
		up.UpdatedAt, up.CreatedAt = T0.Add(time.Hour), T0.Add(2*time.Hour)
		if err := repo.Update(ctx, up); err != nil {
			return err
		}
		up.CreatedAt = a.CreatedAt
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v, %v", got, err)
		}
		clash := up
		clash.URI = b.URI
		if err := conflict("update to a used uri", repo.Update(ctx, clash)); err != nil {
			return err
		}
		ghost := mk(r, "https://ghost.example.com/", T0)
		if err := notFound("update missing", repo.Update(ctx, ghost)); err != nil {
			return err
		}
		wrongRealm := up
		wrongRealm.RealmID = other
		if err := notFound("update other realm", repo.Update(ctx, wrongRealm)); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", repo.Delete(ctx, r, a.ID)); err != nil {
			return err
		}
		if err := notFound("delete other realm", repo.Delete(ctx, other, b.ID)); err != nil {
			return err
		}
		return nil
	})
	// フィーチャーの無効化：全 realm から消す。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.OAuthResources()
		n, err := repo.Count(ctx)
		if err != nil || n < 2 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if got, err := repo.Purge(ctx, 1); err != nil || got != 1 {
			return fmt.Errorf("purge 1 = %d, %v", got, err)
		}
		for {
			got, err := repo.Purge(ctx, 100)
			if err != nil {
				return err
			}
			if got == 0 {
				break
			}
		}
		if n, err := repo.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		return nil
	})
}
