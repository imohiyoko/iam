package storagetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// realm のホスト名と更新（複数 realm。design.md 11.1、ADR 0083）。

func testRealmHosts(t *testing.T, h Harness) {
	s, _ := open(t, h)
	a, b := newRealm("a"), newRealm("b")
	a.Hosts = []string{"a.example.com", "login.a.example"}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, r := range []port.Realm{a, b} {
			if err := tx.Realms().Create(ctx, r); err != nil {
				return err
			}
		}
		got, err := tx.Realms().GetByHost(ctx, "login.a.example")
		if err != nil || got.ID != a.ID || !slices.Equal(got.Hosts, a.Hosts) || !got.UpdatedAt.Equal(T0) {
			return fmt.Errorf("realms.GetByHost = %+v, %v", got, err)
		}
		if got, err := tx.Realms().Get(ctx, b.ID); err != nil || got.Hosts != nil || !got.UpdatedAt.Equal(T0) {
			return fmt.Errorf("realm without hosts = %+v, %v", got, err)
		}
		if _, err := tx.Realms().GetByHost(ctx, "b.example.com"); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("realms.GetByHost missing: want NotFound, got %v", err)
		}

		// 更新：設定とホスト名を置き換える。
		b.Settings, b.Hosts, b.UpdatedAt = []byte(`{"timezone":"Asia/Tokyo"}`), []string{"b.example.com"}, T0.Add(1)
		if err := tx.Realms().Update(ctx, b); err != nil {
			return err
		}
		a.Hosts, a.UpdatedAt = []string{"a.example.com"}, T0.Add(2)
		if err := tx.Realms().Update(ctx, a); err != nil {
			return err
		}
		all, err := tx.Realms().List(ctx)
		if err != nil || len(all) != 2 {
			return fmt.Errorf("realms.List = %+v, %v", all, err)
		}
		for _, r := range all {
			want := map[string]port.Realm{a.ID: a, b.ID: b}[r.ID]
			if !slices.Equal(r.Hosts, want.Hosts) || !r.UpdatedAt.Equal(want.UpdatedAt) || string(r.Settings) != string(want.Settings) {
				return fmt.Errorf("listed realm = %+v, want %+v", r, want)
			}
		}
		if _, err := tx.Realms().GetByHost(ctx, "login.a.example"); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("removed host: want NotFound, got %v", err)
		}
		missing := newRealm("zzz")
		return notFound("update missing realm", tx.Realms().Update(ctx, missing))
	})
	// ホスト名は realm をまたいで重複しない。
	for name, fn := range map[string]func(ctx context.Context, tx port.Tx) error{
		"create": func(ctx context.Context, tx port.Tx) error {
			c := newRealm("c")
			c.Hosts = []string{"b.example.com"}
			return tx.Realms().Create(ctx, c)
		},
		"update": func(ctx context.Context, tx port.Tx) error {
			a.Hosts = []string{"a.example.com", "b.example.com"}
			return tx.Realms().Update(ctx, a)
		},
	} {
		if err := conflict(name+" with a taken host", s.Tx(context.Background(), fn)); err != nil {
			t.Fatal(err)
		}
	}
}
