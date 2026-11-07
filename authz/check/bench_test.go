package check_test

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/port"
)

// BenchmarkCheckHit は判定の材料のキャッシュに当たった判定（design.md 4.5、ADR 0064。目標 1µs）。
func BenchmarkCheckHit(b *testing.B) {
	k := testkit.New(b)
	user := check.Principal{Type: port.PrincipalUser, ID: "u_bench"}
	k.Tx(b, func(ctx context.Context, tx port.Tx) error {
		if err := role.Grant(ctx, tx, k.RealmID, role.RealmAdmin, user.Type, user.ID, k.Clock.Now()); err != nil {
			return err
		}
		return role.Grant(ctx, tx, k.RealmID, role.RealmSupport, user.Type, user.ID, k.Clock.Now())
	})
	c := &check.Checker{Storage: k.Storage, Clock: k.Clock, TTL: time.Hour}
	ctx := context.Background()
	req := check.Request{Principal: user, Action: role.PermUsersRecover}
	if ok, err := c.Check(ctx, k.RealmID, req); err != nil || !ok {
		b.Fatal(ok, err)
	}
	for b.Loop() {
		if ok, err := c.Check(ctx, k.RealmID, req); err != nil || !ok {
			b.Fatal(ok, err)
		}
	}
}

// BenchmarkDecideManyHit は、キャッシュの当たった主体の 100 件の一括判定（authz:batch-check）。
func BenchmarkDecideManyHit(b *testing.B) {
	k := testkit.New(b)
	user := check.Principal{Type: port.PrincipalUser, ID: "u_bench"}
	k.Tx(b, func(ctx context.Context, tx port.Tx) error {
		return role.Grant(ctx, tx, k.RealmID, role.RealmAdmin, user.Type, user.ID, k.Clock.Now())
	})
	c := &check.Checker{Storage: k.Storage, Clock: k.Clock, TTL: time.Hour}
	ctx := context.Background()
	items := make([]check.Item, 100)
	for i := range items {
		items[i] = check.Item{Action: role.PermUsersRecover}
		if i%2 == 1 {
			items[i].Action = role.PermClientsManage
		}
	}
	base := check.Request{Principal: user}
	if _, err := c.DecideMany(ctx, k.RealmID, base, items); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		ds, err := c.DecideMany(ctx, k.RealmID, base, items)
		if err != nil || len(ds) != len(items) {
			b.Fatal(len(ds), err)
		}
	}
}
