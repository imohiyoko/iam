package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// BenchmarkPointLookup は ID による1件の取得を1トランザクションで行う。
// セッションの有効性のキャッシュに外れたときの検証（design.md 5.3）と、認可判定のクエリ（4.5）の
// 下限の目安にする。実際のクエリができたら（M1、M4）そのベンチマークに置き換える。
func BenchmarkPointLookup(b *testing.B) {
	s := openTemp(b)
	defer s.Close()
	ctx := context.Background()
	var ids []string
	s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		for i := range 1000 {
			r := port.Realm{ID: id.New(id.Realm), Slug: "r" + id.New("x")[2:] + string(rune('a'+i%26)), Settings: []byte("{}"), CreatedAt: time.Now()}
			ids = append(ids, r.ID)
			if err := tx.Realms().Create(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	i := 0
	for b.Loop() {
		err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := tx.Realms().Get(ctx, ids[i%len(ids)])
			return err
		})
		if err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkAuditRecord は監査ログ1件の追記（ハッシュチェーン + outbox）を1トランザクションで行う。
func BenchmarkAuditRecord(b *testing.B) {
	s := openTemp(b)
	defer s.Close()
	ctx := context.Background()
	clk := clock.System{}
	realm := id.New(id.Realm)
	for b.Loop() {
		err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "bench", Result: audit.ResultSuccess, RealmID: realm})
			return err
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
