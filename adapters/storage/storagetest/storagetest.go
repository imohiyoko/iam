// Package storagetest は Storage ポートの契約テスト（design.md 12章、ADR 0015）。
//
// 各 Storage アダプタ（参照実装を含む）は自分のテストから Run を呼ぶ。
// 新しい Repository を足したら、ここに契約と realm の分離の検査（IsolationCase）を足す。
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Harness はアダプタごとのテストの準備。
type Harness struct {
	// New は空の Storage を返す。テストの終わりに Close する。
	New func(t *testing.T, clk clock.Clock) port.Storage
	// TamperAudit は監査ログの seq の1件のペイロードを、Storage の外から直接書き換える。
	TamperAudit func(t *testing.T, s port.Storage, seq int64, payload []byte)
}

// T0 は契約テストで使う時刻。
var T0 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

// Run はすべての契約テストを実行する。
func Run(t *testing.T, h Harness) {
	tests := []struct {
		name string
		fn   func(*testing.T, Harness)
	}{
		{"Realms", testRealms},
		{"RealmSlugUniqueConcurrent", testRealmSlugUniqueConcurrent},
		{"Rollback", testRollback},
		{"Features", testFeatures},
		{"DataKeys", testDataKeys},
		{"AuditKeys", testAuditKeys},
		{"DataKeysUniqueConcurrent", testDataKeysUniqueConcurrent},
		{"AuditChain", testAuditChain},
		{"AuditTamperDetected", testAuditTamperDetected},
		{"AuditConcurrentAppend", testAuditConcurrentAppend},
		{"Outbox", testOutbox},
		{"OutboxRelay", testOutboxRelay},
		{"RealmIsolation", testRealmIsolation},
	}
	tests = append(tests, authnTests...)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, h) })
	}
}

func open(t *testing.T, h Harness) (port.Storage, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(T0)
	s := h.New(t, clk)
	t.Cleanup(func() { _ = s.Close() })
	return s, clk
}

func tx(t *testing.T, s port.Storage, fn func(context.Context, port.Tx) error) {
	t.Helper()
	if err := s.Tx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func newRealm(slug string) port.Realm {
	return port.Realm{ID: id.New(id.Realm), Slug: slug, Settings: []byte(`{"timezone":"UTC"}`), CreatedAt: T0}
}

// ---------------------------------------------------------------------------

func testRealms(t *testing.T, h Harness) {
	s, _ := open(t, h)
	a, b := newRealm("a"), newRealm("b")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Realms().Create(ctx, a); err != nil {
			return err
		}
		return tx.Realms().Create(ctx, b)
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		got, err := tx.Realms().Get(ctx, a.ID)
		if err != nil {
			return err
		}
		if got.Slug != "a" || !got.CreatedAt.Equal(T0) || !bytes.Equal(got.Settings, a.Settings) {
			return fmt.Errorf("realms.Get = %+v", got)
		}
		got, err = tx.Realms().GetBySlug(ctx, "b")
		if err != nil || got.ID != b.ID {
			return fmt.Errorf("GetBySlug = %+v, %v", got, err)
		}
		if _, err := tx.Realms().Get(ctx, id.New(id.Realm)); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("realms.Get missing: want NotFound, got %v", err)
		}
		if _, err := tx.Realms().GetBySlug(ctx, "zzz"); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("GetBySlug missing: want NotFound, got %v", err)
		}
		all, err := tx.Realms().List(ctx)
		if err != nil || len(all) != 2 {
			return fmt.Errorf("realms.List = %d, %v", len(all), err)
		}
		if err := tx.Realms().Create(ctx, newRealm("a")); !errors.Is(err, errs.Conflict) {
			return fmt.Errorf("duplicate slug: want Conflict, got %v", err)
		}
		return nil
	})
}

// Concurrent は n 個の fn をできるだけ同時に始め、それぞれの結果を返す（並行性の検査の雛形）。
func Concurrent(n int, fn func(i int) error) []error {
	var wg sync.WaitGroup
	start := make(chan struct{})
	out := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return out
}

// ExactlyOneSucceeds は、同時に行った一意な操作のうち1つだけが成功し、残りが Conflict であることを確かめる。
func ExactlyOneSucceeds(t *testing.T, results []error) {
	t.Helper()
	ok := 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, errs.Conflict):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d succeeded, want exactly 1", ok)
	}
}

func testRealmSlugUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Realms().Create(ctx, newRealm("same"))
		})
	}))
}

func testRollback(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := newRealm("rb")
	boom := errors.New("boom")
	err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if err := tx.Realms().Create(ctx, r); err != nil {
			return err
		}
		if err := tx.DataKeys().Create(ctx, port.DataKey{UserID: id.New(id.User), WrappedKey: []byte{1}, KeyID: "k", CreatedAt: T0}); err != nil {
			return err
		}
		if _, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "test", RealmID: r.ID}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Tx error = %v", err)
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if _, err := tx.Realms().Get(ctx, r.ID); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("realm survived rollback: %v", err)
		}
		if last, err := tx.Audit().Last(ctx); err != nil || last != nil {
			return fmt.Errorf("audit survived rollback: %v, %v", last, err)
		}
		if p, err := tx.Outbox().Pending(ctx, eventlog.TopicAudit, 10); err != nil || len(p) != 0 {
			return fmt.Errorf("outbox survived rollback: %d, %v", len(p), err)
		}
		return nil
	})
}

func testFeatures(t *testing.T, h Harness) {
	s, _ := open(t, h)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		l := tx.Features()
		if err := l.Put(ctx, port.FeatureRecord{Feature: "org", State: port.FeatureEnabling, DataVersion: 1, UpdatedAt: T0}); err != nil {
			return err
		}
		if err := l.Put(ctx, port.FeatureRecord{Feature: "org", State: port.FeatureActive, DataVersion: 1, UpdatedAt: T0.Add(time.Second)}); err != nil {
			return err
		}
		if err := l.Put(ctx, port.FeatureRecord{Feature: "a", State: port.FeatureActive, DataVersion: 2, UpdatedAt: T0}); err != nil {
			return err
		}
		got, err := l.List(ctx)
		if err != nil {
			return err
		}
		if len(got) != 2 || got[0].Feature != "a" || got[1].State != port.FeatureActive || !got[1].UpdatedAt.Equal(T0.Add(time.Second)) {
			return fmt.Errorf("features.List = %+v", got)
		}
		if err := l.Delete(ctx, "a"); err != nil {
			return err
		}
		if err := l.Delete(ctx, "missing"); err != nil {
			return err
		}
		got, _ = l.List(ctx)
		if len(got) != 1 {
			return fmt.Errorf("after delete: %+v", got)
		}
		return nil
	})
}

func testDataKeys(t *testing.T, h Harness) {
	testKeyRepo(t, h, id.New(id.User), port.Tx.DataKeys)
}

// testAuditKeys は監査ログの日ごとの鍵。データ鍵と同じ契約で、別の表に置く。
func testAuditKeys(t *testing.T, h Harness) {
	testKeyRepo(t, h, "rlm_x:2026-10-26", port.Tx.AuditKeys)
	s, _ := open(t, h)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.AuditKeys().Create(ctx, port.DataKey{UserID: "o", WrappedKey: []byte{1}, KeyID: "k", CreatedAt: T0}); err != nil {
			return err
		}
		if _, err := tx.DataKeys().Get(ctx, "o"); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("audit key visible as a data key: %v", err)
		}
		return nil
	})
}

func testKeyRepo(t *testing.T, h Harness, u string, repo func(port.Tx) port.DataKeyRepo) {
	s, _ := open(t, h)
	k := port.DataKey{UserID: u, WrappedKey: []byte{1, 2, 3}, KeyID: "mk_1", CreatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		r := repo(tx)
		if err := r.Create(ctx, k); err != nil {
			return err
		}
		if err := r.Create(ctx, k); !errors.Is(err, errs.Conflict) {
			return fmt.Errorf("duplicate: want Conflict, got %v", err)
		}
		got, err := r.Get(ctx, u)
		if err != nil || !bytes.Equal(got.WrappedKey, k.WrappedKey) || got.KeyID != "mk_1" || !got.CreatedAt.Equal(T0) {
			return fmt.Errorf("dataKeys.Get = %+v, %v", got, err)
		}
		if err := r.Delete(ctx, u); err != nil {
			return err
		}
		if _, err := r.Get(ctx, u); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("after delete: want NotFound, got %v", err)
		}
		return r.Delete(ctx, u)
	})
}

func testDataKeysUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	u := id.New(id.User)
	ExactlyOneSucceeds(t, Concurrent(16, func(i int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.DataKeys().Create(ctx, port.DataKey{UserID: u, WrappedKey: []byte(fmt.Sprint(i)), KeyID: "k", CreatedAt: T0})
		})
	}))
}

func record(t *testing.T, s port.Storage, clk clock.Clock, realmID string, n int) {
	t.Helper()
	for i := range n {
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, clk, audit.Event{
				Type: "test.event", Result: audit.ResultSuccess, RealmID: realmID,
				Actor: audit.Actor{Type: "system"}, IP: "192.0.2.1", Details: map[string]any{"i": i},
			})
			return err
		})
	}
}

func testAuditChain(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := id.New(id.Realm)
	record(t, s, clk, r, 7)
	last, n, err := eventlog.Verify(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 || len(last) != 32 {
		t.Fatalf("Verify: n=%d", n)
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 3, 2)
		if err != nil || len(rs) != 2 || rs[0].Seq != 3 || rs[1].Seq != 4 {
			return fmt.Errorf("audit.Scan = %v, %v", rs, err)
		}
		e, err := audit.Unmarshal(rs[0].Payload)
		if err != nil || e.Type != "test.event" || e.RealmID != r || !e.Time.Equal(T0) {
			return fmt.Errorf("payload = %+v, %v", e, err)
		}
		l, err := tx.Audit().Last(ctx)
		if err != nil || l == nil || l.Seq != 7 || !bytes.Equal(l.Hash, last) {
			return fmt.Errorf("audit.Last = %v, %v", l, err)
		}
		return nil
	})
}

// 監査ログの1件を書き換えると、チェーンの検証で検出できる（roadmap M0 の完了条件）。
func testAuditTamperDetected(t *testing.T, h Harness) {
	if h.TamperAudit == nil {
		t.Skip("TamperAudit not provided")
	}
	s, clk := open(t, h)
	record(t, s, clk, id.New(id.Realm), 5)
	var rec audit.Record
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 3, 1)
		rec = rs[0]
		return err
	})
	forged := bytes.Replace(rec.Payload, []byte(`"result":"success"`), []byte(`"result":"failure"`), 1)
	if bytes.Equal(forged, rec.Payload) {
		t.Fatal("test bug: payload not changed")
	}
	h.TamperAudit(t, s, 3, forged)
	if _, _, err := eventlog.Verify(context.Background(), s); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("want ErrChainBroken, got %v", err)
	}
}

// 同時に追記してもチェーンが分岐しない（Last と Append が同じ Tx で直列化される）。
func testAuditConcurrentAppend(t *testing.T, h Harness) {
	s, clk := open(t, h)
	const workers, each = 8, 10
	errs := Concurrent(workers, func(int) error {
		for range each {
			err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
				_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "concurrent"})
				return err
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, n, err := eventlog.Verify(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if n != workers*each {
		t.Fatalf("n = %d, want %d", n, workers*each)
	}
}

func testOutbox(t *testing.T, h Harness) {
	s, _ := open(t, h)
	ids := []string{id.New(id.Outbox), id.New(id.Outbox), id.New(id.Outbox)}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		o := tx.Outbox()
		for i, x := range ids {
			if err := o.Add(ctx, port.OutboxMessage{ID: x, Topic: "t", Payload: []byte{byte(i)}, CreatedAt: T0.Add(time.Duration(i) * time.Second)}); err != nil {
				return err
			}
		}
		if err := o.Add(ctx, port.OutboxMessage{ID: id.New(id.Outbox), Topic: "other", CreatedAt: T0}); err != nil {
			return err
		}
		if err := o.Add(ctx, port.OutboxMessage{ID: ids[0], Topic: "t", CreatedAt: T0}); !errors.Is(err, errs.Conflict) {
			return fmt.Errorf("duplicate id: want Conflict, got %v", err)
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		o := tx.Outbox()
		p, err := o.Pending(ctx, "t", 2)
		if err != nil || len(p) != 2 || p[0].ID != ids[0] || p[1].ID != ids[1] || p[1].Payload[0] != 1 {
			return fmt.Errorf("outbox.Pending = %+v, %v", p, err)
		}
		if err := o.MarkDelivered(ctx, []string{ids[0], ids[1]}, T0.Add(time.Minute)); err != nil {
			return err
		}
		p, err = o.Pending(ctx, "t", 10)
		if err != nil || len(p) != 1 || p[0].ID != ids[2] {
			return fmt.Errorf("outbox.Pending after delivery = %+v, %v", p, err)
		}
		return nil
	})
}

type collectSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *collectSink) Emit(_ context.Context, es []audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, es...)
	return nil
}

func testOutboxRelay(t *testing.T, h Harness) {
	s, clk := open(t, h)
	record(t, s, clk, id.New(id.Realm), 5)
	sink := &collectSink{}
	r := &eventlog.Relay{Storage: s, Sink: sink, Clock: clk, Batch: 2}
	total := 0
	for {
		n, err := r.Flush(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		total += n
	}
	if total != 5 || len(sink.events) != 5 {
		t.Fatalf("delivered %d, sink has %d", total, len(sink.events))
	}
	for i, e := range sink.events {
		if e.IP != "" || e.UserAgent != "" {
			t.Fatalf("PII in external output: %+v", e)
		}
		// 外部側が末尾の削除を検出できるよう、チェーン上の位置を付けて出す。
		if e.Chain == nil || e.Chain.Seq != int64(i+1) || len(e.Chain.Hash) != 64 {
			t.Fatalf("chain ref missing or wrong: %+v", e.Chain)
		}
	}
}

// ---------------------------------------------------------------------------
// realm の分離

// IsolationCase は realm の分離の検査の1件。Seed で realm に1件以上のデータを入れ、
// Query が別の realm から見て返す件数が 0 であることを確かめる。
type IsolationCase struct {
	Name  string
	Seed  func(ctx context.Context, tx port.Tx, clk clock.Clock, realmID string) error
	Query func(ctx context.Context, tx port.Tx, realmID string) (int, error)
}

// IsolationCases は realm に属するデータを返すメソッドごとの検査。Repository を足したらここに足す。
var IsolationCases = append([]IsolationCase{
	{
		Name: "Audit.ListByRealm",
		Seed: func(ctx context.Context, tx port.Tx, clk clock.Clock, realmID string) error {
			_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "isolation", RealmID: realmID})
			return err
		},
		Query: func(ctx context.Context, tx port.Tx, realmID string) (int, error) {
			rs, err := tx.Audit().ListByRealm(ctx, realmID, 1, 1000)
			return len(rs), err
		},
	},
}, authnIsolationCases...)

// CheckRealmIsolation は cases を2つの realm で実行し、自分の realm では見え、別の realm では見えないことを確かめる。
func CheckRealmIsolation(t *testing.T, s port.Storage, clk clock.Clock, cases []IsolationCase) {
	a, b := newRealm("iso-a-"+id.New("x")[2:]), newRealm("iso-b-"+id.New("x")[2:])
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Realms().Create(ctx, a); err != nil {
			return err
		}
		return tx.Realms().Create(ctx, b)
	})
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			tx(t, s, func(ctx context.Context, tx port.Tx) error { return c.Seed(ctx, tx, clk, a.ID) })
			tx(t, s, func(ctx context.Context, tx port.Tx) error {
				own, err := c.Query(ctx, tx, a.ID)
				if err != nil {
					return err
				}
				if own == 0 {
					return fmt.Errorf("seeded data not visible in its own realm")
				}
				other, err := c.Query(ctx, tx, b.ID)
				if err != nil {
					return err
				}
				if other != 0 {
					return fmt.Errorf("%d rows leaked to another realm", other)
				}
				return nil
			})
		})
	}
}

func testRealmIsolation(t *testing.T, h Harness) {
	s, clk := open(t, h)
	CheckRealmIsolation(t, s, clk, IsolationCases)
}
