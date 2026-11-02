package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの照会とイベントの Webhook の購読（ADR 0100）の契約。

var auditQueryTests = []struct {
	name string
	fn   func(*testing.T, Harness)
}{
	{"AuditQuery", testAuditQuery},
	{"AuditQueryAfterTruncate", testAuditQueryAfterTruncate},
	{"EventSubscriptions", testEventSubscriptions},
	{"EventSubscriptionsDue", testEventSubscriptionsDue},
	{"AuditVerifyRange", testAuditVerifyRange},
	{"AuditVerifyRangeKeyed", testAuditVerifyRangeKeyed},
}

// seqs は返ったレコードの seq を並べる。
func seqs(rs []audit.Record) []int64 {
	out := make([]int64, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Seq)
	}
	return out
}

func testAuditQuery(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	events := []audit.Event{
		{Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "user", ID: "usr_a"}, OrgID: "org_1"}, // 1
		{Type: "login.failed", Result: audit.ResultFailure, RealmID: r, Actor: audit.Actor{Type: "user", ID: "usr_b"}},                    // 2
		{Type: "org.member_removed", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "user", ID: "usr_a"}, OrgID: "org_1",
			Details: map[string]any{"user_id": "usr_b", "membership_id": "mbr_1", "reason": "x_id_like"}}, // 3
		{Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: other, Actor: audit.Actor{Type: "user", ID: "usr_a"}, OrgID: "org_1",
			Details: map[string]any{"user_id": "usr_b"}}, // 4（別の realm）
		{Type: "login_link.issued", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "service_account", ID: "sva_1"},
			Details: map[string]any{"user_id": "usr_b", "count_id": 3}}, // 5
		{Type: "session.revoked", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "system"}}, // 6
	}
	ids := make([]string, len(events))
	for i, e := range events {
		clk.Advance(time.Minute)
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			got, err := eventlog.Record(ctx, tx, clk, e)
			ids[i] = got.ID
			return err
		})
	}
	all := port.AuditQuery{RealmID: r, Limit: 100}
	cases := []struct {
		name string
		q    port.AuditQuery
		want []int64
	}{
		{"all", all, []int64{6, 5, 3, 2, 1}},
		{"limit", port.AuditQuery{RealmID: r, Limit: 2}, []int64{6, 5}},
		{"before", port.AuditQuery{RealmID: r, BeforeSeq: 5, Limit: 2}, []int64{3, 2}},
		{"type", port.AuditQuery{RealmID: r, Filter: audit.Filter{Type: "login.succeeded"}, Limit: 100}, []int64{1}},
		// 前方一致は LIKE ではない（"_" をワイルドカードにしない）。
		{"type_prefix", port.AuditQuery{RealmID: r, Filter: audit.Filter{TypePrefix: "login."}, Limit: 100}, []int64{2, 1}},
		{"type_prefix_underscore", port.AuditQuery{RealmID: r, Filter: audit.Filter{TypePrefix: "login_"}, Limit: 100}, []int64{5}},
		{"result", port.AuditQuery{RealmID: r, Filter: audit.Filter{Result: audit.ResultFailure}, Limit: 100}, []int64{2}},
		{"actor_type", port.AuditQuery{RealmID: r, Filter: audit.Filter{ActorType: "service_account"}, Limit: 100}, []int64{5}},
		{"actor_id", port.AuditQuery{RealmID: r, Filter: audit.Filter{ActorID: "usr_a"}, Limit: 100}, []int64{3, 1}},
		{"org", port.AuditQuery{RealmID: r, Filter: audit.Filter{OrgID: "org_1"}, Limit: 100}, []int64{3, 1}},
		{"ref", port.AuditQuery{RealmID: r, Filter: audit.Filter{Ref: "usr_b"}, Limit: 100}, []int64{5, 3}},
		{"ref_other_key", port.AuditQuery{RealmID: r, Filter: audit.Filter{Ref: "mbr_1"}, Limit: 100}, []int64{3}},
		{"ref_not_id_key", port.AuditQuery{RealmID: r, Filter: audit.Filter{Ref: "x_id_like"}, Limit: 100}, []int64{}},
		{"combined", port.AuditQuery{RealmID: r, Filter: audit.Filter{ActorID: "usr_a", OrgID: "org_1", Type: "login.succeeded"}, Limit: 100}, []int64{1}},
		// 時刻は秒の単位で、境界の秒を含める（呼び出し側がペイロードで確かめ直す）。
		{"since", port.AuditQuery{RealmID: r, Filter: audit.Filter{Since: T0.Add(5 * time.Minute)}, Limit: 100}, []int64{6, 5}},
		{"until", port.AuditQuery{RealmID: r, Filter: audit.Filter{Until: T0.Add(2 * time.Minute)}, Limit: 100}, []int64{2, 1}},
		{"since_until", port.AuditQuery{RealmID: r, Filter: audit.Filter{Since: T0.Add(2 * time.Minute), Until: T0.Add(3 * time.Minute)}, Limit: 100},
			[]int64{3, 2}},
		{"other_realm", port.AuditQuery{RealmID: other, Limit: 100}, []int64{4}},
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, c := range cases {
			rs, err := tx.Audit().Query(ctx, c.q)
			if err != nil {
				return fmt.Errorf("%s: %w", c.name, err)
			}
			if got := seqs(rs); !slices.Equal(got, c.want) {
				return fmt.Errorf("%s: audit.Query = %v, want %v", c.name, got, c.want)
			}
			for _, x := range rs {
				if x.RealmID != c.q.RealmID || len(x.Hash) == 0 || len(x.PrevHash) == 0 || len(x.Payload) == 0 {
					return fmt.Errorf("%s: record %+v", c.name, x)
				}
			}
		}
		got, err := tx.Audit().GetByEventID(ctx, r, ids[2])
		if err != nil || got.Seq != 3 {
			return fmt.Errorf("audit.GetByEventID = %d, %v", got.Seq, err)
		}
		if _, err := tx.Audit().GetByEventID(ctx, other, ids[2]); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("audit.GetByEventID from another realm: want NotFound, got %v", err)
		}
		if _, err := tx.Audit().GetByEventID(ctx, r, id.NewExternal(id.Event)); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("audit.GetByEventID missing: want NotFound, got %v", err)
		}
		return nil
	})
	// 索引を足しても、チェーンの検証は変わらない。
	if _, n, err := eventlog.Verify(context.Background(), s); err != nil || n != 6 {
		t.Fatalf("eventlog.Verify = %d, %v", n, err)
	}
}

// 保持期間で切り詰めたレコードは、索引からも消える（ADR 0072、0100）。
func testAuditQueryAfterTruncate(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := id.New(id.Realm)
	var first string
	for i := range 4 {
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			e, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "user.updated", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "system"},
				Details: map[string]any{"user_id": "usr_x"}})
			if i == 0 {
				first = e.ID
			}
			return err
		})
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 2, 1)
		if err != nil {
			return err
		}
		return tx.Audit().Truncate(ctx, audit.Checkpoint{Seq: 2, Hash: rs[0].Hash, At: T0})
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Query(ctx, port.AuditQuery{RealmID: r, Filter: audit.Filter{Ref: "usr_x"}, Limit: 10})
		if err != nil || !slices.Equal(seqs(rs), []int64{4, 3}) {
			return fmt.Errorf("audit.Query after truncation = %v, %v", seqs(rs), err)
		}
		if _, err := tx.Audit().GetByEventID(ctx, r, first); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("audit.GetByEventID of a truncated event: want NotFound, got %v", err)
		}
		return nil
	})
	// 切り詰めた後も、続きを書いて照会できる。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "user.updated", RealmID: r, Details: map[string]any{"user_id": "usr_x"}})
		return err
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Query(ctx, port.AuditQuery{RealmID: r, Filter: audit.Filter{Ref: "usr_x"}, Limit: 10})
		if err != nil || !slices.Equal(seqs(rs), []int64{5, 4, 3}) {
			return fmt.Errorf("audit.Query after append = %v, %v", seqs(rs), err)
		}
		return nil
	})
}

func newEventSub(realmID string, at time.Time) port.EventSubscription {
	return port.EventSubscription{ID: id.NewExternal(id.EventSubscription), RealmID: realmID, URL: "https://hooks.example.com/iam",
		EventTypes: []string{"login.", "user.deleted"}, PII: "omit", Enabled: true, SecretCiphertext: []byte{1, 2, 3}, CreatedBy: "usr_x",
		CreatedAt: at, UpdatedAt: at, EventSubscriptionDelivery: port.EventSubscriptionDelivery{CursorSeq: 7}}
}

func testEventSubscriptions(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	a, b := newEventSub(r, T0.Add(time.Minute)), newEventSub(r, T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, x := range []port.EventSubscription{a, b} {
			if err := tx.EventSubscriptions().Create(ctx, x); err != nil {
				return err
			}
		}
		if err := tx.EventSubscriptions().Create(ctx, a); !errors.Is(err, errs.Conflict) {
			return fmt.Errorf("duplicate: want Conflict, got %v", err)
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		got, err := tx.EventSubscriptions().Get(ctx, r, a.ID)
		if err != nil || got.URL != a.URL || !slices.Equal(got.EventTypes, a.EventTypes) || got.PII != "omit" || !got.Enabled ||
			string(got.SecretCiphertext) != string(a.SecretCiphertext) || got.CursorSeq != 7 || got.CreatedBy != "usr_x" ||
			!got.CreatedAt.Equal(a.CreatedAt) || got.NextAttemptAt != nil || got.LastDeliveredAt != nil {
			return fmt.Errorf("Get = %+v, %v", got, err)
		}
		if _, err := tx.EventSubscriptions().Get(ctx, other, a.ID); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("Get from another realm: want NotFound, got %v", err)
		}
		list, err := tx.EventSubscriptions().List(ctx, r)
		if err != nil || len(list) != 2 || list[0].ID != b.ID || list[1].ID != a.ID {
			return fmt.Errorf("List = %+v, %v", list, err)
		}
		a.URL, a.EventTypes, a.PII, a.Enabled, a.SecretCiphertext, a.UpdatedAt = "https://other.example.com/", []string{}, "pseudonymize", false, []byte{9}, T0.Add(time.Hour)
		a.CursorSeq = 1000 // Update は配送の状態を変えない
		if err := tx.EventSubscriptions().Update(ctx, a); err != nil {
			return err
		}
		got, err = tx.EventSubscriptions().Get(ctx, r, a.ID)
		if err != nil || got.URL != a.URL || len(got.EventTypes) != 0 || got.PII != "pseudonymize" || got.Enabled || string(got.SecretCiphertext) != "\x09" ||
			!got.UpdatedAt.Equal(a.UpdatedAt) || got.CursorSeq != 7 {
			return fmt.Errorf("Get after Update = %+v, %v", got, err)
		}
		next, at := T0.Add(time.Minute), T0.Add(2*time.Minute)
		if err := tx.EventSubscriptions().SetDelivery(ctx, r, a.ID, port.EventSubscriptionDelivery{CursorSeq: 20, Failures: 2, NextAttemptAt: &next,
			LastError: "status_500", LastDeliveredAt: &at}); err != nil {
			return err
		}
		// カーソルは戻さない。
		if err := tx.EventSubscriptions().SetDelivery(ctx, r, a.ID, port.EventSubscriptionDelivery{CursorSeq: 10, Failures: 3, NextAttemptAt: &next,
			LastError: "timeout", LastDeliveredAt: &at}); err != nil {
			return err
		}
		got, err = tx.EventSubscriptions().Get(ctx, r, a.ID)
		if err != nil || got.CursorSeq != 20 || got.Failures != 3 || got.NextAttemptAt == nil || !got.NextAttemptAt.Equal(next) || got.LastError != "timeout" ||
			got.LastDeliveredAt == nil || !got.LastDeliveredAt.Equal(at) || got.URL != a.URL {
			return fmt.Errorf("Get after SetDelivery = %+v, %v", got, err)
		}
		for _, err := range []error{
			tx.EventSubscriptions().Update(ctx, port.EventSubscription{ID: a.ID, RealmID: other}),
			tx.EventSubscriptions().SetDelivery(ctx, other, a.ID, port.EventSubscriptionDelivery{}),
			tx.EventSubscriptions().Delete(ctx, other, a.ID),
		} {
			if !errors.Is(err, errs.NotFound) {
				return fmt.Errorf("from another realm: want NotFound, got %v", err)
			}
		}
		if err := tx.EventSubscriptions().Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if _, err := tx.EventSubscriptions().Get(ctx, r, a.ID); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("Get after Delete: want NotFound, got %v", err)
		}
		return nil
	})
	// 数え上げと片付け（フィーチャーの無効化）。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for range 2 {
			if err := tx.EventSubscriptions().Create(ctx, newEventSub(other, T0)); err != nil {
				return err
			}
		}
		if n, err := tx.EventSubscriptions().Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("Count = %d, %v", n, err)
		}
		ids, err := tx.EventSubscriptions().Purge(ctx, 2)
		if err != nil || len(ids) != 2 {
			return fmt.Errorf("Purge(2) = %v, %v", ids, err)
		}
		ids, err = tx.EventSubscriptions().Purge(ctx, 10)
		if err != nil || len(ids) != 1 {
			return fmt.Errorf("Purge = %v, %v", ids, err)
		}
		if n, err := tx.EventSubscriptions().Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("Count after Purge = %d, %v", n, err)
		}
		return nil
	})
}

func testEventSubscriptionsDue(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	now := T0.Add(time.Hour)
	early, late, future := now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Minute)
	fresh, waitedLong, waited, notYet, off := newEventSub(r1, T0), newEventSub(r2, T0), newEventSub(r1, T0), newEventSub(r2, T0), newEventSub(r1, T0)
	waitedLong.NextAttemptAt, waited.NextAttemptAt, notYet.NextAttemptAt = &early, &late, &future
	off.Enabled = false
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, x := range []port.EventSubscription{waited, notYet, off, waitedLong, fresh} {
			if err := tx.EventSubscriptions().Create(ctx, x); err != nil {
				return err
			}
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		due, err := tx.EventSubscriptions().Due(ctx, now, 10)
		if err != nil {
			return err
		}
		var got []string
		for _, d := range due {
			got = append(got, d.ID)
		}
		if want := []string{fresh.ID, waitedLong.ID, waited.ID}; !slices.Equal(got, want) {
			return fmt.Errorf("Due = %v, want %v", got, want)
		}
		if due, err := tx.EventSubscriptions().Due(ctx, now, 1); err != nil || len(due) != 1 || due[0].ID != fresh.ID {
			return fmt.Errorf("Due(1) = %+v, %v", due, err)
		}
		return nil
	})
}

// isoEventID・isoSubID は分離の検査で入れたもの（別の realm から ID で引いても見えないことを確かめる）。
var isoEventID, isoSubID string

var auditQueryIsolationCases = []IsolationCase{
	{
		Name: "Audit.Query+GetByEventID",
		Seed: func(ctx context.Context, tx port.Tx, clk clock.Clock, realmID string) error {
			e, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "isolation", RealmID: realmID, OrgID: "org_iso",
				Details: map[string]any{"user_id": "usr_iso"}})
			isoEventID = e.ID
			return err
		},
		Query: func(ctx context.Context, tx port.Tx, realmID string) (int, error) {
			n := 0
			for _, f := range []audit.Filter{{}, {OrgID: "org_iso"}, {Ref: "usr_iso"}, {Type: "isolation"}} {
				rs, err := tx.Audit().Query(ctx, port.AuditQuery{RealmID: realmID, Filter: f, Limit: 100})
				if err != nil {
					return 0, err
				}
				n += len(rs)
			}
			if _, err := tx.Audit().GetByEventID(ctx, realmID, isoEventID); err == nil {
				n++
			} else if !errors.Is(err, errs.NotFound) {
				return 0, err
			}
			return n, nil
		},
	},
	{
		Name: "EventSubscriptions.Get+List",
		Seed: func(ctx context.Context, tx port.Tx, clk clock.Clock, realmID string) error {
			sub := newEventSub(realmID, clk.Now())
			isoSubID = sub.ID
			return tx.EventSubscriptions().Create(ctx, sub)
		},
		Query: func(ctx context.Context, tx port.Tx, realmID string) (int, error) {
			list, err := tx.EventSubscriptions().List(ctx, realmID)
			if err != nil {
				return 0, err
			}
			n := len(list)
			if _, err := tx.EventSubscriptions().Get(ctx, realmID, isoSubID); err == nil {
				n++
			} else if !errors.Is(err, errs.NotFound) {
				return 0, err
			}
			return n, nil
		},
	},
}

// 範囲の検証は、範囲の中の書き換えを位置と理由つきで返し、範囲の外の書き換えには影響されない。
func testAuditVerifyRange(t *testing.T, h Harness) {
	s, clk := open(t, h)
	record(t, s, clk, id.New(id.Realm), 6)
	ctx := context.Background()
	res, err := eventlog.VerifyRange(ctx, s, 0, 0)
	if err != nil || res.Broken != nil || !res.Anchored || res.FromSeq != 1 || res.ToSeq != 6 || res.HeadSeq != 6 || res.LastHash == nil {
		t.Fatalf("whole chain = %+v, %v", res, err)
	}
	// 途中から：先頭に繋がらない（Anchored でない）が、PrevHash は前の範囲の LastHash と一致する。
	head, err := eventlog.VerifyRange(ctx, s, 1, 3)
	if err != nil || head.Broken != nil || head.ToSeq != 3 {
		t.Fatalf("head = %+v, %v", head, err)
	}
	tail, err := eventlog.VerifyRange(ctx, s, 4, 100)
	if err != nil || tail.Broken != nil || tail.Anchored || tail.ToSeq != 6 || !bytes.Equal(tail.PrevHash, head.LastHash) {
		t.Fatalf("tail = %+v, %v", tail, err)
	}
	if _, err := eventlog.VerifyRange(ctx, s, 1, eventlog.MaxVerifyRange+1); err != nil {
		t.Fatalf("range clipped to head: %v", err)
	}
	if h.TamperAudit == nil {
		return
	}
	var rec audit.Record
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 5, 1)
		rec = rs[0]
		return err
	})
	forged := bytes.Replace(rec.Payload, []byte(`"result":"success"`), []byte(`"result":"failure"`), 1)
	if bytes.Equal(forged, rec.Payload) {
		t.Fatal("test bug: payload not changed")
	}
	h.TamperAudit(t, s, 5, forged)
	res, err = eventlog.VerifyRange(ctx, s, 0, 0)
	if err != nil || res.Broken == nil || res.Broken.Seq != 5 || res.Broken.Reason != audit.BrokenHash || res.LastHash != nil {
		t.Fatalf("tampered = %+v, %v", res, err)
	}
	if !errors.Is(res.Broken, audit.ErrChainBroken) {
		t.Fatal("BrokenError does not unwrap to ErrChainBroken")
	}
	if res, err := eventlog.VerifyRange(ctx, s, 1, 4); err != nil || res.Broken != nil {
		t.Fatalf("range before tamper = %+v, %v", res, err)
	}
}

// 範囲の検証は監査の鍵（ADR 0086）で鍵付きのレコードを確かめ、鍵付きの後の鍵なしと、鍵の無い検証を理由つきで返す。
func testAuditVerifyRangeKeyed(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := id.New(id.Realm)
	record(t, s, clk, r, 2)
	keyed := (&eventlog.ClientSealer{Clock: clk, AuditKeys: auditKeys{id: "ak_1", unkeyed: 2}}).Storage(s)
	for range 3 {
		tx(t, keyed, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "test.keyed", Result: audit.ResultSuccess, RealmID: r, Actor: audit.Actor{Type: "system"}})
			return err
		})
	}
	ctx := context.Background()
	if res, err := eventlog.VerifyRange(ctx, keyed, 0, 0); err != nil || res.Broken != nil || res.ToSeq != 5 {
		t.Fatalf("keyed = %+v, %v", res, err)
	}
	if res, err := eventlog.VerifyRange(ctx, keyed, 4, 5); err != nil || res.Broken != nil || res.Anchored {
		t.Fatalf("keyed tail = %+v, %v", res, err)
	}
	if res, err := eventlog.VerifyRange(ctx, s, 0, 0); err != nil || res.Broken == nil || res.Broken.Seq != 3 || res.Broken.Reason != audit.BrokenKeyUnavailable {
		t.Fatalf("without keys = %+v, %v", res, err)
	}
	strict := (&eventlog.ClientSealer{Clock: clk, AuditKeys: auditKeys{id: "ak_1"}}).Storage(s)
	if res, err := eventlog.VerifyRange(ctx, strict, 0, 0); err != nil || res.Broken == nil || res.Broken.Seq != 1 || res.Broken.Reason != audit.BrokenUnkeyed {
		t.Fatalf("strict = %+v, %v", res, err)
	}
}
