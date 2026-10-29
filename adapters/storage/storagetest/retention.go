package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 保持期間（design.md 6.5、9.6、ADR 0072）の契約。

var retentionTests = []struct {
	name string
	fn   func(*testing.T, Harness)
}{
	{"AuditTruncate", testAuditTruncate},
	{"RetentionDeletes", testRetentionDeletes},
	{"RetentionSweep", testRetentionSweep},
}

// 切り詰めた後もチェックポイントから検証でき、チェーンは続きから伸びる。
func testAuditTruncate(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := id.New(id.Realm)
	record(t, s, clk, r, 6)
	var third audit.Record
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil || cp != nil {
			return fmt.Errorf("audit.Checkpoint before truncation = %+v, %v", cp, err)
		}
		rs, err := tx.Audit().Scan(ctx, 3, 1)
		if err != nil {
			return err
		}
		third = rs[0]
		return tx.Audit().Truncate(ctx, audit.Checkpoint{Seq: 3, Hash: third.Hash, At: T0.Add(time.Hour)})
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil || cp == nil || cp.Seq != 3 || !bytes.Equal(cp.Hash, third.Hash) || !cp.At.Equal(T0.Add(time.Hour)) {
			return fmt.Errorf("audit.Checkpoint = %+v, %v", cp, err)
		}
		rs, err := tx.Audit().Scan(ctx, 1, 10)
		if err != nil || len(rs) != 3 || rs[0].Seq != 4 {
			return fmt.Errorf("audit.Scan after truncation = %d records, %v", len(rs), err)
		}
		rs, err = tx.Audit().ListByRealm(ctx, r, 1, 10)
		if err != nil || len(rs) != 3 || rs[0].Seq != 4 {
			return fmt.Errorf("audit.ListByRealm after truncation = %d records, %v", len(rs), err)
		}
		return nil
	})
	record(t, s, clk, r, 1)
	last, n, err := eventlog.Verify(context.Background(), s)
	if err != nil || n != 7 || len(last) != 32 {
		t.Fatalf("Verify after truncation: n=%d, %v", n, err)
	}
	// 2回目はチェックポイントを置き換える。取り消せばチェックポイントも戻る。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 5, 1)
		if err != nil {
			return err
		}
		return tx.Audit().Truncate(ctx, audit.Checkpoint{Seq: 5, Hash: rs[0].Hash, At: T0.Add(2 * time.Hour)})
	})
	if err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if err := tx.Audit().Truncate(ctx, audit.Checkpoint{Seq: 6, Hash: []byte("x"), At: T0}); err != nil {
			return err
		}
		return errRollback
	}); !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil || cp == nil || cp.Seq != 5 {
			return fmt.Errorf("audit.Checkpoint after rollback = %+v, %v", cp, err)
		}
		rs, err := tx.Audit().Scan(ctx, 1, 10)
		if err != nil || len(rs) != 2 || rs[0].Seq != 6 {
			return fmt.Errorf("audit.Scan after rollback = %d records, %v", len(rs), err)
		}
		return nil
	})
	if _, n, err := eventlog.Verify(context.Background(), s); err != nil || n != 7 {
		t.Fatalf("Verify after second truncation: n=%d, %v", n, err)
	}
}

var errRollback = errors.New("rollback")

func testRetentionDeletes(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	cutoff := T0.Add(48 * time.Hour)
	// 期限切れ・失効済み（cutoff より前）は消え、生きているものと cutoff 以降に失効したものは残る。
	expired, revoked, alive, recent := newSession(r, "u1", T0), newSession(other, "u2", T0), newSession(r, "u3", T0), newSession(r, "u4", T0)
	revoked.ExpiresAt, alive.ExpiresAt, recent.ExpiresAt = T0.Add(90*24*time.Hour), T0.Add(90*24*time.Hour), T0.Add(90*24*time.Hour)
	revoked.RevokedAt, recent.RevokedAt = ptr(T0.Add(time.Hour)), ptr(cutoff.Add(time.Hour))
	outIDs := []string{id.New(id.Outbox), id.New(id.Outbox), id.New(id.Outbox)}
	old, late, pending := newScheduled(r, "a", T0), newScheduled(other, "b", T0), newScheduled(r, "c", T0.Add(time.Hour))
	e1, e2, e3 := newEmail(r, "u1", "i1"), newEmail(r, "u3", "i3"), newEmail(other, "u2", "i2")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, x := range []port.Session{expired, revoked, alive, recent} {
			if err := tx.Sessions().Create(ctx, x); err != nil {
				return err
			}
		}
		for i, x := range outIDs {
			if err := tx.Outbox().Add(ctx, port.OutboxMessage{ID: x, Topic: "t", Payload: []byte{byte(i)}, CreatedAt: T0}); err != nil {
				return err
			}
		}
		if err := tx.Outbox().MarkDelivered(ctx, outIDs[:1], T0.Add(time.Hour)); err != nil {
			return err
		}
		if err := tx.Outbox().MarkDelivered(ctx, outIDs[1:2], cutoff.Add(time.Hour)); err != nil {
			return err
		}
		for _, x := range []port.ScheduledEvent{old, late, pending} {
			if err := tx.ScheduledEvents().Schedule(ctx, x); err != nil {
				return err
			}
		}
		if _, err := tx.ScheduledEvents().MarkFired(ctx, r, old.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if _, err := tx.ScheduledEvents().MarkFired(ctx, other, late.ID, cutoff.Add(time.Hour)); err != nil {
			return err
		}
		for _, e := range []port.UserEmail{e1, e2, e3} {
			if err := tx.Emails().Create(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		// 件数の上限を守る。
		if n, err := tx.Sessions().DeleteEnded(ctx, cutoff, 1); err != nil || n != 1 {
			return fmt.Errorf("sessions.DeleteEnded(limit 1) = %d, %v", n, err)
		}
		if n, err := tx.Sessions().DeleteEnded(ctx, cutoff, 10); err != nil || n != 1 {
			return fmt.Errorf("sessions.DeleteEnded = %d, %v", n, err)
		}
		for _, x := range []port.Session{expired, revoked} {
			if err := notFound("ended session", func() error { _, err := tx.Sessions().Get(ctx, x.RealmID, x.ID); return err }()); err != nil {
				return err
			}
		}
		for _, x := range []port.Session{alive, recent} {
			if _, err := tx.Sessions().Get(ctx, x.RealmID, x.ID); err != nil {
				return fmt.Errorf("kept session: %w", err)
			}
		}
		if n, err := tx.Outbox().DeleteDelivered(ctx, cutoff, 10); err != nil || n != 1 {
			return fmt.Errorf("outbox.DeleteDelivered = %d, %v", n, err)
		}
		// 消した後も、未配送のものは送れる。配送済みのものは二重に配送済みにならない。
		p, err := tx.Outbox().Pending(ctx, "t", 10)
		if err != nil || len(p) != 1 || p[0].ID != outIDs[2] {
			return fmt.Errorf("outbox.Pending after delete = %+v, %v", p, err)
		}
		if err := tx.Outbox().MarkDelivered(ctx, outIDs, cutoff); err != nil {
			return err
		}
		if n, err := tx.ScheduledEvents().DeleteFired(ctx, cutoff, 10); err != nil || n != 1 {
			return fmt.Errorf("scheduled.DeleteFired = %d, %v", n, err)
		}
		due, err := tx.ScheduledEvents().Due(ctx, cutoff, 10)
		if err != nil || len(due) != 1 || due[0].ID != pending.ID {
			return fmt.Errorf("scheduled.Due after delete = %+v, %v", due, err)
		}
		if ok, err := tx.ScheduledEvents().MarkFired(ctx, other, late.ID, cutoff); err != nil || ok {
			return fmt.Errorf("scheduled.MarkFired on kept fired event = %v, %v", ok, err)
		}
		// 暗号文は realm ごとに消え、インデックスは残る。
		if n, err := tx.Emails().ClearCiphertexts(ctx, r, 1); err != nil || n != 1 {
			return fmt.Errorf("emails.ClearCiphertexts(limit 1) = %d, %v", n, err)
		}
		if n, err := tx.Emails().ClearCiphertexts(ctx, r, 10); err != nil || n != 1 {
			return fmt.Errorf("emails.ClearCiphertexts = %d, %v", n, err)
		}
		if n, err := tx.Emails().ClearCiphertexts(ctx, r, 10); err != nil || n != 0 {
			return fmt.Errorf("emails.ClearCiphertexts again = %d, %v", n, err)
		}
		for _, e := range []port.UserEmail{e1, e2} {
			got, err := tx.Emails().GetByIndex(ctx, r, e.Index)
			if err != nil || len(got.Ciphertext) != 0 || got.ID != e.ID {
				return fmt.Errorf("cleared email = %+v, %v", got, err)
			}
		}
		got, err := tx.Emails().GetByIndex(ctx, other, e3.Index)
		if err != nil || !bytes.Equal(got.Ciphertext, e3.Ciphertext) {
			return fmt.Errorf("email in another realm = %+v, %v", got, err)
		}
		return nil
	})
}

// eventlog.Retention は期間を過ぎた監査ログを切り詰め、audit.truncated を記録する。最新のレコードは消さない。
func testRetentionSweep(t *testing.T, h Harness) {
	s, clk := open(t, h)
	r := id.New(id.Realm)
	record(t, s, clk, r, 4)
	clk.Advance(10 * 24 * time.Hour)
	record(t, s, clk, r, 2)
	// 期限の切れたサービスアカウントのトークン（ADR 0074）。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, exp := range []time.Time{T0.Add(time.Hour), clk.Now().Add(time.Hour)} {
			if err := tx.ServiceAccounts().CreateToken(ctx, port.ServiceAccountToken{ID: id.New(id.SAToken), RealmID: r, ServiceAccountID: "sva_x",
				CredentialID: "sac_x", Hash: []byte("h"), CreatedAt: T0, ExpiresAt: exp}); err != nil {
				return err
			}
		}
		return nil
	})
	ret := &eventlog.Retention{Storage: s, Clock: clk, RealmID: r, Audit: 5 * 24 * time.Hour, Ended: 24 * time.Hour, Batch: 2}
	n, err := ret.Sweep(context.Background())
	if err != nil || n.Audit != 4 || n.Tokens != 1 {
		t.Fatalf("Sweep = %+v, %v", n, err)
	}
	if _, last, err := eventlog.Verify(context.Background(), s); err != nil || last != 7 {
		t.Fatalf("Verify after sweep: last=%d, %v", last, err)
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil || cp == nil || cp.Seq != 4 {
			return fmt.Errorf("audit.Checkpoint = %+v, %v", cp, err)
		}
		l, err := tx.Audit().Last(ctx)
		if err != nil {
			return err
		}
		e, err := audit.Unmarshal(l.Payload)
		if err != nil || e.Type != eventlog.EventAuditTruncated || fmt.Sprint(e.Details["through_seq"]) != "4" || fmt.Sprint(e.Details["removed"]) != "4" {
			return fmt.Errorf("truncated event = %+v, %v", e, err)
		}
		return nil
	})
	// 2回目は消すものが無い（audit.truncated は新しいので残る）。
	if n, err := ret.Sweep(context.Background()); err != nil || n.Audit != 0 {
		t.Fatalf("second Sweep = %+v, %v", n, err)
	}
	// すべてが古くなっても、最新のレコードは残る。
	clk.Advance(30 * 24 * time.Hour)
	// 前回の audit.truncated も古いので、2回に分けて消える（5〜6、次に 7）。
	if n, err := ret.Sweep(context.Background()); err != nil || n.Audit != 3 {
		t.Fatalf("Sweep of all = %+v, %v", n, err)
	}
	if _, last, err := eventlog.Verify(context.Background(), s); err != nil || last != 9 {
		t.Fatalf("Verify after full sweep: last=%d, %v", last, err)
	}
}
