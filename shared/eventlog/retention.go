package eventlog

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// EventAuditTruncated は監査ログを保持期間で切り詰めた出来事。チェックポイント（最後に消したレコード）を載せ、SIEM にも送る（design.md 6.5）。
const EventAuditTruncated = "audit.truncated"

// auditPage は監査ログの切り詰めで1つのトランザクションに読む件数。
// 切り詰めの間は監査の追記が待つため、1回のトランザクションを短く保つ。
const auditPage = 1000

// Retention は保持期間を過ぎたデータを消す（design.md 6.5、9.6、ADR 0072）。
type Retention struct {
	Storage port.Storage
	Clock   clock.Clock
	// RealmID は audit.truncated を記録する realm（チェーンは全 realm で1本）。
	RealmID string
	// Audit は監査ログの保持期間。0 なら切り詰めない。
	Audit time.Duration
	// Ended は失効・期限切れのセッション、配送済みの outbox、発火済みの予約イベント、期限の切れたサービスアカウントのトークンを残す期間。0 なら消さない。
	Ended time.Duration
	// IndexOnlyRealms はメールの最小化モード（index_only）の realm。残っているアドレスの暗号文を消す。
	IndexOnlyRealms []string
	Interval        time.Duration
	Batch           int
	Log             *slog.Logger
}

// Swept は1回の掃除で消した件数。
type Swept struct {
	Audit, Sessions, Outbox, Scheduled, Emails, Tokens int
}

// Run は ctx が終わるまで掃除を繰り返す。
func (r *Retention) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if n, err := r.Sweep(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger().Warn("retention sweep failed", "error", err)
		} else if n != (Swept{}) {
			r.logger().Info("retention sweep", "audit", n.Audit, "sessions", n.Sessions, "outbox", n.Outbox, "scheduled", n.Scheduled, "emails", n.Emails,
				"tokens", n.Tokens)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep は期間を過ぎた分を消し切るまで、Batch 件ずつのトランザクションで消す。
func (r *Retention) Sweep(ctx context.Context) (Swept, error) {
	var n Swept
	now := r.Clock.Now()
	if r.Audit > 0 {
		for {
			k, err := r.truncateAudit(ctx, now.Add(-r.Audit))
			n.Audit += k
			if err != nil || k == 0 {
				if err != nil {
					return n, err
				}
				break
			}
		}
	}
	if r.Ended > 0 {
		before := now.Add(-r.Ended)
		steps := []struct {
			count *int
			del   func(ctx context.Context, tx port.Tx) (int, error)
		}{
			{&n.Sessions, func(ctx context.Context, tx port.Tx) (int, error) {
				return tx.Sessions().DeleteEnded(ctx, before, r.batch())
			}},
			{&n.Outbox, func(ctx context.Context, tx port.Tx) (int, error) {
				return tx.Outbox().DeleteDelivered(ctx, before, r.batch())
			}},
			{&n.Scheduled, func(ctx context.Context, tx port.Tx) (int, error) {
				return tx.ScheduledEvents().DeleteFired(ctx, before, r.batch())
			}},
			{&n.Tokens, func(ctx context.Context, tx port.Tx) (int, error) {
				return tx.ServiceAccounts().DeleteExpiredTokens(ctx, before, r.batch())
			}},
		}
		for _, s := range steps {
			if err := r.drain(ctx, s.count, s.del); err != nil {
				return n, err
			}
		}
	}
	for _, realmID := range r.IndexOnlyRealms {
		if err := r.drain(ctx, &n.Emails, func(ctx context.Context, tx port.Tx) (int, error) {
			return tx.Emails().ClearCiphertexts(ctx, realmID, r.batch())
		}); err != nil {
			return n, err
		}
	}
	return n, nil
}

// drain は del が Batch 件より少なく消すまで繰り返す。
func (r *Retention) drain(ctx context.Context, count *int, del func(ctx context.Context, tx port.Tx) (int, error)) error {
	for {
		var k int
		if err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			k, err = del(ctx, tx)
			return err
		}); err != nil {
			return err
		}
		*count += k
		if k < r.batch() {
			return nil
		}
	}
}

// truncateAudit は cutoff より前のレコードを先頭から最大 auditPage 件消し、消した件数を返す。
// 時刻が cutoff 以降のレコードに当たったらそこで止める（時刻の逆転があっても、新しいものを消さない）。
// 最新のレコードは消さない（チェーンの続きを Last から求めるため）。消したら audit.truncated を同じトランザクションで記録する。
func (r *Retention) truncateAudit(ctx context.Context, cutoff time.Time) (int, error) {
	removed := 0
	err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		removed = 0
		last, err := tx.Audit().Last(ctx)
		if err != nil || last == nil {
			return err
		}
		from := int64(1)
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil {
			return err
		}
		if cp != nil {
			from = cp.Seq + 1
		}
		rs, err := tx.Audit().Scan(ctx, from, auditPage)
		if err != nil {
			return err
		}
		var through *audit.Record
		for i := range rs {
			if rs[i].Seq >= last.Seq {
				break
			}
			e, err := audit.Unmarshal(rs[i].Payload)
			if err != nil {
				return err
			}
			if !e.Time.Before(cutoff) {
				break
			}
			through = &rs[i]
		}
		if through == nil {
			return nil
		}
		next := audit.Checkpoint{Seq: through.Seq, Hash: through.Hash, At: r.Clock.Now()}
		if err := tx.Audit().Truncate(ctx, next); err != nil {
			return err
		}
		removed = int(through.Seq - from + 1)
		_, err = Record(ctx, tx, r.Clock, audit.Event{
			Type: EventAuditTruncated, Result: audit.ResultSuccess, RealmID: r.RealmID, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"through_seq": through.Seq, "through_hash": hex.EncodeToString(through.Hash), "removed": removed,
				"before": cutoff.UTC().Format(time.RFC3339Nano)},
		})
		return err
	})
	return removed, err
}

func (r *Retention) logger() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

func (r *Retention) batch() int {
	if r.Batch <= 0 {
		return 100
	}
	return r.Batch
}
