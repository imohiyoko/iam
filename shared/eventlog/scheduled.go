package eventlog

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Schedule は時刻の境界の出来事（停止の開始・終了、有効期間の始まり・終わり）を at に予約する（design.md 4.8）。
// 時刻を過ぎると Scheduler が監査ログ（と outbox）に出す。ref は取り消しの単位。details に個人情報を入れない。
func Schedule(ctx context.Context, tx port.Tx, clk clock.Clock, realmID, ref, typ string, at time.Time, details map[string]any) error {
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return tx.ScheduledEvents().Schedule(ctx, port.ScheduledEvent{
		ID: id.New(id.Event), RealmID: realmID, Ref: ref, Type: typ, Payload: b, FireAt: at, CreatedAt: clk.Now(),
	})
}

// Handler は予約の時刻を過ぎた出来事の後始末（Org の削除、期限の過ぎた招待の鍵の削除など。4.10）。
// 発火の記録と監査ログと同じトランザクションで呼ぶ。エラーを返せば全体を取り消し、次の回にやり直す。
// details は予約したときの詳細で、Handler が足した鍵も監査ログに載る。
type Handler func(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error

// Scheduler は予約の時刻を過ぎた出来事を監査ログに出す。出るのは時刻の後（Interval の分は遅れうる）だが、
// アクセスの可否はこの処理に依らず時刻から計算する（4.8）。発火済みの記録と監査ログは同じトランザクションで書くので、
// 複数のインスタンスで動かしても1回だけ出る。
type Scheduler struct {
	Storage  port.Storage
	Clock    clock.Clock
	Interval time.Duration
	Batch    int
	Log      *slog.Logger
	// Handlers は出来事の種類ごとの後始末。無い種類は監査ログに出すだけ。
	Handlers map[string]Handler
}

// Run は ctx が終わるまで発火を繰り返す。
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		if _, err := s.Fire(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger().Warn("scheduled events failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Fire は時刻を過ぎた分を1回出す。出した件数を返す。1件の失敗で残りを止めない（最初の誤りを返す）。
func (s *Scheduler) Fire(ctx context.Context) (int, error) {
	var due []port.ScheduledEvent
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		due, err = tx.ScheduledEvents().Due(ctx, s.Clock.Now(), s.batch())
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, e := range due {
		fired := false
		err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ok, err := tx.ScheduledEvents().MarkFired(ctx, e.RealmID, e.ID, s.Clock.Now())
			if err != nil || !ok {
				return err
			}
			var details map[string]any
			if len(e.Payload) > 0 {
				if err := json.Unmarshal(e.Payload, &details); err != nil {
					return err
				}
			}
			if details == nil {
				details = map[string]any{}
			}
			details["scheduled_at"] = e.FireAt.UTC().Format(time.RFC3339Nano)
			if h := s.Handlers[e.Type]; h != nil {
				if err := h(ctx, tx, e, details); err != nil {
					return err
				}
			}
			_, err = Record(ctx, tx, s.Clock, audit.Event{
				Type: e.Type, Result: audit.ResultSuccess, RealmID: e.RealmID, Actor: audit.Actor{Type: "system"}, Details: details,
			})
			fired = err == nil
			return err
		})
		if err != nil {
			s.logger().Warn("scheduled event failed", "id", e.ID, "type", e.Type, "error", err)
			if first == nil {
				first = err
			}
			continue
		}
		if fired {
			n++
		}
	}
	return n, first
}

func (s *Scheduler) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

func (s *Scheduler) batch() int {
	if s.Batch <= 0 {
		return 100
	}
	return s.Batch
}
