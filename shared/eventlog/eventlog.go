// Package eventlog は監査ログの記録・検証と、outbox からの外部出力を行う（design.md 6章）。
package eventlog

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// TopicAudit は監査ログの外部出力の outbox のトピック。
const TopicAudit = "audit"

// Record は監査ログに1件を追記し、外部出力用に outbox へ積む。
// 呼び出し側の操作と同じトランザクションで呼ぶ（操作とログが必ず揃う）。
// IP と User-Agent は切り詰めて残し、全文は ClientSealer を通した Storage なら暗号化して残す（ADR 0063）。
func Record(ctx context.Context, tx port.Tx, clk clock.Clock, e audit.Event) (audit.Event, error) {
	if e.ID == "" {
		e.ID = id.NewExternal(id.Event)
	}
	if e.Time.IsZero() {
		e.Time = clk.Now()
	}
	if e.Version == 0 {
		e.Version = audit.SchemaVersion
	}
	if err := protectClient(ctx, tx, &e); err != nil {
		return e, err
	}
	last, err := tx.Audit().Last(ctx)
	if err != nil {
		return e, err
	}
	keyID, key, err := chainKey(ctx, tx)
	if err != nil {
		return e, err
	}
	rec, err := audit.NextKeyed(last, e, keyID, key)
	if err != nil {
		return e, err
	}
	if err := tx.Audit().Append(ctx, rec); err != nil {
		return e, err
	}
	x := audit.External(e)
	x.Chain = &audit.ChainRef{Seq: rec.Seq, Hash: hex.EncodeToString(rec.Hash)}
	ext, err := json.Marshal(x)
	if err != nil {
		return e, err
	}
	err = tx.Outbox().Add(ctx, port.OutboxMessage{ID: e.ID, Topic: TopicAudit, Payload: ext, CreatedAt: e.Time})
	return e, err
}

// chainKey は tx で書くレコードの監査の鍵を返す（ADR 0086）。ClientSealer を通した Storage で、鍵を置いていれば鍵付き。
func chainKey(ctx context.Context, tx port.Tx) (string, []byte, error) {
	st, ok := tx.(sealingTx)
	if !ok || st.c.AuditKeys == nil {
		return "", nil, nil
	}
	kid, err := st.c.AuditKeys.CurrentAuditKeyID(ctx)
	if err != nil || kid == "" {
		return "", nil, err
	}
	key, err := st.c.AuditKeys.AuditKey(ctx, kid)
	return kid, key, err
}

// Verify はチェーンを先頭（保持期間で切り詰めた後はチェックポイント。design.md 6.5）から検証する。
// 最後のハッシュと最後の seq を返す。s が ClientSealer を通した Storage なら、その監査の鍵で鍵付きのレコードも確かめる。
func Verify(ctx context.Context, s port.Storage) (last []byte, n int64, err error) {
	var keys port.AuditKeyStore
	if ss, ok := s.(sealingStorage); ok {
		keys = ss.c.AuditKeys
	}
	return VerifyWith(ctx, s, keys)
}

// VerifyWith は監査の鍵 keys（nil なら鍵なしのレコードだけ）でチェーンを検証する。
func VerifyWith(ctx context.Context, s port.Storage, keys port.AuditKeyStore) (last []byte, n int64, err error) {
	const page = 500
	c := audit.Chain{Prev: audit.Genesis, Next: 1}
	if keys != nil {
		c.Keys = func(kid string) ([]byte, error) { return keys.AuditKey(ctx, kid) }
		// 鍵を置いていれば、鍵なしで許す範囲より後は鍵付きでなければならない（ADR 0086）。
		kid, err := keys.CurrentAuditKeyID(ctx)
		if err != nil {
			return nil, 0, err
		}
		if kid != "" {
			until, err := keys.AuditUnkeyedUntil(ctx)
			if err != nil {
				return nil, 0, err
			}
			c.KeyedFrom = until + 1
		}
	}
	if err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if cp != nil {
			c.Prev, c.Next, c.Keyed = cp.Hash, cp.Seq+1, cp.KeyID != ""
		}
		return err
	}); err != nil {
		return nil, 0, err
	}
	for {
		var rs []audit.Record
		err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			rs, err = tx.Audit().Scan(ctx, c.Next, page)
			return err
		})
		if err != nil {
			return nil, 0, err
		}
		if err := c.Verify(rs); err != nil {
			return nil, 0, err
		}
		if len(rs) < page {
			return c.Prev, c.Next - 1, nil
		}
	}
}

// Relay は outbox のメッセージを外部に送る（少なくとも1回）。受け取る側は ID で重複排除する。
//
// 既定では監査イベント（TopicAudit）を Sink に送る。Deliver を指定すると Topic のメッセージを Deliver に渡す
// （通知など）。Deliver は送れたメッセージの ID を返す。
type Relay struct {
	Storage  port.Storage
	Sink     port.EventSink
	Topic    string
	Deliver  func(ctx context.Context, msgs []port.OutboxMessage) (delivered []string, err error)
	Clock    clock.Clock
	Interval time.Duration
	Batch    int
	Log      *slog.Logger
}

func (r *Relay) topic() string {
	if r.Topic == "" {
		return TopicAudit
	}
	return r.Topic
}

// Run は ctx が終わるまで送出を繰り返す。
func (r *Relay) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if _, err := r.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger().Warn("outbox relay failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush は未配送の分を1回送る。送った件数を返す。
func (r *Relay) Flush(ctx context.Context) (int, error) {
	var pending []port.OutboxMessage
	err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		pending, err = tx.Outbox().Pending(ctx, r.topic(), r.batch())
		return err
	})
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	if r.Deliver != nil {
		ids, derr := r.Deliver(ctx, pending)
		if len(ids) > 0 {
			if err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				return tx.Outbox().MarkDelivered(ctx, ids, r.Clock.Now())
			}); err != nil {
				return 0, err
			}
		}
		return len(ids), derr
	}
	events := make([]audit.Event, 0, len(pending))
	ids := make([]string, 0, len(pending))
	for _, m := range pending {
		ids = append(ids, m.ID)
		e, err := audit.Unmarshal(m.Payload)
		if err != nil {
			// 読めないメッセージで送出全体を止めない。監査ログ本体（チェーン）には残っており、
			// 外部側は chain.seq の欠けで検出できる。
			r.logger().Error("skipping unreadable outbox message", "id", m.ID, "error", err)
			continue
		}
		events = append(events, e)
	}
	// 送ってから配送済みにする。途中で落ちれば次回また送る（少なくとも1回）。
	if err := r.Sink.Emit(ctx, events); err != nil {
		return 0, err
	}
	err = r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.Outbox().MarkDelivered(ctx, ids, r.Clock.Now())
	})
	return len(ids), err
}

func (r *Relay) logger() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

func (r *Relay) batch() int {
	if r.Batch <= 0 {
		return 100
	}
	return r.Batch
}
