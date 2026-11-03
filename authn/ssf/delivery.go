package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// 配送。push（RFC 8935）は全 realm で1つの配送のループが送り、poll（RFC 8936）は受信側の要求の中で監査ログを読んで待ちに積む。
// どちらも監査ログを outbox にし、ストリームごとの位置から読む（少なくとも1回。jti は送り直しても同じ）。

const (
	sendTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 16
	lease            = time.Minute
	maxBackoff       = time.Hour
	firstRetry       = 10 * time.Second
	duePerTick       = 10
	readBatch        = 100
	// MaxPollEvents は1回の poll で返す SET の数の上限。
	MaxPollEvents = 100
)

// IssuerOf は realm の iss（SET の iss と、iss_sub の対象の iss）。空なら送らない。
type IssuerOf func(ctx context.Context, tx port.Tx, realmID string) (string, error)

// Deliverer は push のストリームに SET を送る（全 realm で1つ）。
type Deliverer struct {
	Storage     port.Storage
	Transmitter *Transmitter
	Issuer      IssuerOf
	Clock       clock.Clock
	Interval    time.Duration
	Log         *slog.Logger
	// HTTP は送信に使うクライアント（テスト用）。nil なら公開のアドレスにだけつなぐクライアント（イベントの Webhook と同じ）。
	HTTP *http.Client
}

func (d *Deliverer) logger() *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}

func (d *Deliverer) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return eventsub.PublicClient(d.Transmitter != nil && d.Transmitter.AllowPrivateNetworks)
}

// Run は ctx が終わるまで配送を繰り返す。
func (d *Deliverer) Run(ctx context.Context) {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		if _, err := d.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
			d.logger().Warn("ssf delivery failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush は送る時刻の来たストリームを取り（lease の間はほかのインスタンスが取らない）、それぞれ続きを送る。送った SET の数を返す。
func (d *Deliverer) Flush(ctx context.Context) (int, error) {
	var due []port.SSFStream
	err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if due, err = tx.SSFStreams().DuePush(ctx, d.Clock.Now(), duePerTick); err != nil {
			return err
		}
		until := d.Clock.Now().Add(lease)
		for _, s := range due {
			st := s.SSFStreamDelivery
			st.NextAttemptAt = &until
			if err := tx.SSFStreams().SetDelivery(ctx, s.RealmID, s.ID, st); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, s := range due {
		sent, err := d.deliver(ctx, s)
		n += sent
		if err != nil && first == nil {
			first = err
		}
	}
	return n, first
}

// deliver は1つのストリームの続きを送る。送れなかった SET の前までの位置を書き、倍々に待つ。
func (d *Deliverer) deliver(ctx context.Context, s port.SSFStream) (int, error) {
	var auth string
	var sets []signed
	var last int64
	err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		iss, err := d.Issuer(ctx, tx, s.RealmID)
		if err != nil || iss == "" {
			return err
		}
		if auth, err = d.Transmitter.Authorization(ctx, tx, s); err != nil {
			return err
		}
		rs, err := tx.Audit().ListByRealm(ctx, s.RealmID, s.CursorSeq+1, readBatch)
		if err != nil || len(rs) == 0 {
			return err
		}
		last = rs[len(rs)-1].Seq
		sets, err = d.Transmitter.prepare(ctx, tx, s, iss, rs, func(r audit.Record, err error) {
			d.logger().Error("ssf: skipping unreadable audit record", "seq", r.Seq, "error", err)
		})
		return err
	})
	if err != nil {
		return 0, err
	}
	now := d.Clock.Now()
	st := s.SSFStreamDelivery
	poll := now.Add(d.Interval)
	if last == 0 {
		st.NextAttemptAt = &poll
		return 0, d.setDelivery(ctx, s, st, nil)
	}
	var done []signed
	rejected := ""
	for i, x := range sets {
		res := d.send(ctx, s, auth, x.SET)
		if !res.retry {
			if res.err != "" {
				// 受信側が SET を受けなかった（400）。送り直しても同じなので飛ばす（RFC 8935 2.3）。
				d.logger().Warn("ssf: receiver rejected a SET", "stream", s.ID, "jti", x.JTI, "error", res.err)
				rejected = "rejected_" + res.err
			}
			done = append(done, x)
			continue
		}
		st.Failures++
		wait := min(firstRetry<<min(st.Failures-1, 20), maxBackoff)
		next := now.Add(wait)
		st.NextAttemptAt, st.LastError = &next, res.err
		// 送れなかった SET のレコードの前まで進める（同じレコードの前の SET も送り直す。jti が同じなので受信側で除ける）。
		st.CursorSeq = max(st.CursorSeq, x.Seq-1)
		if i > 0 {
			st.LastDeliveredAt = &now
		}
		return len(done), d.setDelivery(ctx, s, st, done)
	}
	if len(sets) > 0 {
		st.LastDeliveredAt = &now
	}
	st.CursorSeq, st.Failures, st.LastError = last, 0, rejected
	st.NextAttemptAt = &poll
	if last-s.CursorSeq >= readBatch {
		st.NextAttemptAt = nil
	}
	return len(done), d.setDelivery(ctx, s, st, done)
}

func (d *Deliverer) setDelivery(ctx context.Context, s port.SSFStream, st port.SSFStreamDelivery, done []signed) error {
	return d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		for _, x := range done {
			if err := forget(ctx, tx, s, x); err != nil {
				return err
			}
		}
		return tx.SSFStreams().SetDelivery(ctx, s.RealmID, s.ID, st)
	})
}

type sendResult struct {
	retry bool
	err   string
}

// send は1つの SET を POST する（RFC 8935 2）。2xx は届いた。400 は受信側が SET を受けなかった（送り直さない）。
// それ以外（401・403・429・5xx・接続の失敗）は送り直す。転送には従わない。
func (d *Deliverer) send(ctx context.Context, s port.SSFStream, auth, set string) sendResult {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.EndpointURL, strings.NewReader(set))
	if err != nil {
		return sendResult{retry: true, err: eventsub.ErrConnection}
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := d.client().Do(req) // #nosec G704 -- 送り先は受信側が登録し、公開のアドレスに限る（eventsub.PublicClient）
	if err != nil {
		return sendResult{retry: true, err: errorCode(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode/100 == 2:
		return sendResult{}
	case resp.StatusCode == http.StatusBadRequest:
		var e struct {
			Err string `json:"err"`
		}
		_ = json.Unmarshal(body, &e)
		code := "invalid_request"
		switch e.Err {
		case "invalid_key", "invalid_issuer", "invalid_audience", "authentication_failed", "access_denied":
			code = e.Err
		}
		return sendResult{err: code}
	}
	return sendResult{retry: true, err: "status_" + strconv.Itoa(resp.StatusCode)}
}

func errorCode(err error) string {
	switch {
	case strings.Contains(err.Error(), "not a public address"):
		return eventsub.ErrAddressNotAllowed
	case errors.Is(err, context.DeadlineExceeded):
		return eventsub.ErrTimeout
	}
	return eventsub.ErrConnection
}

// PollRequest は poll の要求（RFC 8936 2.4）。
type PollRequest struct {
	MaxEvents         *int                `json:"maxEvents,omitempty"`
	ReturnImmediately bool                `json:"returnImmediately,omitempty"`
	Ack               []string            `json:"ack,omitempty"`
	SetErrs           map[string]SetError `json:"setErrs,omitempty"`
}

// SetError は受信側が受けなかった SET の理由（RFC 8936 2.4）。
type SetError struct {
	Err         string `json:"err"`
	Description string `json:"description,omitempty"`
}

// PollResponse は poll の応答（RFC 8936 2.5）。
type PollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable,omitempty"`
}

// Poll は確認（ack）と誤り（setErrs）の SET を待ちから外し、監査ログの続きを待ちに積んで、最大 maxEvents 件を返す
// （既定・上限は MaxPollEvents）。長いポーリングはしない（returnImmediately に関わらず、すぐに返す）。paused・disabled の
// ストリームは積まず、返さない。
func (t *Transmitter) Poll(ctx context.Context, tx port.Tx, realmID, issuer string, c Caller, streamID string, req PollRequest,
	log *slog.Logger) (PollResponse, error) {
	out := PollResponse{Sets: map[string]string{}}
	s, err := own(ctx, tx, realmID, c, streamID)
	if err != nil {
		return out, err
	}
	if s.DeliveryMethod != port.SSFDeliveryPoll {
		return out, ErrStreamNotFound
	}
	if len(req.Ack) > 1000 || len(req.SetErrs) > 1000 {
		return out, invalid("too many ack or setErrs")
	}
	limit := MaxPollEvents
	if req.MaxEvents != nil {
		if *req.MaxEvents < 0 {
			return out, invalid("maxEvents")
		}
		limit = min(*req.MaxEvents, MaxPollEvents)
	}
	ack := append([]string{}, req.Ack...)
	for jti := range req.SetErrs {
		ack = append(ack, jti)
	}
	if len(ack) > 0 {
		if _, err := tx.SSFStreams().AckPollEvents(ctx, realmID, s.ID, ack); err != nil {
			return out, err
		}
	}
	if len(req.SetErrs) > 0 {
		codes := map[string]int{}
		for _, e := range req.SetErrs {
			code := e.Err
			if len(code) > 64 {
				code = code[:64]
			}
			codes[code]++
		}
		if err := t.record(ctx, tx, AuditPollErrors, s, c, map[string]any{"errors": codes}); err != nil {
			return out, err
		}
	}
	if s.Status != port.SSFStatusEnabled {
		return out, nil
	}
	if err := t.fill(ctx, tx, &s, issuer, log); err != nil {
		return out, err
	}
	if limit == 0 {
		return out, nil
	}
	evs, err := tx.SSFStreams().ListPollEvents(ctx, realmID, s.ID, limit+1)
	if err != nil {
		return out, err
	}
	if len(evs) > limit {
		evs, out.MoreAvailable = evs[:limit], true
	}
	for _, e := range evs {
		out.Sets[e.JTI] = e.SET
	}
	if !out.MoreAvailable {
		// 監査ログにまだ続きがあれば、次の poll で取れることを知らせる。
		rs, err := tx.Audit().ListByRealm(ctx, realmID, s.CursorSeq+1, 1)
		if err != nil {
			return out, err
		}
		out.MoreAvailable = len(rs) > 0
	}
	return out, nil
}

// fill は poll のストリームの位置から監査ログを読み、待ちの SET の上限まで積んで位置を進める（s の位置も書き換える）。
func (t *Transmitter) fill(ctx context.Context, tx port.Tx, s *port.SSFStream, issuer string, log *slog.Logger) error {
	if issuer == "" {
		return nil
	}
	for range 10 {
		pending, err := tx.SSFStreams().CountPollEvents(ctx, s.RealmID, s.ID)
		if err != nil || pending >= MaxPendingPoll {
			return err
		}
		rs, err := tx.Audit().ListByRealm(ctx, s.RealmID, s.CursorSeq+1, min(readBatch, MaxPendingPoll-pending))
		if err != nil || len(rs) == 0 {
			return err
		}
		sets, err := t.prepare(ctx, tx, *s, issuer, rs, func(r audit.Record, err error) {
			if log != nil {
				log.ErrorContext(ctx, "ssf: skipping unreadable audit record", "seq", r.Seq, "error", err)
			}
		})
		if err != nil {
			return err
		}
		now := t.Clock.Now()
		evs := make([]port.SSFPollEvent, 0, len(sets))
		for _, x := range sets {
			evs = append(evs, port.SSFPollEvent{RealmID: s.RealmID, StreamID: s.ID, JTI: x.JTI, Seq: x.Seq, SET: x.SET, CreatedAt: now})
			if err := forget(ctx, tx, *s, x); err != nil {
				return err
			}
		}
		if err := tx.SSFStreams().AddPollEvents(ctx, evs); err != nil {
			return err
		}
		st := s.SSFStreamDelivery
		st.CursorSeq = rs[len(rs)-1].Seq
		if len(sets) > 0 {
			st.LastDeliveredAt = &now
		}
		if err := tx.SSFStreams().SetDelivery(ctx, s.RealmID, s.ID, st); err != nil {
			return err
		}
		s.SSFStreamDelivery = st
		if len(rs) < readBatch {
			return nil
		}
	}
	return nil
}
