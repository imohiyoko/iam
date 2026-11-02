package eventsub

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	// SignatureHeader は署名（EventSink の Webhook・フローフックと同じ形）。
	SignatureHeader = "X-IAM-Signature"
	// SubscriptionHeader は購読の ID。
	SubscriptionHeader = "X-IAM-Subscription"
	// TestEventType はテスト送信のイベントの種類（監査ログには載らない）。
	TestEventType = "event_subscription.test"

	sendTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 16
	// lease は配送を始めた購読を、ほかのインスタンスが取らない時間（送り終えれば書き直す）。
	lease = time.Minute
	// maxBackoff は失敗が続いたときの待ちの上限。
	maxBackoff = time.Hour
	firstRetry = 10 * time.Second
	duePerTick = 10
)

// 送れなかった理由（LastError、テスト送信の結果）。個人情報や URL を含めない。
const (
	ErrAddressNotAllowed = "address_not_allowed"
	ErrTimeout           = "timeout"
	ErrConnection        = "connection_failed"
)

var errNotPublic = errors.New("eventsub: destination is not a public address")

// Result は1回の送信の結果。
type Result struct {
	Delivered bool
	Status    int
	Error     string
}

// Deliverer は購読ごとの位置から監査ログを読み、宛先に送る（全 realm で1つ。ADR 0100）。
type Deliverer struct {
	Storage  port.Storage
	Service  *Service
	Clock    clock.Clock
	Interval time.Duration
	// Batch は1回の要求で送るイベントの数の上限。
	Batch int
	Log   *slog.Logger
	// HTTP は送信に使うクライアント（テスト用）。nil なら公開のアドレスにだけつなぐクライアント。
	HTTP *http.Client
}

func (d *Deliverer) batch() int {
	if d.Batch <= 0 || d.Batch > 100 {
		return 100
	}
	return d.Batch
}

func (d *Deliverer) logger() *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}

// Run は ctx が終わるまで配送を繰り返す。
func (d *Deliverer) Run(ctx context.Context) {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		if _, err := d.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
			d.logger().Warn("event subscription delivery failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush は送る時刻の来た購読を取り（ほかのインスタンスが同時に送らないよう、lease の間は取れなくする）、それぞれ1回送る。
// 送ったイベントの数を返す。
func (d *Deliverer) Flush(ctx context.Context) (int, error) {
	var due []port.EventSubscription
	err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if due, err = tx.EventSubscriptions().Due(ctx, d.Clock.Now(), duePerTick); err != nil {
			return err
		}
		until := d.Clock.Now().Add(lease)
		for _, s := range due {
			st := s.EventSubscriptionDelivery
			st.NextAttemptAt = &until
			if err := tx.EventSubscriptions().SetDelivery(ctx, s.RealmID, s.ID, st); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// 1つの購読の失敗で、ほかの購読を止めない（失敗した購読は lease の後にまた取る）。
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

// deliver は1つの購読の続きを送り、配送の状態を書く。
func (d *Deliverer) deliver(ctx context.Context, sub port.EventSubscription) (int, error) {
	var secret []byte
	var rs []audit.Record
	err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if secret, err = d.Service.Secret(ctx, tx, sub); err != nil {
			return err
		}
		rs, err = tx.Audit().ListByRealm(ctx, sub.RealmID, sub.CursorSeq+1, d.batch())
		return err
	})
	if err != nil {
		return 0, err
	}
	now := d.Clock.Now()
	st := sub.EventSubscriptionDelivery
	poll := now.Add(d.Interval)
	if len(rs) == 0 {
		st.NextAttemptAt = &poll
		return 0, d.setDelivery(ctx, sub, st)
	}
	events := make([]audit.Event, 0, len(rs))
	for _, r := range rs {
		e, err := audit.Unmarshal(r.Payload)
		if err != nil {
			// 読めないレコードで配送全体を止めない（チェーンの検証で検出できる）。
			d.logger().Error("skipping unreadable audit record", "seq", r.Seq, "error", err)
			continue
		}
		if !Wants(sub, e.Type) {
			continue
		}
		x := audit.External(e)
		x.Chain = &audit.ChainRef{Seq: r.Seq, Hash: hex.EncodeToString(r.Hash)}
		events = append(events, x)
	}
	if len(events) > 0 {
		res := d.Send(ctx, sub, secret, events)
		if !res.Delivered {
			st.Failures++
			wait := min(firstRetry<<min(st.Failures-1, 20), maxBackoff)
			next := now.Add(wait)
			st.NextAttemptAt, st.LastError = &next, res.Error
			if st.LastError == "" {
				st.LastError = "status_" + strconv.Itoa(res.Status)
			}
			return 0, d.setDelivery(ctx, sub, st)
		}
		st.LastDeliveredAt = &now
	}
	st.CursorSeq, st.Failures, st.LastError = rs[len(rs)-1].Seq, 0, ""
	// 1回で送り切れなければ、続きをすぐに送る。
	st.NextAttemptAt = &poll
	if len(rs) == d.batch() {
		st.NextAttemptAt = nil
	}
	return len(events), d.setDelivery(ctx, sub, st)
}

func (d *Deliverer) setDelivery(ctx context.Context, sub port.EventSubscription, st port.EventSubscriptionDelivery) error {
	return d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.EventSubscriptions().SetDelivery(ctx, sub.RealmID, sub.ID, st)
	})
}

// Test はテスト用のイベント（監査ログには載らない）を1件送る。
func (d *Deliverer) Test(ctx context.Context, sub port.EventSubscription, secret []byte) Result {
	e := audit.Event{Version: audit.SchemaVersion, ID: id.NewExternal(id.Event), Time: d.Clock.Now().UTC(), Type: TestEventType,
		Result: audit.ResultSuccess, RealmID: sub.RealmID, Actor: audit.Actor{Type: "system"}, Details: map[string]any{"subscription_id": sub.ID}}
	return d.Send(ctx, sub, secret, []audit.Event{e})
}

// Send はイベントを {"events": [...]} にして POST する。2xx なら送れた。転送には従わない。
func (d *Deliverer) Send(ctx context.Context, sub port.EventSubscription, secret []byte, events []audit.Event) Result {
	for i := range events {
		events[i] = redact(sub, secret, events[i])
	}
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return Result{Error: ErrConnection}
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return Result{Error: ErrConnection}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, Sign(secret, d.Clock.Now(), body))
	req.Header.Set(SubscriptionHeader, sub.ID)
	resp, err := d.client().Do(req) // #nosec G704 -- 宛先は運営者が登録し、公開のアドレスに限る
	if err != nil {
		return Result{Error: errorCode(err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return Result{Delivered: resp.StatusCode/100 == 2, Status: resp.StatusCode}
}

// Sign は署名のヘッダーの値（t=<UNIX 秒>,v1=<hex(HMAC-SHA-256(鍵, "<t>." + 本文))>）。
func Sign(secret []byte, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// redact は全文の暗号文を外し、切り詰めた IP と User-Agent の大分類を購読の設定に従って出さないか仮名にする。
// 仮名の鍵は署名の鍵から作る（購読ごとに異なり、鍵を作り直すと仮名も変わる）。
func redact(sub port.EventSubscription, secret []byte, e audit.Event) audit.Event {
	e.Client = ""
	if sub.PII != PIIPseudonymize {
		e.IP, e.UserAgent = "", ""
		return e
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("iam event subscription pseudonym"))
	key := m.Sum(nil)
	e.IP, e.UserAgent = pseudonym(key, e.IP), pseudonym(key, e.UserAgent)
	return e
}

// pseudonym は "p_" + HMAC-SHA-256 の先頭 16 バイトの16進（EventSink の仮名化と同じ形）。空なら空。
func pseudonym(key []byte, v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return "p_" + hex.EncodeToString(m.Sum(nil)[:16])
}

func errorCode(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errNotPublic):
		return ErrAddressNotAllowed
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ErrTimeout
	}
	return ErrConnection
}

func (d *Deliverer) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return PublicClient(d.Service != nil && d.Service.AllowPrivateNetworks)
}

// PublicClient は、つなぐ先のアドレスが公開のアドレスでなければ断るクライアント（名前の解決の後、実際につなぐアドレスで確かめる。
// 解決とつなぐ間に向き先を変えられても通らない）。プロキシは使わない。転送には従わない。allowPrivate なら確かめない。
func PublicClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errNotPublic
			}
			a, err := netip.ParseAddr(host)
			if err != nil || !oauth.PublicAddr(a) {
				return fmt.Errorf("%w: %s", errNotPublic, host)
			}
			return nil
		}
	}
	t := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: sendTimeout, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: t, Timeout: sendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
