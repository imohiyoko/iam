package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// downStorage は Tx がいつも失敗する保存先（一時的な障害）。
type downStorage struct{ port.Storage }

func (downStorage) Tx(context.Context, func(context.Context, port.Tx) error) error {
	return errors.New("storage down")
}

// 読めないメッセージは送らずに終え、保存先の一時的な失敗は、あきらめるまで残して次の送出でまた試す。
func TestLogoutDelivererRetriesTransientErrors(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewFake(now)
	d := &provider.LogoutDeliverer{Storage: downStorage{}, Clock: c, GiveUp: time.Hour}
	msgs := []port.OutboxMessage{
		{ID: "bad", Topic: provider.LogoutTopic, Payload: []byte("{"), CreatedAt: now},
		{ID: "ok", Topic: provider.LogoutTopic, Payload: []byte(`{}`), CreatedAt: now},
	}
	done, err := d.Deliver(context.Background(), msgs)
	if err != nil || !slices.Equal(done, []string{"bad"}) {
		t.Fatalf("done = %v, %v", done, err)
	}
	c.Advance(time.Hour)
	if done, err := d.Deliver(context.Background(), msgs[1:]); err != nil || !slices.Equal(done, []string{"ok"}) {
		t.Fatalf("after give up: %v, %v", done, err)
	}
}

// flakyStorage は連携先の読み出しだけが失敗し、outbox への書き込みは記録する保存先。fn が失敗すれば書き込みを捨てる
// （ロールバック）。failMark なら MarkDelivered が失敗する。
type flakyStorage struct {
	port.Storage
	added     *[]port.OutboxMessage
	delivered *[]string
	failMark  bool
}

type flakyTx struct {
	port.Tx
	out *recordingOutbox
}

type flakyClients struct{ port.ClientRepo }

type recordingOutbox struct {
	port.OutboxRepo
	added     []port.OutboxMessage
	delivered []string
	failMark  bool
}

func (s flakyStorage) Tx(ctx context.Context, fn func(context.Context, port.Tx) error) error {
	out := &recordingOutbox{failMark: s.failMark}
	if err := fn(ctx, flakyTx{out: out}); err != nil {
		return err
	}
	*s.added = append(*s.added, out.added...)
	*s.delivered = append(*s.delivered, out.delivered...)
	return nil
}
func (t flakyTx) Clients() port.ClientRepo { return flakyClients{} }
func (t flakyTx) Outbox() port.OutboxRepo  { return t.out }
func (flakyClients) Get(context.Context, string, string) (port.Client, error) {
	return port.Client{}, errors.New("db timeout")
}
func (o *recordingOutbox) Add(_ context.Context, m port.OutboxMessage) error {
	o.added = append(o.added, m)
	return nil
}
func (o *recordingOutbox) MarkDelivered(_ context.Context, ids []string, _ time.Time) error {
	if o.failMark {
		return errors.New("db timeout")
	}
	o.delivered = append(o.delivered, ids...)
	return nil
}

// 送れなかったものは outbox の末尾に積み直し（先頭に残して後ろを塞がない）、元のものは同じトランザクションで配送済みにする。
// あきらめるまでの時間は最初に積んだ時刻から数える。
func TestLogoutDelivererRequeuesFailures(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewFake(start)
	var added []port.OutboxMessage
	var delivered []string
	d := &provider.LogoutDeliverer{Storage: flakyStorage{added: &added, delivered: &delivered}, Clock: c, GiveUp: time.Hour}
	m := port.OutboxMessage{ID: "m1", Topic: provider.LogoutTopic, Payload: []byte(`{"realm_id":"r","client_id":"c"}`), CreatedAt: start}
	for i := range 2 {
		c.Advance(30 * time.Minute)
		done, err := d.Deliver(context.Background(), []port.OutboxMessage{m})
		if i == 1 {
			// 最初に積んでから1時間たったので、積み直さずにあきらめる。
			if err != nil || !slices.Equal(done, []string{m.ID}) || len(added) != 1 {
				t.Fatalf("give up: done = %v, %v, requeued %d", done, err, len(added))
			}
			break
		}
		if err != nil || len(done) != 0 || !slices.Equal(delivered, []string{m.ID}) {
			t.Fatalf("requeue: done = %v, %v, delivered %v", done, err, delivered)
		}
		if len(added) != 1 || added[0].ID == m.ID || added[0].Topic != provider.LogoutTopic || !added[0].CreatedAt.Equal(c.Now()) {
			t.Fatalf("requeued = %+v", added)
		}
		var x struct {
			ClientID string     `json:"client_id"`
			FirstAt  *time.Time `json:"first_at"`
		}
		if err := json.Unmarshal(added[0].Payload, &x); err != nil || x.ClientID != "c" || x.FirstAt == nil || !x.FirstAt.Equal(start) {
			t.Fatalf("requeued payload = %s", added[0].Payload)
		}
		m = added[0]
	}
}

// 元のメッセージを配送済みにできなければ、積み直しも残さない（同じものが2通り積まれない）。元のものは次の送出でまた試す。
func TestLogoutDelivererRequeueIsAtomic(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var added []port.OutboxMessage
	var delivered []string
	d := &provider.LogoutDeliverer{Storage: flakyStorage{added: &added, delivered: &delivered, failMark: true}, Clock: clock.NewFake(start), GiveUp: time.Hour}
	m := port.OutboxMessage{ID: "m1", Topic: provider.LogoutTopic, Payload: []byte(`{"realm_id":"r","client_id":"c"}`), CreatedAt: start}
	done, err := d.Deliver(context.Background(), []port.OutboxMessage{m})
	if err != nil || len(done) != 0 || len(added) != 0 || len(delivered) != 0 {
		t.Fatalf("done = %v, %v, added %d, delivered %v", done, err, len(added), delivered)
	}
}
