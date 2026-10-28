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

// flakyStorage は連携先の読み出しだけが失敗し、outbox への追加は記録する保存先。
type flakyStorage struct {
	port.Storage
	added *[]port.OutboxMessage
}

type flakyTx struct {
	port.Tx
	added *[]port.OutboxMessage
}

type flakyClients struct{ port.ClientRepo }

type recordingOutbox struct {
	port.OutboxRepo
	added *[]port.OutboxMessage
}

func (s flakyStorage) Tx(ctx context.Context, fn func(context.Context, port.Tx) error) error {
	return fn(ctx, flakyTx{added: s.added})
}
func (t flakyTx) Clients() port.ClientRepo { return flakyClients{} }
func (t flakyTx) Outbox() port.OutboxRepo  { return recordingOutbox{added: t.added} }
func (flakyClients) Get(context.Context, string, string) (port.Client, error) {
	return port.Client{}, errors.New("db timeout")
}
func (o recordingOutbox) Add(_ context.Context, m port.OutboxMessage) error {
	*o.added = append(*o.added, m)
	return nil
}

// 送れなかったものは outbox の末尾に積み直し（先頭に残して後ろを塞がない）、最初に積んだ時刻からあきらめるまでを数える。
func TestLogoutDelivererRequeuesFailures(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewFake(start)
	var added []port.OutboxMessage
	d := &provider.LogoutDeliverer{Storage: flakyStorage{added: &added}, Clock: c, GiveUp: time.Hour}
	m := port.OutboxMessage{ID: "m1", Topic: provider.LogoutTopic, Payload: []byte(`{"realm_id":"r","client_id":"c"}`), CreatedAt: start}
	for i := range 2 {
		c.Advance(30 * time.Minute)
		done, err := d.Deliver(context.Background(), []port.OutboxMessage{m})
		if err != nil || !slices.Equal(done, []string{m.ID}) {
			t.Fatalf("attempt %d: done = %v, %v", i, done, err)
		}
		if i == 1 {
			// 最初に積んでから1時間たったので、積み直さずにあきらめる。
			if len(added) != 1 {
				t.Fatalf("requeued after give up: %d", len(added))
			}
			break
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
