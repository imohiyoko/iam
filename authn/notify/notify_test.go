package notify_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

type sink struct{ got []string }

func (s *sink) Notify(_ context.Context, n port.Notification) error {
	s.got = append(s.got, n.ID)
	return nil
}

// 秘密の期限が過ぎた通知は届けずに配送済みにする（使えないリンクやコードを送らない）。
func TestDelivererSkipsExpired(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	past, future := clk.Now().Add(-time.Second), clk.Now().Add(time.Minute)
	msg := func(id string, exp *time.Time) port.OutboxMessage {
		b, err := json.Marshal(port.Notification{ID: id, ExpiresAt: exp, HasSecret: exp != nil})
		if err != nil {
			t.Fatal(err)
		}
		return port.OutboxMessage{ID: "m-" + id, Payload: b}
	}
	s := &sink{}
	done, err := notify.Deliverer(s, clk, nil)(context.Background(),
		[]port.OutboxMessage{msg("expired", &past), msg("live", &future), msg("plain", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 3 {
		t.Fatalf("done: %v", done)
	}
	if len(s.got) != 2 || s.got[0] != "live" || s.got[1] != "plain" {
		t.Fatalf("delivered: %v", s.got)
	}
}
