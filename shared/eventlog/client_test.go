package eventlog_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの IP と User-Agent（ADR 0063）。

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

func record(t *testing.T, s port.Storage, k *testkit.Kit, actor audit.Actor) audit.Event {
	t.Helper()
	var e audit.Event
	if err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		e, err = eventlog.Record(ctx, tx, k.Clock, audit.Event{Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: k.RealmID,
			Actor: actor, IP: "203.0.113.77", UserAgent: ua})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func open(t *testing.T, c *eventlog.ClientSealer, k *testkit.Kit, e audit.Event) (string, string, error) {
	t.Helper()
	var ip, agent string
	var err error
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		ip, agent, err = c.Open(ctx, tx, e)
		return nil
	})
	return ip, agent, err
}

func TestClientSealing(t *testing.T) {
	k := testkit.New(t)
	c := &eventlog.ClientSealer{Crypter: k.Crypter, Clock: k.Clock, Retention: 30 * 24 * time.Hour}
	s := c.Storage(k.Storage)
	u := k.SeedUser(t)
	alice := record(t, s, k, audit.Actor{Type: "user", ID: u.PublicID})
	anon := record(t, s, k, audit.Actor{Type: "anonymous"})

	// ペイロードには切り詰めた値だけを平文で置き、全文は client に暗号化して置く。全文は外部出力には出さない。
	if alice.IP != "203.0.113.0/24" || alice.UserAgent != "Chrome on Windows" || alice.Client == "" {
		t.Fatalf("event = %+v", alice)
	}
	if x := audit.External(alice); x.IP != alice.IP || x.UserAgent != alice.UserAgent || x.Client != "" {
		t.Fatalf("external = %+v", x)
	}
	for _, e := range []audit.Event{alice, anon} {
		if ip, agent, err := open(t, c, k, e); err != nil || ip != "203.0.113.77" || agent != ua {
			t.Fatalf("open %s = %q %q %v", e.Actor.Type, ip, agent, err)
		}
	}
	// 書き換えた client は読めない（別のイベントの暗号文の流用も）。
	moved := anon
	moved.Client = alice.Client
	if _, _, err := open(t, c, k, moved); err == nil {
		t.Fatal("moved client opened")
	}

	// 本人のデータ鍵を消すと、本人の全文だけが読めなくなる。
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.DataKeys().Delete(ctx, u.ID) })
	if _, _, err := open(t, c, k, alice); !errors.Is(err, eventlog.ErrClientUnreadable) {
		t.Fatalf("after shredding: %v", err)
	}
	if _, _, err := open(t, c, k, anon); err != nil {
		t.Fatalf("anonymous after shredding: %v", err)
	}
	// 削除したユーザーの名前で記録しても全文は残さない。
	if e := record(t, s, k, audit.Actor{Type: "user", ID: u.PublicID}); e.Client != "" || e.IP != "203.0.113.0/24" {
		t.Fatalf("shredded actor = %+v", e)
	}

	// 保持期間の後に日ごとの鍵を消し、その日の全文は誰のものも読めなくなる。
	sch := &eventlog.Scheduler{Storage: s, Clock: k.Clock, Handlers: map[string]eventlog.Handler{eventlog.EventClientKeyExpired: c.Expire}}
	k.Clock.Advance(30 * 24 * time.Hour)
	if n, err := sch.Fire(context.Background()); err != nil || n != 0 {
		t.Fatalf("fire before retention: %d %v", n, err)
	}
	k.Clock.Advance(24 * time.Hour)
	if n, err := sch.Fire(context.Background()); err != nil || n != 1 {
		t.Fatalf("fire: %d %v", n, err)
	}
	if _, _, err := open(t, c, k, anon); !errors.Is(err, eventlog.ErrClientUnreadable) {
		t.Fatalf("after retention: %v", err)
	}
	// チェーンはそのまま検証できる。
	if _, n, err := eventlog.Verify(context.Background(), k.Storage); err != nil || n < 4 {
		t.Fatalf("verify: %d %v", n, err)
	}
}

func TestRecordWithoutSealer(t *testing.T) {
	k := testkit.New(t)
	e := record(t, k.Storage, k, audit.Actor{Type: "anonymous"})
	if e.IP != "203.0.113.0/24" || e.UserAgent != "Chrome on Windows" || e.Client != "" {
		t.Fatalf("event = %+v", e)
	}
}
