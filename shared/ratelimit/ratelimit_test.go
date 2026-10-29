package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// counter は Incr だけを持つ EphemeralStore（shared/ は adapters/ を import しない）。
type counter struct {
	port.EphemeralStore
	n map[string]int64
}

func newCounter() *counter { return &counter{n: map[string]int64{}} }

func (c *counter) Incr(_ context.Context, key string, _ time.Duration) (int64, error) {
	c.n[key]++
	return c.n[key], nil
}

func TestFixedWindow(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC))
	l := &ratelimit.Limiter{Cache: newCounter(), Clock: clk, Window: time.Minute, Limit: 3}
	ctx := context.Background()
	for i := range 3 {
		if err := l.Allow(ctx, "ip:a"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	err := l.Allow(ctx, "ip:a")
	ex, ok := errors.AsType[*ratelimit.ExceededError](err)
	if !ok || !ex.First || ex.RetryAfter != 30*time.Second {
		t.Fatalf("4th request: %v (%+v)", err, ex)
	}
	if ex, _ := errors.AsType[*ratelimit.ExceededError](l.Allow(ctx, "ip:a")); ex == nil || ex.First {
		t.Fatalf("5th request must be limited and not first: %+v", ex)
	}
	// 別のキーは別に数える。
	if err := l.Allow(ctx, "ip:b"); err != nil {
		t.Fatal(err)
	}
	// 次の窓では戻る。
	clk.Advance(30 * time.Second)
	if err := l.Allow(ctx, "ip:a"); err != nil {
		t.Fatalf("next window: %v", err)
	}
}

func TestDisabled(t *testing.T) {
	var l *ratelimit.Limiter
	if err := l.Allow(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Now())
	l = &ratelimit.Limiter{Cache: newCounter(), Clock: clk, Window: time.Minute}
	for range 100 {
		if err := l.Allow(context.Background(), "x"); err != nil {
			t.Fatal(err)
		}
	}
}

// AllowFrom は接続元ごとに Limit 回、接続元を問わず Total 回まで許す。他の接続元が使い切っても本人の分は残る。
func TestAllowFrom(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC))
	l := &ratelimit.Limiter{Cache: newCounter(), Clock: clk, Window: time.Minute, Limit: 2, Total: 5}
	ctx := context.Background()
	for i := range 2 {
		if err := l.AllowFrom(ctx, "email:a", "203.0.113.1"); err != nil {
			t.Fatalf("attacker request %d: %v", i, err)
		}
	}
	if err := l.AllowFrom(ctx, "email:a", "203.0.113.1"); err == nil {
		t.Fatal("attacker over the per-source limit")
	}
	// 同じ /64 は同じ接続元。
	if err := l.AllowFrom(ctx, "email:a", "2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if err := l.AllowFrom(ctx, "email:a", "2001:db8::2"); err != nil {
		t.Fatal(err)
	}
	if err := l.AllowFrom(ctx, "email:a", "2001:db8::3"); err == nil {
		t.Fatal("same /64 over the per-source limit")
	}
	// 本人の接続元の分は残る。接続元を問わない上限（5）を超えれば止める。
	if err := l.AllowFrom(ctx, "email:a", "198.51.100.7"); err != nil {
		t.Fatalf("victim: %v", err)
	}
	if err := l.AllowFrom(ctx, "email:a", "192.0.2.9"); err == nil {
		t.Fatal("over the total")
	}
}
