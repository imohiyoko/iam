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
