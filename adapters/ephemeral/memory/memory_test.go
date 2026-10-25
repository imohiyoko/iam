package memory

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
)

var t0 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

// スパイク：偽の時計と TTL 付きキャッシュの組み合わせで時刻の境界をテストできるか（ADR 0043）。
func TestTTLBoundaryWithFakeClock(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := New(clk)
	if err := s.Set(ctx, "k", []byte("v"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	clk.Advance(30*time.Second - time.Nanosecond)
	if _, ok, _ := s.Get(ctx, "k"); !ok {
		t.Fatal("must be present 1ns before expiry")
	}
	clk.Advance(time.Nanosecond)
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatal("must be gone exactly at expiry")
	}
}

func TestTTLRequired(t *testing.T) {
	s := New(clock.NewFake(t0))
	if err := s.Set(context.Background(), "k", nil, 0); err == nil {
		t.Fatal("ttl 0 must be rejected")
	}
	if _, err := s.Incr(context.Background(), "k", -1); err == nil {
		t.Fatal("negative ttl must be rejected")
	}
}

func TestIncrKeepsWindow(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := New(clk)
	for i := int64(1); i <= 3; i++ {
		n, err := s.Incr(ctx, "rl", time.Minute)
		if err != nil || n != i {
			t.Fatalf("Incr = %d, %v", n, err)
		}
		clk.Advance(10 * time.Second)
	}
	// 窓は最初の Incr から数える（固定窓）。
	clk.Set(t0.Add(time.Minute))
	if n, _ := s.Incr(ctx, "rl", time.Minute); n != 1 {
		t.Fatalf("new window: %d", n)
	}
}

func TestValueIsCopied(t *testing.T) {
	ctx := context.Background()
	s := New(clock.NewFake(t0))
	v := []byte("abc")
	s.Set(ctx, "k", v, time.Minute)
	v[0] = 'x'
	got, _, _ := s.Get(ctx, "k")
	got[1] = 'y'
	again, _, _ := s.Get(ctx, "k")
	if string(again) != "abc" {
		t.Fatalf("stored value mutated: %q", again)
	}
}

func TestSweep(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := New(clk)
	s.Set(ctx, "a", nil, time.Second)
	s.Set(ctx, "b", nil, time.Hour)
	clk.Advance(time.Minute)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("Sweep = %d", n)
	}
}

// セッションの有効性のキャッシュに当たった場合の検証（design.md 5.3）の代わりの計測。
func BenchmarkGetHit(b *testing.B) {
	ctx := context.Background()
	s := New(clock.System{})
	s.Set(ctx, "session:ses_x", make([]byte, 128), time.Minute)
	for b.Loop() {
		if _, ok, _ := s.Get(ctx, "session:ses_x"); !ok {
			b.Fatal("miss")
		}
	}
}
