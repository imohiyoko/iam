package lockout_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

func guard() (*lockout.Guard, *clock.Fake) {
	clk := clock.NewFake(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	return &lockout.Guard{Cache: newStore(clk), Clock: clk, Config: lockout.Config{Threshold: 5, Window: 15 * time.Minute,
		LockDuration: 10 * time.Minute, MaxLockDuration: 30 * time.Minute, DelayAfter: 2, BaseDelay: time.Second, MaxDelay: 4 * time.Second}}, clk
}

func retry(t *testing.T, err error) time.Duration {
	t.Helper()
	ex, ok := errors.AsType[*ratelimit.ExceededError](err)
	if !ok {
		t.Fatalf("want *ExceededError, got %v", err)
	}
	return ex.RetryAfter
}

func TestDelaysThenLock(t *testing.T) {
	g, clk := guard()
	ctx := context.Background()
	fail := func() *lockout.Lock {
		t.Helper()
		if err := g.Check(ctx, "r", lockout.ScopeLoginID, "alice"); err != nil {
			t.Fatalf("check before failure: %v", err)
		}
		l, err := g.Failed(ctx, "r", lockout.ScopeLoginID, "alice")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	// 1 回目は待たない。2 回目から 1s、2s、4s（max_delay で止まる）。
	fail()
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		if l := fail(); l != nil {
			t.Fatalf("locked early at %d", i)
		}
		if got := retry(t, g.Check(ctx, "r", lockout.ScopeLoginID, "alice")); got != want {
			t.Fatalf("delay %d = %s, want %s", i, got, want)
		}
		// ほかの対象・ほかの realm・ほかの種類には効かない。
		for _, err := range []error{g.Check(ctx, "r", lockout.ScopeLoginID, "bob"), g.Check(ctx, "r2", lockout.ScopeLoginID, "alice"),
			g.Check(ctx, "r", lockout.ScopeSecondFactor, "alice")} {
			if err != nil {
				t.Fatalf("leaked to another subject: %v", err)
			}
		}
		clk.Advance(want)
	}
	// 5 回目でロック（10 分）。
	l := fail()
	if l == nil || l.Level != 1 || !l.Until.Equal(clk.Now().Add(10*time.Minute)) {
		t.Fatalf("lock = %+v", l)
	}
	if got := retry(t, g.Check(ctx, "r", lockout.ScopeLoginID, "alice")); got != 10*time.Minute {
		t.Fatalf("lock retry = %s", got)
	}
	st, err := g.Status(ctx, "r", lockout.ScopeLoginID, "alice")
	if err != nil || st.LockedUntil == nil || st.Level != 1 || st.Failures != 0 || !st.Locked() {
		t.Fatalf("status = %+v, %v", st, err)
	}
	clk.Advance(10 * time.Minute)
	// 明けたら数え直す。続けてロックされると 2 倍（20 分）、その次は max_lock_duration（30 分）で止まる。
	for _, want := range []time.Duration{20 * time.Minute, 30 * time.Minute} {
		var l *lockout.Lock
		for range 5 {
			clk.Advance(5 * time.Second)
			l = fail()
		}
		if l == nil || l.Until.Sub(clk.Now()) != want {
			t.Fatalf("relock = %+v, want %s", l, want)
		}
		clk.Advance(want)
	}
}

func TestSucceededAndUnlock(t *testing.T) {
	g, clk := guard()
	ctx := context.Background()
	for range 3 {
		if _, err := g.Failed(ctx, "r", lockout.ScopeSecondFactor, "u"); err != nil {
			t.Fatal(err)
		}
	}
	if g.Check(ctx, "r", lockout.ScopeSecondFactor, "u") == nil {
		t.Fatal("no delay after 3 failures")
	}
	// 成功で失敗の回数と待ち時間を消す。
	if err := g.Succeeded(ctx, "r", lockout.ScopeSecondFactor, "u"); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(ctx, "r", lockout.ScopeSecondFactor, "u"); err != nil {
		t.Fatalf("after success: %v", err)
	}
	for range 5 {
		clk.Advance(10 * time.Second)
		if _, err := g.Failed(ctx, "r", lockout.ScopeSecondFactor, "u"); err != nil {
			t.Fatal(err)
		}
	}
	st, err := g.Unlock(ctx, "r", lockout.ScopeSecondFactor, "u")
	if err != nil || st.LockedUntil == nil || st.Level != 1 {
		t.Fatalf("unlock returned %+v, %v", st, err)
	}
	if err := g.Check(ctx, "r", lockout.ScopeSecondFactor, "u"); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	if st, _ := g.Status(ctx, "r", lockout.ScopeSecondFactor, "u"); st.Locked() || st.Level != 0 || st.Failures != 0 {
		t.Fatalf("status after unlock = %+v", st)
	}
}

func TestWindowExpires(t *testing.T) {
	g, clk := guard()
	ctx := context.Background()
	for range 4 {
		clk.Advance(5 * time.Second)
		if _, err := g.Failed(ctx, "r", lockout.ScopeLoginID, "a"); err != nil {
			t.Fatal(err)
		}
	}
	// 窓が過ぎれば数え直すので、次の失敗ではロックしない。
	clk.Advance(16 * time.Minute)
	if l, err := g.Failed(ctx, "r", lockout.ScopeLoginID, "a"); err != nil || l != nil {
		t.Fatalf("after window = %+v, %v", l, err)
	}
}

func TestNilGuard(t *testing.T) {
	var g *lockout.Guard
	ctx := context.Background()
	if err := g.Check(ctx, "r", lockout.ScopeLoginID, "a"); err != nil {
		t.Fatal(err)
	}
	if l, err := g.Failed(ctx, "r", lockout.ScopeLoginID, "a"); l != nil || err != nil {
		t.Fatal(l, err)
	}
	if err := g.Succeeded(ctx, "r", lockout.ScopeLoginID, "a"); err != nil {
		t.Fatal(err)
	}
	if st, err := g.Unlock(ctx, "r", lockout.ScopeLoginID, "a"); err != nil || st.Locked() {
		t.Fatal(st, err)
	}
}
