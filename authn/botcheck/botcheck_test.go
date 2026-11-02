package botcheck_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// tokenVerifier は値が一致すれば通す。
type tokenVerifier string

func (v tokenVerifier) Verify(_ context.Context, token, _ string) error {
	if token != string(v) {
		return port.ErrBotRejected
	}
	return nil
}

type broken struct{}

func (broken) Verify(context.Context, string, string) error { return errors.New("timeout") }

func guard(mode botcheck.Mode, v port.BotVerifier) (*botcheck.Guard, *clock.Fake) {
	clk := clock.NewFake(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	return &botcheck.Guard{Verifier: v, Cache: newStore(clk), Clock: clk, Mode: mode, AfterFailures: 3, Window: 10 * time.Minute}, clk
}

func TestAlways(t *testing.T) {
	g, _ := guard(botcheck.ModeAlways, tokenVerifier("ok"))
	ctx := context.Background()
	for _, tok := range []string{"", "ng", strings.Repeat("x", 5000)} {
		if err := g.Check(ctx, "r", "203.0.113.1", tok); !errors.Is(err, botcheck.ErrRequired) {
			t.Errorf("Check(%q) = %v", tok[:min(len(tok), 8)], err)
		}
	}
	if err := g.Check(ctx, "r", "203.0.113.1", "ok"); err != nil {
		t.Fatal(err)
	}
	// 検証の障害でも通さない。
	g.Verifier = broken{}
	if err := g.Check(ctx, "r", "203.0.113.1", "ok"); !errors.Is(err, botcheck.ErrRequired) {
		t.Fatalf("verifier failure = %v", err)
	}
}

func TestSuspicious(t *testing.T) {
	g, clk := guard(botcheck.ModeSuspicious, tokenVerifier("ok"))
	ctx := context.Background()
	for range 3 {
		if err := g.Check(ctx, "r", "2001:db8::1", ""); err != nil {
			t.Fatalf("before failures: %v", err)
		}
		if err := g.Failed(ctx, "r", "2001:db8::1"); err != nil {
			t.Fatal(err)
		}
	}
	// 同じ /64 は疑わしい。別の接続元・別の realm は求めない。
	if err := g.Check(ctx, "r", "2001:db8::2", ""); !errors.Is(err, botcheck.ErrRequired) {
		t.Fatalf("same /64 = %v", err)
	}
	if err := g.Check(ctx, "r", "2001:db8::2", "ok"); err != nil {
		t.Fatalf("with token = %v", err)
	}
	for _, c := range [][2]string{{"r", "2001:db8:1::1"}, {"r2", "2001:db8::1"}} {
		if err := g.Check(ctx, c[0], c[1], ""); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	clk.Advance(10 * time.Minute)
	if err := g.Check(ctx, "r", "2001:db8::1", ""); err != nil {
		t.Fatalf("next window: %v", err)
	}
	var nilGuard *botcheck.Guard
	if err := nilGuard.Check(ctx, "r", "x", ""); err != nil || nilGuard.Failed(ctx, "r", "x") != nil {
		t.Fatal("nil guard")
	}
}
