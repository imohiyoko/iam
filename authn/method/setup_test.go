package method

import (
	"context"
	"errors"
	"testing"

	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/port"
)

// configurable は設定を持つテスト用の方式。
type configurable struct {
	fake
	configured bool
	fail       bool
}

func (c configurable) Setup(_ context.Context, s port.MethodSetup) (port.Authenticator, error) {
	if c.fail || s.Options["bad"] != "" {
		return nil, errors.New("bad option")
	}
	c.configured = true
	return c, nil
}

func TestActiveWithConfigures(t *testing.T) {
	c := configurable{fake: fake{info("cfgm", "f", port.UsageSecondFactor)}}
	setup := func(i port.MethodInfo) port.MethodSetup { return port.MethodSetup{Options: map[string]string{}} }
	s, err := ActiveWith(context.Background(), func(string) bool { return false }, setup, c)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := s.Get("cfgm")
	if !ok || !a.(configurable).configured {
		t.Fatalf("not configured: %+v", a)
	}
	// 設定に失敗すれば起動を止める。
	if _, err := ActiveWith(context.Background(), func(string) bool { return false }, func(port.MethodInfo) port.MethodSetup {
		return port.MethodSetup{Options: map[string]string{"bad": "1"}}
	}, c); err == nil {
		t.Fatal("setup failure ignored")
	}
	if s.Without([]string{"cfgm"}).Supports("cfgm", "") || !s.Supports("cfgm", port.UsageSecondFactor) {
		t.Fatal("Without must not change the original set")
	}
}

func TestEventType(t *testing.T) {
	if EventType("sms", "code_sent") != "method.sms.code_sent" || EventType("sms", "Code") != "" || EventType("BAD", "x") != "" {
		t.Fatal("EventType")
	}
}

func TestScopedEphemeral(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	a, b := Scoped(k.Cache, "sms", "r1"), Scoped(k.Cache, "sms", "r2")
	if err := a.Set(ctx, "k", []byte("v"), 60e9); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get(ctx, "k"); ok {
		t.Fatal("another realm reads the key")
	}
	if _, ok, _ := k.Cache.Get(ctx, "k"); ok {
		t.Fatal("the key is not prefixed")
	}
	if v, ok, _ := a.Take(ctx, "k"); !ok || string(v) != "v" {
		t.Fatal("take")
	}
}
