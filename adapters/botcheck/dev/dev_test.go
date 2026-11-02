package dev_test

import (
	"context"
	"errors"
	"testing"

	"github.com/imohiyoko/iam/adapters/botcheck/dev"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func TestDev(t *testing.T) {
	f, err := plugin.BotCheck("dev")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f(ctx, plugin.Config{Options: map[string]string{"token": "ok"}}); err == nil {
		t.Error("dev adapter outside development mode")
	}
	v, err := f(ctx, plugin.Config{Dev: true, Options: map[string]string{"token": "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(ctx, "ok", ""); err != nil {
		t.Error(err)
	}
	for _, tok := range []string{"", "ng", "ok "} {
		if err := v.Verify(ctx, tok, ""); !errors.Is(err, port.ErrBotRejected) {
			t.Errorf("Verify(%q) = %v", tok, err)
		}
	}
	if err := (dev.Verifier{}).Verify(ctx, "", ""); !errors.Is(err, port.ErrBotRejected) {
		t.Error("empty token configured")
	}
}
