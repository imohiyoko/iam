// Package dev は開発用の PushSender（開発モードのみ。ADR 0104）。チャレンジをログに出す（宛先は出さない）。
package dev

import (
	"context"
	"errors"
	"log/slog"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterPushSender("dev", func(_ context.Context, cfg plugin.Config) (port.PushSender, error) {
		if !cfg.Dev {
			return nil, errors.New("push_sender dev: only available in development mode")
		}
		if err := cfg.CheckOptions(); err != nil {
			return nil, err
		}
		l := cfg.Logger
		if l == nil {
			l = slog.Default()
		}
		return &Sender{Log: l}, nil
	})
}

// Sender はチャレンジをログに出す。
type Sender struct{ Log *slog.Logger }

// Send はチャレンジの ID と端末の ID をログに出す（開発用）。
func (s *Sender) Send(ctx context.Context, m port.PushMessage) error {
	s.Log.InfoContext(ctx, "dev push sender (development only)", "device_id", m.DeviceID, "challenge_id", m.ChallengeID,
		"platform", m.Platform, "expires_at", m.ExpiresAt)
	return nil
}
