// Package dev は開発用の SMSSender（開発モードのみ。ADR 0104）。コードをログに出す（番号は末尾の 2 桁だけ）。
package dev

import (
	"context"
	"errors"
	"log/slog"

	"github.com/imohiyoko/iam/authn/method/sms"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterSMSSender("dev", func(_ context.Context, cfg plugin.Config) (port.SMSSender, error) {
		if !cfg.Dev {
			return nil, errors.New("sms_sender dev: only available in development mode")
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

// Sender はコードをログに出す。
type Sender struct{ Log *slog.Logger }

// Send はコードをログに出す（開発用）。
func (s *Sender) Send(ctx context.Context, m port.SMSMessage) error {
	s.Log.InfoContext(ctx, "dev sms sender (development only)", "to", sms.Mask(m.To), "channel", m.Channel, "code", m.Code,
		"expires_at", m.ExpiresAt)
	return nil
}
