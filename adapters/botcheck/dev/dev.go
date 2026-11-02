// Package dev は開発とテスト用の BotVerifier（フィーチャー bot_protection。ADR 0105）。設定した値（token）だけを通す。
// 開発モード（dev: true）でだけ作れる。
package dev

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterBotCheck("dev", func(_ context.Context, cfg plugin.Config) (port.BotVerifier, error) {
		if !cfg.Dev {
			return nil, errors.New("bot_check dev: only available in development mode")
		}
		if err := cfg.CheckOptions("token"); err != nil {
			return nil, err
		}
		t := cfg.Option("token", "")
		if t == "" {
			return nil, errors.New("bot_check dev: token is required")
		}
		return Verifier{Token: t}, nil
	})
}

// Verifier は Token と一致するトークンだけを通す。
type Verifier struct{ Token string }

// Verify は token が Token と一致すれば nil、違えば port.ErrBotRejected。
func (v Verifier) Verify(_ context.Context, token, _ string) error {
	if v.Token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(v.Token)) != 1 {
		return port.ErrBotRejected
	}
	return nil
}
