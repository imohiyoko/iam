// Package dev は開発用の Notifier（開発ビルドのみ。design.md 2.4）。
//
// 通知をログに出す。秘密を取り出してリンクを組み立てる表示は、claim API ができる M1 で追加する。
package dev

import (
	"context"
	"errors"
	"log/slog"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterNotifier("dev", func(_ context.Context, cfg plugin.Config) (port.Notifier, error) {
		if !cfg.Dev {
			return nil, errors.New("notifier dev: only available in development mode")
		}
		if err := cfg.CheckOptions(); err != nil {
			return nil, err
		}
		l := cfg.Logger
		if l == nil {
			l = slog.Default()
		}
		return &Notifier{Log: l}, nil
	})
}

// Notifier は通知をログに出す。
type Notifier struct{ Log *slog.Logger }

// Notify はペイロード（ID のみで秘密と宛先を含まない）をログに出す。
func (n *Notifier) Notify(ctx context.Context, x port.Notification) error {
	n.Log.InfoContext(ctx, "dev notifier", "notification_id", x.ID, "type", x.Type,
		"realm_id", x.RealmID, "user_id", x.UserID, "org_id", x.OrgID, "has_secret", x.HasSecret)
	return nil
}
