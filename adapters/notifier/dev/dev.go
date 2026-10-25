// Package dev は開発用の Notifier（開発ビルドのみ。design.md 2.4）。
//
// 通知をログに出す。秘密を持つ通知は、IAM から渡された Claim で秘密を取り出し、コードとリンクもログに出す
// （配信用のアプリを作らずにメールのログインを試せるように）。開発モードでしか作れない。
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
type Notifier struct {
	Log *slog.Logger
	// Claim は通知の秘密（宛先、コード、リンクのトークン）を取り出す（IAM が SetDevClaim で渡す）。nil なら秘密は出さない。
	Claim func(ctx context.Context, realmID, notificationID string) (to, code, token string, err error)
	// BaseURL はリンクの組み立てに使う公開 URL（空なら相対パス）。
	BaseURL string
}

// SetDevClaim は秘密の取り出し方を受け取る。
func (n *Notifier) SetDevClaim(baseURL string, claim func(ctx context.Context, realmID, notificationID string) (to, code, token string, err error)) {
	n.BaseURL, n.Claim = baseURL, claim
}

// Notify はペイロード（ID のみで秘密と宛先を含まない）をログに出す。秘密があれば取り出して出す（開発用）。
func (n *Notifier) Notify(ctx context.Context, x port.Notification) error {
	n.Log.InfoContext(ctx, "dev notifier", "notification_id", x.ID, "type", x.Type,
		"realm_id", x.RealmID, "user_id", x.UserID, "org_id", x.OrgID, "has_secret", x.HasSecret)
	if !x.HasSecret || n.Claim == nil {
		return nil
	}
	to, code, token, err := n.Claim(ctx, x.RealmID, x.ID)
	if err != nil {
		n.Log.WarnContext(ctx, "dev notifier: could not claim secret", "notification_id", x.ID, "error", err)
		return nil
	}
	n.Log.InfoContext(ctx, "dev notifier: secret (development only)", "notification_id", x.ID, "to", to,
		"code", code, "link", n.BaseURL+"/login/email#token="+token)
	return nil
}
