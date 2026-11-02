// Package webhook は、運用者のプッシュの中継（FCM・APNs に送るもの）に Webhook でチャレンジを渡す PushSender
// （フィーチャー push_auth。ADR 0104）。
//
// 本文は {"type":"iam.push.challenge","token":…,"platform":…,"challenge_id":…,"device_id":…,"expires_at":…}。0031 の例外として
// 端末の宛先（token）を入れる（届けるのに欠かせない）。照合する番号・ユーザーの ID・メールアドレスは入れない。
//
// 署名：X-IAM-Signature: t=<UNIX 秒>,v1=<hex(HMAC-SHA-256(secret, "<t>." + body))>（通知の Webhook と同じ）
//
// 設定（push_sender.options）：url（https。開発モードだけ http）、secret_env（32 バイト以上の秘密を持つ環境変数。読んだ後に消す）、
// timeout（既定 5 秒、30 秒以下）。
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	notifier "github.com/imohiyoko/iam/adapters/notifier/webhook"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterPushSender("webhook", func(_ context.Context, cfg plugin.Config) (port.PushSender, error) {
		if err := cfg.CheckOptions("url", "secret_env", "timeout"); err != nil {
			return nil, err
		}
		u, err := url.Parse(cfg.Option("url", ""))
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(cfg.Dev && u.Scheme == "http")) {
			return nil, errors.New("push_sender webhook: url must be an https URL (http only in development mode)")
		}
		env := cfg.Option("secret_env", "")
		secret := os.Getenv(env)
		if env == "" || len(secret) < 32 {
			return nil, errors.New("push_sender webhook: secret_env must name an environment variable holding a secret of 32+ bytes")
		}
		_ = os.Unsetenv(env)
		timeout := 5 * time.Second
		if v := cfg.Option("timeout", ""); v != "" {
			if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 || timeout > 30*time.Second {
				return nil, fmt.Errorf("push_sender webhook: invalid timeout %q", v)
			}
		}
		return New(u.String(), []byte(secret), timeout, cfg.Clock), nil
	})
}

// Sender は Webhook の PushSender。
type Sender struct {
	url    string
	secret []byte
	client *http.Client
	clock  clock.Clock
}

// New は Sender を返す。
func New(url string, secret []byte, timeout time.Duration, clk clock.Clock) *Sender {
	if clk == nil {
		clk = clock.System{}
	}
	return &Sender{url: url, secret: secret, clock: clk, client: &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Body は Webhook の本文。
type Body struct {
	Type        string    `json:"type"`
	Token       string    `json:"token"`
	Platform    string    `json:"platform,omitempty"`
	ChallengeID string    `json:"challenge_id"`
	DeviceID    string    `json:"device_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Send は中継にチャレンジを渡す。2xx 以外はエラー（届かなかったとみなす）。
func (s *Sender) Send(ctx context.Context, m port.PushMessage) error {
	body, err := json.Marshal(Body{Type: "iam.push.challenge", Token: m.Token, Platform: m.Platform, ChallengeID: m.ChallengeID,
		DeviceID: m.DeviceID, ExpiresAt: m.ExpiresAt.UTC()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAM-Signature", notifier.Sign(s.secret, body, s.clock.Now()))
	resp, err := s.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return fmt.Errorf("push_sender webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("push_sender webhook: returned %d", resp.StatusCode)
	}
	return nil
}
