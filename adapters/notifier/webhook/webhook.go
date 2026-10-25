// Package webhook は通知を Webhook で外部に渡す Notifier（design.md 2.4）。
//
// ペイロードは ID だけ（秘密と宛先を含まない）。受け取る側は署名を確かめ、notification_id で重複排除する
// （outbox からの送出は少なくとも1回）。秘密は受け取る側が claim API で取り出す。
//
// 署名：X-IAM-Signature: t=<UNIX 秒>,v1=<hex(HMAC-SHA-256(secret, "<t>." + body))>
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterNotifier("webhook", func(_ context.Context, cfg plugin.Config) (port.Notifier, error) {
		if err := cfg.CheckOptions("url", "secret_env", "timeout"); err != nil {
			return nil, err
		}
		u, err := url.Parse(cfg.Option("url", ""))
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(cfg.Dev && u.Scheme == "http")) {
			return nil, errors.New("notifier webhook: url must be an https URL (http only in development mode)")
		}
		env := cfg.Option("secret_env", "")
		secret := os.Getenv(env)
		if env == "" || len(secret) < 32 {
			return nil, errors.New("notifier webhook: secret_env must name an environment variable holding a secret of 32+ bytes")
		}
		_ = os.Unsetenv(env)
		timeout := 10 * time.Second
		if v := cfg.Option("timeout", ""); v != "" {
			if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 {
				return nil, fmt.Errorf("notifier webhook: invalid timeout %q", v)
			}
		}
		return New(u.String(), []byte(secret), timeout, cfg.Clock), nil
	})
}

// Notifier は Webhook の Notifier。
type Notifier struct {
	url    string
	secret []byte
	client *http.Client
	clock  clock.Clock
}

// New は Notifier を返す。
func New(url string, secret []byte, timeout time.Duration, clk clock.Clock) *Notifier {
	if clk == nil {
		clk = clock.System{}
	}
	return &Notifier{url: url, secret: secret, clock: clk, client: &http.Client{
		Timeout: timeout,
		// 転送先を検証していない宛先には送らない。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Sign は署名ヘッダーの値を返す。
func Sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// Notify は通知を送る。2xx 以外はエラー（outbox から再送する）。
func (n *Notifier) Notify(ctx context.Context, x port.Notification) error {
	body, err := json.Marshal(x)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAM-Notification-Id", x.ID)
	req.Header.Set("X-IAM-Signature", Sign(n.secret, body, n.clock.Now()))
	resp, err := n.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notifier webhook: %s returned %d", x.ID, resp.StatusCode)
	}
	return nil
}
