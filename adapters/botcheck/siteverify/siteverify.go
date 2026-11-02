// Package siteverify は汎用の siteverify の API でボットの確認のトークンを確かめる BotVerifier（フィーチャー bot_protection。
// ADR 0105）。Cloudflare Turnstile・hCaptcha・reCAPTCHA に共通の形：`secret`・`response`・`remoteip` をフォームで POST し、
// JSON の `success`（と、設定すれば `hostname`）を確かめる。
package siteverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterBotCheck("siteverify", func(_ context.Context, cfg plugin.Config) (port.BotVerifier, error) {
		if err := cfg.CheckOptions("url", "secret_env", "timeout", "hostname"); err != nil {
			return nil, err
		}
		u, err := url.Parse(cfg.Option("url", ""))
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && (!cfg.Dev || u.Scheme != "http")) {
			return nil, errors.New("bot_check siteverify: url must be an https URL (http only in development mode)")
		}
		env := cfg.Option("secret_env", "")
		if env == "" {
			return nil, errors.New("bot_check siteverify: secret_env is required")
		}
		secret := os.Getenv(env)
		_ = os.Unsetenv(env)
		if secret == "" {
			return nil, fmt.Errorf("bot_check siteverify: %s is empty", env)
		}
		timeout := 3 * time.Second
		if v := cfg.Option("timeout", ""); v != "" {
			if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 || timeout > 10*time.Second {
				return nil, fmt.Errorf("bot_check siteverify: timeout %q must be within (0, 10s]", v)
			}
		}
		return New(u.String(), secret, cfg.Option("hostname", ""), timeout), nil
	})
}

// Verifier は siteverify の BotVerifier。
type Verifier struct {
	url, secret, hostname string
	client                *http.Client
}

var _ port.BotVerifier = (*Verifier)(nil)

// New は Verifier を返す。hostname が空でなければ、応答の hostname と一致することも求める。
func New(endpoint, secret, hostname string, timeout time.Duration) *Verifier {
	return &Verifier{url: endpoint, secret: secret, hostname: hostname, client: &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// maxBody は応答の上限。
const maxBody = 64 << 10

type response struct {
	Success  *bool  `json:"success"`
	Hostname string `json:"hostname"`
}

// Verify はトークンを確かめる。通らなければ port.ErrBotRejected、確かめられなければそのほかのエラー。
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) error {
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "imohiyoko-iam")
	resp, err := v.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return fmt.Errorf("bot_check siteverify: returned %d", resp.StatusCode)
	}
	return v.decide(io.LimitReader(resp.Body, maxBody))
}

func (v *Verifier) decide(r io.Reader) error {
	var out response
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return fmt.Errorf("bot_check siteverify: %w", err)
	}
	if out.Success == nil {
		return errors.New("bot_check siteverify: response without success")
	}
	if !*out.Success || (v.hostname != "" && !strings.EqualFold(out.Hostname, v.hostname)) {
		return port.ErrBotRejected
	}
	return nil
}
