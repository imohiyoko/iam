// Package hibp は Pwned Passwords の range API（k-匿名）で漏洩済みパスワードを確かめる BreachChecker
// （design.md 4.1）。送るのは SHA-1 の先頭 5 文字だけで、応答の候補と手元で照合する。
// 応答の大きさから問い合わせを推測されないよう、詰め物（Add-Padding）を求める。
package hibp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

// DefaultURL は公開の API。互換の API（自前のミラーなど）は url で選ぶ。
const DefaultURL = "https://api.pwnedpasswords.com"

func init() {
	plugin.RegisterBreachCheck("hibp", func(_ context.Context, cfg plugin.Config) (port.BreachChecker, error) {
		if err := cfg.CheckOptions("url", "timeout"); err != nil {
			return nil, err
		}
		u, err := url.Parse(cfg.Option("url", DefaultURL))
		if err != nil || u.Host == "" || (u.Scheme != "https" && (!cfg.Dev || u.Scheme != "http")) {
			return nil, errors.New("breach_check hibp: url must be an https URL (http only in development mode)")
		}
		timeout := 2 * time.Second
		if v := cfg.Option("timeout", ""); v != "" {
			if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 {
				return nil, fmt.Errorf("breach_check hibp: invalid timeout %q", v)
			}
		}
		return New(strings.TrimSuffix(u.String(), "/"), timeout), nil
	})
}

// Checker は range API の BreachChecker。
type Checker struct {
	url    string
	client *http.Client
}

// New は Checker を返す。
func New(baseURL string, timeout time.Duration) *Checker {
	return &Checker{url: baseURL, client: &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// maxBody は応答の上限（詰め物つきで通常は 1,000 行前後、数十 KB）。
const maxBody = 2 << 20

// Breached は SHA-1 の先頭 5 文字で候補を取り、残りの 35 文字と出現の回数で判定する（回数 0 は詰め物）。
func (c *Checker) Breached(ctx context.Context, sha1Hex string) (bool, error) {
	h := strings.ToUpper(sha1Hex)
	if len(h) != 40 {
		return false, errors.New("breach_check hibp: want a SHA-1 hex digest")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/range/"+h[:5], nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "imohiyoko-iam")
	resp, err := c.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return false, fmt.Errorf("breach_check hibp: range returned %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBody))
	for sc.Scan() {
		suffix, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(suffix, h[5:]) {
			return strings.TrimLeft(count, "0") != "", nil
		}
	}
	return false, sc.Err()
}
