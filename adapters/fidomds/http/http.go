// Package http は FIDO Metadata Service（MDS3）の BLOB を HTTPS で取る FIDOMetadataSource（フィーチャー passkey_attestation、
// ADR 0096）。コアはバックグラウンドで定期的に呼び、ログインと登録の経路では呼ばない。署名はコアが確かめる。
package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

// DefaultURL は FIDO Alliance の本番の MDS3。
const DefaultURL = "https://mds3.fidoalliance.org/"

func init() {
	plugin.RegisterFIDOMDS("http", func(_ context.Context, cfg plugin.Config) (port.FIDOMetadataSource, error) {
		if err := cfg.CheckOptions("url", "timeout"); err != nil {
			return nil, err
		}
		u, err := url.Parse(cfg.Option("url", DefaultURL))
		if err != nil || u.Host == "" || (u.Scheme != "https" && (!cfg.Dev || u.Scheme != "http")) {
			return nil, errors.New("fido_mds http: url must be an https URL (http only in development mode)")
		}
		timeout := 30 * time.Second
		if v := cfg.Option("timeout", ""); v != "" {
			if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 {
				return nil, fmt.Errorf("fido_mds http: invalid timeout %q", v)
			}
		}
		return New(u.String(), timeout), nil
	})
}

// Source は HTTPS の BLOB。
type Source struct {
	url    string
	client *http.Client
}

// New は Source を返す。リダイレクトは追う（MDS3 は配信先に転送する）が、同じ scheme のものを 5 回までにする。
func New(rawURL string, timeout time.Duration) *Source {
	scheme := "https"
	if u, err := url.Parse(rawURL); err == nil {
		scheme = u.Scheme
	}
	return &Source{url: rawURL, client: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != scheme {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
}

// Fetch は BLOB を取る。
func (s *Source) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "imohiyoko-iam")
	resp, err := s.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("fido_mds http: %s returned %d", s.url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, attestation.MaxBlobBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > attestation.MaxBlobBytes {
		return nil, errors.New("fido_mds http: blob is too large")
	}
	return b, nil
}
