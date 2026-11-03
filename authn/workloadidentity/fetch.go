package workloadidentity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/port"
)

// 発行者の JWKS の取得とキャッシュ（ADR 0116）。SSRF の対策は ADR 0077・0100 と同じく、実際につなぐアドレスが公開の
// アドレスであることを確かめ、プロキシを使わず、転送に従わない。

const (
	// fetchTimeout は 1 回の取得の上限。
	fetchTimeout = 5 * time.Second
	// maxFetchBody は Discovery と JWKS の応答の上限。
	maxFetchBody = 256 << 10
	// jwksTTL は取得した JWKS を置く時間。
	jwksTTL = time.Hour
	// fetchWindow と maxFetches は、発行者ごとの取得の回数の上限（未認証の要求で問い合わせを繰り返させない）。
	fetchWindow = time.Minute
	maxFetches  = 5
)

var errNotPublic = errors.New("workload identity: not a public address")

// guardedClient は公開のアドレスにだけつなぎ、転送に従わないクライアント（eventsub.PublicClient と同じ確かめ方）。
func guardedClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: fetchTimeout}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errNotPublic
			}
			a, err := netip.ParseAddr(host)
			if err != nil || !oauth.PublicAddr(a) {
				return fmt.Errorf("%w: %s", errNotPublic, host)
			}
			return nil
		}
	}
	t := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: fetchTimeout, ResponseHeaderTimeout: fetchTimeout,
		MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &http.Client{Transport: t, Timeout: fetchTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *Service) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	s.once.Do(func() { s.guarded = guardedClient(s.AllowPrivateNetworks) })
	return s.guarded
}

// getJSON は https の URL から JSON を取得する。200 以外・上限を超える応答は誤り。
func (s *Service) getJSON(ctx context.Context, u string) ([]byte, error) {
	if !ValidHTTPSURL(u) {
		return nil, fmt.Errorf("workload identity: not an https URL: %q", u)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client().Do(req) // #nosec G704 -- 発行者の URL は https に限り、公開のアドレスにだけつなぐ
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("workload identity: %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFetchBody {
		return nil, fmt.Errorf("workload identity: %s: response too large", u)
	}
	return b, nil
}

// discoverJWKSURI は issuer の OpenID Provider Configuration から jwks_uri を読む。issuer は登録と完全一致すること。
func (s *Service) discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	b, err := s.getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", fmt.Errorf("workload identity: discovery: %w", err)
	}
	if d.Issuer != issuer {
		return "", fmt.Errorf("workload identity: discovery issuer %q does not match %q", d.Issuer, issuer)
	}
	if !ValidHTTPSURL(d.JWKSURI) {
		return "", fmt.Errorf("workload identity: discovery jwks_uri %q is not an https URL", d.JWKSURI)
	}
	return d.JWKSURI, nil
}

func cacheKey(p port.WorkloadIdentityProvider) string {
	h := sha256.Sum256([]byte(p.ID + "\x00" + strconv.FormatInt(p.UpdatedAt.UnixNano(), 10)))
	return "wif:jwks:v1:" + base64.RawURLEncoding.EncodeToString(h[:])
}

// keys は発行者の鍵を返す。固定の JWKS ならそれを、そうでなければキャッシュか取得したものを返す。refresh なら
// （知らない kid）キャッシュを使わずに取得し直す。取得の回数は発行者ごとに限る。
func (s *Service) keys(ctx context.Context, p port.WorkloadIdentityProvider, cfg Config, refresh bool) ([]jose.JSONWebKey, error) {
	if len(cfg.JWKS) > 0 {
		return parseKeySet(cfg.JWKS, false)
	}
	key := cacheKey(p)
	if !refresh {
		b, ok, err := s.Cache.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if ok {
			return parseKeySet(b, false)
		}
	}
	n, err := s.Cache.Incr(ctx, "wif:jwks:fetch:v1:"+p.ID, fetchWindow)
	if err != nil {
		return nil, err
	}
	if n > maxFetches {
		return nil, errors.New("workload identity: too many jwks fetches")
	}
	u := cfg.JWKSURI
	if u == "" {
		if u, err = s.discoverJWKSURI(ctx, p.Issuer); err != nil {
			return nil, err
		}
	}
	b, err := s.getJSON(ctx, u)
	if err != nil {
		return nil, err
	}
	ks, err := parseKeySet(b, false)
	if err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		return nil, errors.New("workload identity: jwks has no usable keys")
	}
	if err := s.Cache.Set(ctx, key, b, jwksTTL); err != nil {
		return nil, err
	}
	return ks, nil
}
