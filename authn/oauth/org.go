package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 専用 SSO（design.md 11.3、ADR 0077）。
//
// Org の owner が登録する OIDC の connection（connections.owner_org_id）。不変条件：
//   - その Org の管理ユーザーだけがログイン・連携でき、ログインはその Org に入る（Org の IdP がなりすませる相手を限る）
//   - 登録は、Org が証明したドメインのアドレスに限り、Org の管理ユーザーとメンバーとして作る（確認の経路 sso）
//   - 戻り先はホスト型ログイン画面に固定する（Org は選べない）
//   - トークンエンドポイントは公開のアドレスに限り、解決したアドレスに直接つなぐ（SSRF と DNS rebinding を防ぐ）

// Resolver は名前解決（net.Resolver が満たす）。
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// OrgConnection は Org の owner が登録する OIDC の connection の設定。
type OrgConnection struct {
	Issuer       string
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Scopes は空なら openid と email。openid を含むこと。
	Scopes []string
}

// MaxOrgConnections は 1 Org の connection の上限。
const MaxOrgConnections = 5

// NewOrgConnection は Org（内部 ID）の connection を作る。slug は ID と同じ（運営者の slug と重ならない）。
func (s *Service) NewOrgConnection(ctx context.Context, realmID, orgID string, in OrgConnection) (port.Connection, error) {
	if !okURL(s.OrgRedirectURI, s.Dev) {
		// server.public_url が無ければ戻り先が決まらない（設定の誤り。登録は 400）。
		return port.Connection{}, errs.WithCode(errs.KindInvalid, "public_url_required", "oauth: org redirect uri is not configured (server.public_url)")
	}
	if !okURL(in.Issuer, s.Dev) {
		return port.Connection{}, errs.New(errs.KindInvalid, "oauth connection: issuer must be an https URL")
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email"}
	}
	for _, v := range []string{in.Issuer, in.AuthURL, in.TokenURL, in.ClientID, in.ClientSecret} {
		if len(v) > 2048 {
			return port.Connection{}, errs.New(errs.KindInvalid, "oauth connection: value too long")
		}
	}
	if len(scopes) > 20 || slices.ContainsFunc(scopes, func(v string) bool { return v == "" || len(v) > 100 || strings.ContainsAny(v, " \t\r\n") }) {
		return port.Connection{}, errs.New(errs.KindInvalid, "oauth connection: invalid scopes")
	}
	if in.ClientSecret == "" {
		return port.Connection{}, errs.New(errs.KindInvalid, "oauth connection: issuers, client_id and client secret are required")
	}
	cfg := Config{Issuers: []string{in.Issuer}, AuthURL: in.AuthURL, TokenURL: in.TokenURL, ClientID: in.ClientID, Scopes: slices.Clone(scopes),
		RedirectURIs: []string{s.OrgRedirectURI}}
	sealed, err := s.Crypter.Seal(ctx, secretPurpose, []byte(in.ClientSecret))
	if err != nil {
		return port.Connection{}, err
	}
	cfg.ClientSecret = sealed
	if err := cfg.Validate(s.Dev); err != nil {
		return port.Connection{}, err
	}
	b, err := json.Marshal(cfg) // #nosec G117 -- シークレットは Seal で封をしたもの
	if err != nil {
		return port.Connection{}, err
	}
	cid := id.NewExternal(id.Connection)
	return port.Connection{ID: cid, RealmID: realmID, Slug: cid, Type: Type, Config: b, CreatedAt: s.Clock.Now(), OwnerOrgID: orgID}, nil
}

// ConnectionInfo は connection の設定のうち、公開してよいもの（Org の owner に返す）。
type ConnectionInfo struct {
	Issuer, AuthURL, TokenURL, ClientID, RedirectURI string
	Scopes                                           []string
}

// Info は connection の設定のうち、公開してよいものを返す（クライアントシークレットは返さない）。
func Info(c port.Connection) (ConnectionInfo, error) {
	var cfg Config
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return ConnectionInfo{}, fmt.Errorf("oauth: connection %s: %w", c.ID, err)
	}
	out := ConnectionInfo{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL, ClientID: cfg.ClientID, Scopes: cfg.Scopes}
	if len(cfg.Issuers) > 0 {
		out.Issuer = cfg.Issuers[0]
	}
	if len(cfg.RedirectURIs) > 0 {
		out.RedirectURI = cfg.RedirectURIs[0]
	}
	return out, nil
}

// managedByOwner は、ユーザー（内部 ID）が connection を持つ Org の管理ユーザーかを確かめる。
func (s *Service) managedByOwner(ctx context.Context, realmID string, c port.Connection, userID string) error {
	return s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, realmID, userID)
		if err != nil {
			return err
		}
		if u.ManagedOrgID != c.OwnerOrgID {
			return ErrNotManagedByOwner
		}
		return nil
	})
}

// orgClient は Org が設定したトークンエンドポイントへの接続。名前を解決し、公開のアドレスでなければ断り、
// 解決したアドレスに直接つなぐ（つなぐ間に名前の向き先を変えられないように）。プロキシを使う設定なら、
// 解決したアドレスを確かめたうえで、接続はプロキシに任せる。AllowPrivateNetworks（開発・テスト）なら確かめない。
func (s *Service) orgClient(ctx context.Context, req *http.Request) (*http.Client, error) {
	c := s.httpClient()
	if s.AllowPrivateNetworks {
		return c, nil
	}
	host, port := req.URL.Hostname(), req.URL.Port()
	if port == "" {
		port = "443"
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		r := s.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if addrs, err = r.LookupNetIP(ctx, "ip", host); err != nil {
			return nil, fmt.Errorf("token endpoint: resolve: %w", err)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("token endpoint: no address")
	}
	for _, a := range addrs {
		if !PublicAddr(a) {
			return nil, fmt.Errorf("token endpoint: %s is not a public address", a)
		}
	}
	base, ok := c.Transport.(*http.Transport)
	if !ok || base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	if p, err := proxyFor(t, req); err != nil || p != nil {
		c.Transport = t
		return c, err
	}
	target := net.JoinHostPort(addrs[0].Unmap().String(), port)
	d := &net.Dialer{Timeout: exchangeTimeout}
	t.DialTLSContext = nil
	t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, target)
	}
	c.Transport = t
	return c, nil
}

func proxyFor(t *http.Transport, req *http.Request) (*url.URL, error) {
	if t.Proxy == nil {
		return nil, nil
	}
	return t.Proxy(req)
}

// 公開のアドレスとみなさない範囲（IsPrivate などで判定できないもの）。
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64（内部のアドレスに変換されうる）
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4（IPv4 のアドレスを埋め込む）
}

// PublicAddr は a がインターネット上の公開のユニキャストアドレスかを返す。
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.Zone() != "" {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
