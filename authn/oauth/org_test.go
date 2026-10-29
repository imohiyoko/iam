package oauth_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// fakeOrgSSO は Org の側（ドメインの証明と管理ユーザーにすること）を模す。
type fakeOrgSSO struct {
	domain   string
	admitted []string
}

func (f *fakeOrgSSO) SSODomainVerified(_ context.Context, _ port.Tx, _, _, email string) (bool, error) {
	return len(email) > len(f.domain) && email[len(email)-len(f.domain)-1:] == "@"+f.domain, nil
}

func (f *fakeOrgSSO) AdmitSSO(ctx context.Context, tx port.Tx, orgID string, u port.User, _, _ string) error {
	f.admitted = append(f.admitted, u.PublicID)
	return tx.Users().SetManagedOrg(ctx, u.RealmID, u.ID, orgID, u.CreatedAt)
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f[host], nil
}

// orgConn は Org 専用の connection を置き、その slug を返す。
func (e *env) orgConn(t *testing.T, tokenURL string) (string, *fakeOrgSSO) {
	t.Helper()
	f := &fakeOrgSSO{domain: "acme.example"}
	e.svc.OrgSSO, e.svc.OrgRedirectURI = f, redirect
	c, err := e.svc.NewOrgConnection(context.Background(), e.k.RealmID, id.New(id.Org), oauth.OrgConnection{Issuer: "https://issuer.example",
		AuthURL: "https://issuer.example/auth?hd=x", TokenURL: tokenURL, ClientID: clientID, ClientSecret: clientSecret})
	if err != nil {
		t.Fatal(err)
	}
	if c.Slug != c.ID || c.OwnerOrgID == "" {
		t.Fatalf("org connection = %+v", c)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Connections().Create(ctx, c) })
	return c.Slug, f
}

func TestOrgConnectionValidation(t *testing.T) {
	e := setup(t)
	e.svc.OrgRedirectURI = redirect
	ok := oauth.OrgConnection{Issuer: "https://idp.example", AuthURL: "https://idp.example/a", TokenURL: "https://idp.example/t",
		ClientID: "c", ClientSecret: "s"}
	for name, edit := range map[string]func(*oauth.OrgConnection){
		"http token url": func(c *oauth.OrgConnection) { c.TokenURL = "http://idp.example/t" },
		"http issuer":    func(c *oauth.OrgConnection) { c.Issuer = "http://idp.example" },
		"no openid":      func(c *oauth.OrgConnection) { c.Scopes = []string{"email"} },
		"bad scope":      func(c *oauth.OrgConnection) { c.Scopes = []string{"openid", "a b"} },
		"no secret":      func(c *oauth.OrgConnection) { c.ClientSecret = "" },
	} {
		in := ok
		edit(&in)
		if _, err := e.svc.NewOrgConnection(context.Background(), e.k.RealmID, "org_x", in); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c, err := e.svc.NewOrgConnection(context.Background(), e.k.RealmID, "org_x", ok)
	if err != nil {
		t.Fatal(err)
	}
	// server.public_url が無ければ戻り先が相対になり、登録できない（設定の誤りで 400）。
	e.svc.OrgRedirectURI = "/login/oauth/callback"
	if _, err := e.svc.NewOrgConnection(context.Background(), e.k.RealmID, "org_x", ok); !errors.Is(err, errs.Invalid) || !strings.Contains(err.Error(), "public_url") {
		t.Errorf("no public url: %v", err)
	}
	e.svc.OrgRedirectURI = redirect
	info, err := oauth.Info(c)
	if err != nil || info.RedirectURI != redirect || len(info.Scopes) != 2 || info.Issuer != ok.Issuer {
		t.Fatalf("info = %+v, %v", info, err)
	}
}

func (e *env) authorizeVia(t *testing.T, slug, sub, email string) oauth.Complete {
	t.Helper()
	return e.authorizeSlug(t, slug, sub, email, true)
}

func TestOrgConnectionSignupAndLogin(t *testing.T) {
	e := setup(t)
	e.svc.AllowPrivateNetworks = true
	slug, f := e.orgConn(t, e.p.srv.URL+"/token")
	e.svc.Accounts.VerifiedVia = append(e.svc.Accounts.VerifiedVia, port.VerifiedViaSSO)

	// 証明していないドメインでは登録できない。
	if _, err := e.complete(t, e.authorizeVia(t, slug, "s-0", "eve@other.example")); !errors.Is(err, oauth.ErrSSODomainNotVerified) {
		t.Fatalf("outside domain: %v", err)
	}
	res, err := e.complete(t, e.authorizeVia(t, slug, "s-1", "sam@acme.example"))
	if err != nil || !res.Created || len(f.admitted) != 1 || f.admitted[0] != res.UserID {
		t.Fatalf("signup = %+v, %v (admitted %v)", res, err, f.admitted)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, e.k.RealmID, res.UserID)
		if err != nil {
			return err
		}
		es, err := tx.Emails().ListByUser(ctx, e.k.RealmID, u.ID)
		if err != nil || len(es) != 1 || es[0].VerifiedVia != port.VerifiedViaSSO {
			t.Fatalf("emails = %+v, %v", es, err)
		}
		// 管理ユーザーでなくなると、Org の connection ではログインできない。
		return tx.Users().SetManagedOrg(ctx, e.k.RealmID, u.ID, "", u.CreatedAt)
	})
	if _, err := e.complete(t, e.authorizeVia(t, slug, "s-1", "sam@acme.example")); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("login of unmanaged user: %v", err)
	}
	// 連携も、その Org の管理ユーザーだけ。
	if _, err := e.svc.StartLink(context.Background(), e.k.RealmID, slug, "", id.New(id.User)); err == nil {
		t.Fatal("link by unknown user succeeded")
	}
	// Org の側が無ければ（フィーチャーがオフ）、Org の connection は無いものとみなす。
	e.svc.OrgSSO = nil
	if _, err := e.svc.Start(context.Background(), e.k.RealmID, slug, ""); !errors.Is(err, errs.NotFound) {
		t.Fatalf("start without OrgSSO: %v", err)
	}
}

// Org が設定したトークンエンドポイントは、公開のアドレスでなければつながない（SSRF）。
func TestOrgConnectionTokenEndpointMustBePublic(t *testing.T) {
	e := setup(t)
	e.svc.Accounts.VerifiedVia = append(e.svc.Accounts.VerifiedVia, port.VerifiedViaSSO)
	slug, _ := e.orgConn(t, e.p.srv.URL+"/token") // 127.0.0.1
	if _, err := e.complete(t, e.authorizeVia(t, slug, "s-1", "sam@acme.example")); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("loopback token endpoint: %v", err)
	}
	e.svc.Resolver = fakeResolver{"idp.acme.example": {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.5")}}
	slug2, _ := e.orgConn(t, "https://idp.acme.example/token")
	if _, err := e.complete(t, e.authorizeVia(t, slug2, "s-1", "sam@acme.example")); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("name resolving to a private address: %v", err)
	}
	// realm 共通の connection（運営者が設定）は確かめない。
	if _, err := e.complete(t, e.authorize(t, "s-2", "bob@example.com", true)); err != nil {
		t.Fatalf("realm connection: %v", err)
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "255.255.255.255": false, "224.0.0.1": false, "::1": false, "fe80::1": false,
		"fd00::1": false, "::ffff:10.0.0.1": false, "::ffff:8.8.8.8": true, "64:ff9b::a00:1": false, "2002:a00:1::": false,
	} {
		if got := oauth.PublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("PublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}
