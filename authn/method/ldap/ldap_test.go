package ldap_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/method/ldap"
	"github.com/imohiyoko/iam/authn/method/ldap/ldaptest"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

const (
	base     = "dc=example,dc=com"
	people   = "ou=people," + base
	groups   = "ou=groups," + base
	svcDN    = "cn=svc," + base
	svcPW    = "svc-secret"
	engDN    = "cn=Engineering," + groups
	salesDN  = "cn=Sales," + groups
	otherDN  = "cn=Outside,ou=elsewhere," + base
	clientIP = "192.0.2.1"
)

type env struct {
	k   *testkit.Kit
	srv *ldaptest.Server
	svc *ldap.Service
}

type fakeOrgSSO struct{ domain string }

func (f *fakeOrgSSO) SSODomainVerified(_ context.Context, _ port.Tx, _, _, email string) (bool, error) {
	return strings.HasSuffix(email, "@"+f.domain), nil
}

func (f *fakeOrgSSO) AdmitSSO(ctx context.Context, tx port.Tx, orgID string, u port.User, _, _ string) error {
	now := u.CreatedAt
	if err := tx.Memberships().Create(ctx, port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: u.RealmID,
		UserID: u.ID, OrgID: orgID, Status: port.MembershipActive, Role: port.OrgMember, CreatedAt: now, UpdatedAt: now}); err != nil {
		return err
	}
	return tx.Users().SetManagedOrg(ctx, u.RealmID, u.ID, orgID, now)
}

func setup(t *testing.T, mode ldaptest.Mode) *env {
	t.Helper()
	k := testkit.New(t)
	srv := ldaptest.New(t, mode)
	srv.Add(svcDN, map[string][]string{"cn": {"svc"}, "userPassword": {svcPW}})
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	accts := &account.Service{Crypter: k.Crypter, Clock: k.Clock,
		VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode, port.VerifiedViaOAuthProvider, port.VerifiedViaSSO}}
	o := &oauth.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Sessions: sm, Accounts: accts}
	svc := &ldap.Service{Storage: k.Storage, Crypter: k.Crypter, Clock: k.Clock, OAuth: o, Accounts: accts, Sessions: sm}
	return &env{k: k, srv: srv, svc: svc}
}

func (e *env) person(name, uuid, email string, memberOf ...string) {
	attrs := map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {name}, "entryUUID": {uuid}, "userPassword": {"pw-" + name}, "memberOf": memberOf}
	if email != "" {
		attrs["mail"] = []string{email}
	}
	e.srv.Add("uid="+name+","+people, attrs)
}

func (e *env) input(edit ...func(*ldap.ConnectionInput)) ldap.ConnectionInput {
	in := ldap.ConnectionInput{URL: e.srv.URL, CAPEM: e.srv.CAPEM, BindDN: svcDN, BindPassword: svcPW, UserBaseDN: people, TrustEmail: true,
		GroupBaseDN: groups, Sync: ldap.Sync{Enabled: true, Provision: true}}
	for _, f := range edit {
		f(&in)
	}
	return in
}

func (e *env) conn(t *testing.T, slug, owner string, in ldap.ConnectionInput) port.Connection {
	t.Helper()
	c, err := ldap.NewConnection(context.Background(), e.k.Crypter, e.k.Clock.Now(), e.k.RealmID, slug, owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c.Config, []byte(svcPW)) {
		t.Fatal("bind password stored in plaintext")
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Connections().Create(ctx, c) })
	return c
}

func (e *env) login(slug, user, pw string) (oauth.Result, error) {
	return e.svc.Login(context.Background(), e.k.RealmID, slug, ldap.Credentials{Username: user, Password: pw, Client: oauth.Client{IP: clientIP}})
}

func TestLoginSignupAndRelogin(t *testing.T) {
	for name, mode := range map[string]ldaptest.Mode{"ldaps": ldaptest.LDAPS, "starttls": ldaptest.StartTLS} {
		t.Run(name, func(t *testing.T) {
			e := setup(t, mode)
			e.person("alice", "uuid-alice", "alice@example.com")
			e.conn(t, "corp", "", e.input())
			res, err := e.login("corp", "alice", "pw-alice")
			if err != nil || !res.Created {
				t.Fatalf("first login = %+v, %v", res, err)
			}
			if got := res.Session.Session.AuthMethods; !slices.Equal(got, []string{"pwd"}) {
				t.Errorf("amr = %v, want [pwd]", got)
			}
			again, err := e.login("corp", "ALICE", "pw-alice")
			if err != nil || again.Created || again.UserID != res.UserID {
				t.Fatalf("second login = %+v, %v", again, err)
			}
			binds, _, plain := e.srv.Stats()
			if plain != 0 {
				t.Errorf("%d operations before TLS", plain)
			}
			if !slices.Contains(binds, "uid=alice,"+people) || !slices.Contains(binds, svcDN) {
				t.Errorf("binds = %v", binds)
			}
		})
	}
}

func TestLoginFailures(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.person("bob", "uuid-bob", "")
	e.conn(t, "corp", "", e.input())
	for name, c := range map[string][2]string{
		"wrong password": {"alice", "nope"},
		"empty password": {"alice", ""},
		"unknown user":   {"carol", "pw-carol"},
		"wildcard":       {"*", "pw-alice"},
		"injection":      {"alice)(uid=*", "pw-alice"},
		"control char":   {"alice\x00", "pw-alice"},
		"empty user":     {"", "pw-alice"},
	} {
		if _, err := e.login("corp", c[0], c[1]); !errors.Is(err, ldap.ErrAuthFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	binds, searches, _ := e.srv.Stats()
	for _, b := range binds {
		if b != svcDN {
			t.Errorf("unexpected successful bind as %q (an empty password must never reach the directory)", b)
		}
	}
	for _, f := range searches {
		if strings.Contains(f, "(uid=*)") || strings.Contains(f, "uid=alice)(") {
			t.Errorf("filter injection reached the directory: %s", f)
		}
	}
	// 同じ名前の項目が 2 つあれば、どちらでも bind しない。
	for i, uuid := range []string{"uuid-dup-1", "uuid-dup-2"} {
		e.srv.Add("cn=dup"+string(rune('1'+i))+","+people, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"dup"},
			"entryUUID": {uuid}, "mail": {"dup@example.com"}, "userPassword": {"pw-dup"}})
	}
	if _, err := e.login("corp", "dup", "pw-dup"); !errors.Is(err, ldap.ErrAuthFailed) {
		t.Errorf("ambiguous username: %v", err)
	}
	if binds, _, _ := e.srv.Stats(); slices.ContainsFunc(binds, func(b string) bool { return strings.HasPrefix(b, "cn=dup") }) {
		t.Errorf("bound as an ambiguous entry: %v", binds)
	}
	// メールの無い本人は登録できない（理由は本人確認の後なので返す）。
	if _, err := e.login("corp", "bob", "pw-bob"); !errors.Is(err, oauth.ErrEmailUnverified) {
		t.Errorf("no email: %v", err)
	}
	// 存在しない connection は NotFound。
	if _, err := e.login("missing", "alice", "pw-alice"); !errors.Is(err, errs.NotFound) {
		t.Errorf("missing connection: %v", err)
	}
}

func TestLoginWithoutTrustedEmail(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.conn(t, "corp", "", e.input(func(in *ldap.ConnectionInput) { in.TrustEmail = false }))
	if _, err := e.login("corp", "alice", "pw-alice"); !errors.Is(err, oauth.ErrEmailUnverified) {
		t.Fatalf("untrusted email: %v", err)
	}
}

func TestTLSIsVerified(t *testing.T) {
	e := setup(t, ldaptest.StartTLS)
	e.person("alice", "uuid-alice", "alice@example.com")
	other := ldaptest.New(t, ldaptest.LDAPS)
	for name, edit := range map[string]func(*ldap.ConnectionInput){
		"system roots": func(in *ldap.ConnectionInput) { in.CAPEM = "" },
		"wrong ca":     func(in *ldap.ConnectionInput) { in.CAPEM = other.CAPEM },
		"wrong pin":    func(in *ldap.ConnectionInput) { in.Pins = []string{other.Pin} },
		"wrong name": func(in *ldap.ConnectionInput) {
			in.URL = strings.Replace(in.URL, "127.0.0.1", "localhost", 1)
		},
	} {
		slug := strings.ReplaceAll(name, " ", "-")
		e.conn(t, slug, "", e.input(edit))
		if _, err := e.login(slug, "alice", "pw-alice"); !errors.Is(err, ldap.ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.conn(t, "pinned", "", e.input(func(in *ldap.ConnectionInput) { in.Pins = []string{e.srv.Pin} }))
	if _, err := e.login("pinned", "alice", "pw-alice"); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	binds, _, plain := e.srv.Stats()
	if plain != 0 {
		t.Fatalf("%d operations before TLS", plain)
	}
	if n := len(binds); n != 2 {
		t.Fatalf("binds = %v (failed TLS must not send credentials)", binds)
	}
}

func TestDirectoryUnavailable(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.conn(t, "badsvc", "", e.input(func(in *ldap.ConnectionInput) { in.BindPassword = "wrong" }))
	if _, err := e.login("badsvc", "alice", "pw-alice"); !errors.Is(err, ldap.ErrUnavailable) {
		t.Errorf("bad service password: %v", err)
	}
	e.conn(t, "corp", "", e.input())
	e.srv.SetDown(true)
	if _, err := e.login("corp", "alice", "pw-alice"); !errors.Is(err, ldap.ErrUnavailable) {
		t.Errorf("down: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.conn(t, "corp", "", e.input())
	e.svc.PerAccount = &ratelimit.Limiter{Cache: e.k.Cache, Clock: e.k.Clock, Window: time.Minute, Limit: 2}
	for range 2 {
		if _, err := e.login("corp", "Alice", "bad"); !errors.Is(err, ldap.ErrAuthFailed) {
			t.Fatal(err)
		}
	}
	if _, err := e.login("corp", "alice", "pw-alice"); err == nil {
		t.Fatal("rate limit not applied")
	} else if _, ok := errors.AsType[*ratelimit.ExceededError](err); !ok {
		t.Fatalf("want ExceededError, got %v", err)
	}
}

func TestOrgConnection(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@acme.example")
	e.person("eve", "uuid-eve", "eve@other.example")
	orgID := id.New(id.Org)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Orgs().Create(ctx, port.Org{ID: orgID, PublicID: id.NewExternal(id.Org), RealmID: e.k.RealmID, Kind: port.OrgShared, Name: "acme",
			CreatedAt: e.k.Clock.Now(), UpdatedAt: e.k.Clock.Now()})
	})
	e.svc.OAuth.OrgSSO = &fakeOrgSSO{domain: "acme.example"}
	if _, err := ldap.NewConnection(context.Background(), e.k.Crypter, e.k.Clock.Now(), e.k.RealmID, "", orgID, e.input()); !errors.Is(err, errs.Invalid) {
		t.Fatalf("trust_email on an org connection: %v", err)
	}
	c := e.conn(t, "", orgID, e.input(func(in *ldap.ConnectionInput) { in.TrustEmail = false }))
	// 開発・テストでなければ、Org の connection は公開のアドレスにしかつながない。
	if _, err := e.login(c.Slug, "alice", "pw-alice"); !errors.Is(err, ldap.ErrUnavailable) {
		t.Fatalf("private address: %v", err)
	}
	if binds, _, _ := e.srv.Stats(); len(binds) != 0 {
		t.Fatalf("connected to a private address: %v", binds)
	}
	e.svc.OAuth.AllowPrivateNetworks = true
	if _, err := e.login(c.Slug, "eve", "pw-eve"); !errors.Is(err, oauth.ErrSSODomainNotVerified) {
		t.Fatalf("outside domain: %v", err)
	}
	res, err := e.login(c.Slug, "alice", "pw-alice")
	if err != nil || !res.Created {
		t.Fatalf("org signup = %+v, %v", res, err)
	}
	// 管理ユーザーでない人は連携できない（ディレクトリに問い合わせる前に断る）。
	u := e.k.SeedUser(t)
	if _, err := e.svc.Link(context.Background(), e.k.RealmID, c.Slug, u.ID, ldap.Credentials{Username: "eve", Password: "pw-eve"}); !errors.Is(err, oauth.ErrNotManagedByOwner) {
		t.Fatalf("link by unmanaged user: %v", err)
	}
	// Org 専用 SSO が無効なら、Org の connection は無い。
	e.svc.OAuth.OrgSSO = nil
	if _, err := e.login(c.Slug, "alice", "pw-alice"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("org sso disabled: %v", err)
	}
}

func TestLink(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.conn(t, "corp", "", e.input())
	u := e.k.SeedUser(t)
	ident, err := e.svc.Link(context.Background(), e.k.RealmID, "corp", u.ID, ldap.Credentials{Username: "alice", Password: "pw-alice"})
	if err != nil || ident.UserID != u.ID || ident.ProviderSubject != "uuid-alice" {
		t.Fatalf("link = %+v, %v", ident, err)
	}
	if _, err := e.svc.Link(context.Background(), e.k.RealmID, "corp", u.ID, ldap.Credentials{Username: "alice", Password: "pw-alice"}); !errors.Is(err, oauth.ErrIdentityExists) {
		t.Fatalf("link twice: %v", err)
	}
	if _, err := e.svc.Link(context.Background(), e.k.RealmID, "corp", u.ID, ldap.Credentials{Username: "alice", Password: "x"}); !errors.Is(err, ldap.ErrAuthFailed) {
		t.Fatalf("link with a wrong password: %v", err)
	}
	// 連携の後は、その外部 ID でログインできる（登録はしない）。
	res, err := e.login("corp", "alice", "pw-alice")
	if err != nil || res.Created || res.UserID != u.PublicID {
		t.Fatalf("login after link = %+v, %v", res, err)
	}
}

func TestConnectionValidation(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	for name, edit := range map[string]func(*ldap.ConnectionInput){
		"plain scheme":   func(in *ldap.ConnectionInput) { in.URL = "http://ldap.example" },
		"no host":        func(in *ldap.ConnectionInput) { in.URL = "ldaps://" },
		"path":           func(in *ldap.ConnectionInput) { in.URL = "ldaps://ldap.example/dc=x" },
		"userinfo":       func(in *ldap.ConnectionInput) { in.URL = "ldaps://u:p@ldap.example" },
		"bad ca":         func(in *ldap.ConnectionInput) { in.CAPEM = "not pem" },
		"bad pin":        func(in *ldap.ConnectionInput) { in.Pins = []string{"abc"} },
		"bad bind dn":    func(in *ldap.ConnectionInput) { in.BindDN = "not a dn" },
		"no password":    func(in *ldap.ConnectionInput) { in.BindPassword = "" },
		"bad filter":     func(in *ldap.ConnectionInput) { in.UserFilter = "(objectClass=person" },
		"bad attribute":  func(in *ldap.ConnectionInput) { in.LoginAttribute = "uid)(x" },
		"bad on_missing": func(in *ldap.ConnectionInput) { in.Sync.OnMissing = "delete" },
		"short interval": func(in *ldap.ConnectionInput) { in.Sync.IntervalSeconds = 60 },
		"bad group base": func(in *ldap.ConnectionInput) { in.GroupBaseDN = "=" },
	} {
		if _, err := ldap.NewConnection(context.Background(), e.k.Crypter, e.k.Clock.Now(), e.k.RealmID, "x", "", e.input(edit)); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c, err := ldap.NewConnection(context.Background(), e.k.Crypter, e.k.Clock.Now(), e.k.RealmID, "", "", e.input(func(in *ldap.ConnectionInput) {
		in.ActiveDirectory = true
	}))
	if err != nil || c.Slug != c.ID {
		t.Fatalf("ad connection = %+v, %v", c, err)
	}
	info, err := ldap.InfoOf(c)
	if err != nil || info.LoginAttribute != "sAMAccountName" || info.IDAttribute != "objectGUID" || info.GroupAttribute != "memberOf" ||
		info.Sync.OnMissing != ldap.OnMissingSuspend || !info.CAConfigured {
		t.Fatalf("info = %+v, %v", info, err)
	}
	pw := "rotated"
	c2, changed, err := ldap.UpdateConnection(context.Background(), e.k.Crypter, c, ldap.Update{BindPassword: &pw})
	if err != nil || !slices.Equal(changed, []string{"bind_password"}) || bytes.Equal(c2.Config, c.Config) || bytes.Contains(c2.Config, []byte(pw)) {
		t.Fatalf("update = %v, %v", changed, err)
	}
	empty := ""
	if _, _, err := ldap.UpdateConnection(context.Background(), e.k.Crypter, c, ldap.Update{BindPassword: &empty}); !errors.Is(err, errs.Invalid) {
		t.Fatalf("empty password update: %v", err)
	}
}

func TestActiveDirectoryDisabledAccount(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	guid := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dn := "cn=Alice," + people
	e.srv.Add(dn, map[string][]string{"objectCategory": {"person"}, "objectClass": {"user"}, "sAMAccountName": {"alice"},
		"mail": {"alice@example.com"}, "userPassword": {"pw-alice"}, "userAccountControl": {"514"}})
	e.srv.SetRaw(dn, "objectGUID", guid)
	e.conn(t, "ad", "", e.input(func(in *ldap.ConnectionInput) { in.ActiveDirectory = true }))
	if _, err := e.login("ad", "alice", "pw-alice"); !errors.Is(err, ldap.ErrAuthFailed) {
		t.Fatalf("disabled account: %v", err)
	}
	e.srv.Add(dn, map[string][]string{"objectCategory": {"person"}, "objectClass": {"user"}, "sAMAccountName": {"alice"},
		"mail": {"alice@example.com"}, "userPassword": {"pw-alice"}, "userAccountControl": {"512"}})
	e.srv.SetRaw(dn, "objectGUID", guid)
	if _, err := e.login("ad", "alice", "pw-alice"); err != nil {
		t.Fatalf("enabled account: %v", err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Connections().GetBySlug(ctx, e.k.RealmID, "ad")
		if err != nil {
			return err
		}
		_, err = tx.Identities().GetBySubject(ctx, e.k.RealmID, c.ID, "00112233-4455-6677-8899-aabbccddeeff")
		return err
	})
}

// sync は同期を 1 回行う。
func (e *env) sync(t *testing.T, c port.Connection) ldap.SyncResult {
	t.Helper()
	res, err := e.svc.Sync(context.Background(), c, "req")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (e *env) userBySubject(t *testing.T, c port.Connection, sub string) port.User {
	t.Helper()
	var u port.User
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		i, err := tx.Identities().GetBySubject(ctx, e.k.RealmID, c.ID, sub)
		if err != nil {
			return err
		}
		u, err = tx.Users().Get(ctx, e.k.RealmID, i.UserID)
		return err
	})
	return u
}

func (e *env) suspended(t *testing.T, u port.User) bool {
	t.Helper()
	var out bool
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := account.Check(ctx, tx, u, e.k.Clock.Now(), e.k.Clock.Now())
		out = err != nil
		return nil
	})
	return out
}

// groupMembers は Group の名前 → ユーザーの公開 ID。
func (e *env) groupMembers(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		gs, err := tx.Groups().ListByOrg(ctx, e.k.RealmID, "")
		if err != nil {
			return err
		}
		for _, g := range gs {
			ms, err := tx.Groups().ListMembers(ctx, e.k.RealmID, g.ID)
			if err != nil {
				return err
			}
			out[g.Name] = []string{}
			for _, m := range ms {
				u, err := tx.Users().Get(ctx, e.k.RealmID, m.MemberID)
				if err != nil {
					return err
				}
				out[g.Name] = append(out[g.Name], u.PublicID)
			}
			slices.Sort(out[g.Name])
		}
		return nil
	})
	return out
}

func TestSync(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com", engDN, otherDN)
	e.person("bob", "uuid-bob", "bob@example.com", engDN, salesDN)
	e.person("nomail", "uuid-nomail", "")
	// 手で作った同じ名前の Group は引き取らない。
	manual := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: e.k.RealmID, Name: "Sales", CreatedAt: e.k.Clock.Now(), UpdatedAt: e.k.Clock.Now()}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Groups().Create(ctx, manual) })
	changed := 0
	e.svc.GroupsChanged = func(string) { changed++ }
	c := e.conn(t, "corp", "", e.input())

	res := e.sync(t, c)
	if !res.Complete || res.Entries != 3 || res.Provisioned != 2 || res.ProvisionSkipped != 0 || res.GroupsCreated != 1 || res.GroupConflicts != 1 || res.MembersAdded != 2 {
		t.Fatalf("first sync = %+v", res)
	}
	alice, bob := e.userBySubject(t, c, "uuid-alice"), e.userBySubject(t, c, "uuid-bob")
	want := []string{alice.PublicID, bob.PublicID}
	slices.Sort(want)
	if got := e.groupMembers(t); !slices.Equal(got["Engineering"], want) || len(got["Sales"]) != 0 || len(got) != 2 || changed != 1 {
		t.Fatalf("groups = %v (changed %d)", got, changed)
	}
	// 2 回目は何も変えない。
	if res := e.sync(t, c); res.Provisioned != 0 || res.GroupsCreated != 0 || res.MembersAdded+res.MembersRemoved+res.Suspended != 0 {
		t.Fatalf("second sync = %+v", res)
	}

	// bob がディレクトリから消える：停止し、Group から外す。alice は Group を抜ける。
	e.srv.Remove("uid=bob," + people)
	e.person("alice", "uuid-alice", "alice@example.com")
	res = e.sync(t, c)
	if res.Missing != 1 || res.Suspended != 1 || res.MembersRemoved != 2 {
		t.Fatalf("removal sync = %+v", res)
	}
	if !e.suspended(t, bob) || e.suspended(t, alice) {
		t.Fatal("bob must be suspended, alice must not")
	}
	if got := e.groupMembers(t); len(got["Engineering"]) != 0 {
		t.Fatalf("groups after removal = %v", got)
	}
	// 戻れば解除する。
	e.person("bob", "uuid-bob", "bob@example.com", engDN)
	res = e.sync(t, c)
	if res.Reactivated != 1 || res.MembersAdded != 1 || e.suspended(t, bob) {
		t.Fatalf("reactivation sync = %+v", res)
	}
	// 運営者の停止は同期で解除しない。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, _, err := e.svc.Accounts.SuspendUser(ctx, tx, e.k.RealmID, bob, account.Suspend{Category: account.CategoryTOSViolation, Reason: "spam"},
			audit.Actor{Type: "user"}, "")
		return err
	})
	e.sync(t, c)
	if !e.suspended(t, bob) {
		t.Fatal("an operator suspension was lifted by the sync")
	}
}

func TestSyncDeprovisionGuard(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	for i := range 20 {
		e.person(fmt.Sprintf("u%02d", i), fmt.Sprintf("uuid-%02d", i), fmt.Sprintf("u%02d@example.com", i))
	}
	c := e.conn(t, "corp", "", e.input())
	if res := e.sync(t, c); res.Provisioned != 20 {
		t.Fatalf("provision = %+v", res)
	}
	// 検索の基点の誤りなどで大半が見えなくなっても、全員は止めない。
	for i := range 15 {
		e.srv.Remove(fmt.Sprintf("uid=u%02d,%s", i, people))
	}
	res := e.sync(t, c)
	if !res.DeprovisionAborted || res.Suspended != 0 || res.Missing != 15 {
		t.Fatalf("guard = %+v", res)
	}
	// 障害の回は何も変えない（失敗として記録する）。
	e.srv.SetDown(true)
	if _, err := e.svc.Sync(context.Background(), c, "req"); !errors.Is(err, ldap.ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
	var failed int
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		evs, err := tx.Audit().ListByRealm(ctx, e.k.RealmID, 0, 1000)
		for _, ev := range evs {
			if strings.Contains(string(ev.Payload), `"ldap.sync.failed"`) {
				failed++
			}
		}
		return err
	})
	if failed != 1 {
		t.Fatalf("ldap.sync.failed events = %d", failed)
	}
}

func TestSyncOnMissingNone(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	c := e.conn(t, "corp", "", e.input(func(in *ldap.ConnectionInput) { in.Sync.OnMissing = ldap.OnMissingNone }))
	e.sync(t, c)
	alice := e.userBySubject(t, c, "uuid-alice")
	e.srv.Remove("uid=alice," + people)
	if res := e.sync(t, c); res.Suspended != 0 || e.suspended(t, alice) {
		t.Fatalf("on_missing none = %+v", res)
	}
}

// UserBy は Kerberos のプリンシパルの結び付け（ADR 0107）：サービスアカウントで探し、紐付いた外部 ID のユーザーを返す。
func TestUserBy(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@example.com")
	e.person("bob", "uuid-bob", "bob@example.com")
	e.srv.Add("uid=carol,"+people, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"carol"}, "entryUUID": {"uuid-carol"},
		"userPassword": {"pw-carol"}, "krbPrincipalName": {"carol@EXAMPLE.COM"}, "mail": {"carol@example.com"}})
	e.conn(t, "corp", "", e.input())
	alice, err := e.login("corp", "alice", "pw-alice")
	if err != nil {
		t.Fatal(err)
	}
	carol, err := e.login("corp", "carol", "pw-carol")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	publicID := func(internal string) string {
		var u port.User
		e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			var err error
			u, err = tx.Users().Get(ctx, e.k.RealmID, internal)
			return err
		})
		return u.PublicID
	}
	if got, err := e.svc.UserBy(ctx, e.k.RealmID, "corp", "uid", "alice"); err != nil || publicID(got) != alice.UserID {
		t.Fatalf("uid = %q, %v", got, err)
	}
	if got, err := e.svc.UserBy(ctx, e.k.RealmID, "corp", "krbPrincipalName", "carol@EXAMPLE.COM"); err != nil || publicID(got) != carol.UserID {
		t.Fatalf("krbPrincipalName = %q, %v", got, err)
	}
	for name, c := range map[string][2]string{
		"no entry":      {"uid", "nobody"},
		"not linked":    {"uid", "bob"},
		"wildcard":      {"uid", "*"},
		"injection":     {"uid", "alice)(uid=*"},
		"bad attribute": {"uid)(x", "alice"},
		"empty":         {"uid", ""},
	} {
		if _, err := e.svc.UserBy(ctx, e.k.RealmID, "corp", c[0], c[1]); !errors.Is(err, errs.NotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.UserBy(ctx, e.k.RealmID, "nope", "uid", "alice"); !errors.Is(err, errs.NotFound) {
		t.Errorf("unknown connection: %v", err)
	}
	// 1 件より多く当たれば誰にもしない。
	e.srv.Add("uid=alice2,"+people, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "entryUUID": {"uuid-alice2"}})
	if _, err := e.svc.UserBy(ctx, e.k.RealmID, "corp", "uid", "alice"); !errors.Is(err, errs.NotFound) {
		t.Errorf("two entries: %v", err)
	}
	e.srv.SetDown(true)
	if _, err := e.svc.UserBy(ctx, e.k.RealmID, "corp", "uid", "carol"); !errors.Is(err, ldap.ErrUnavailable) || !errors.Is(err, errs.Unavailable) {
		t.Errorf("down: %v", err)
	}
}

func TestUserByOrgConnection(t *testing.T) {
	e := setup(t, ldaptest.LDAPS)
	e.person("alice", "uuid-alice", "alice@acme.example")
	orgID := id.New(id.Org)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Orgs().Create(ctx, port.Org{ID: orgID, PublicID: id.NewExternal(id.Org), RealmID: e.k.RealmID, Kind: port.OrgShared, Name: "acme",
			CreatedAt: e.k.Clock.Now(), UpdatedAt: e.k.Clock.Now()})
	})
	e.svc.OAuth.OrgSSO = &fakeOrgSSO{domain: "acme.example"}
	e.svc.OAuth.AllowPrivateNetworks = true
	c := e.conn(t, "", orgID, e.input(func(in *ldap.ConnectionInput) { in.TrustEmail = false }))
	if _, err := e.svc.UserBy(context.Background(), e.k.RealmID, c.Slug, "uid", "alice"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("org connection: %v", err)
	}
	if binds, _, _ := e.srv.Stats(); len(binds) != 0 {
		t.Fatalf("connected for an org connection: %v", binds)
	}
}
