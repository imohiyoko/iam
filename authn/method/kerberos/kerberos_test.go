package kerberos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"

	"github.com/imohiyoko/iam/authn/method"
	kt "github.com/imohiyoko/iam/authn/method/kerberos/kerberostest"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

type keys struct{}

func (keys) MasterKey(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{1}, pii.KeySize), nil
}
func (keys) CurrentMasterKeyID(context.Context) (string, error) { return "mk_1", nil }
func (keys) IndexKey(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{2}, pii.KeySize), nil
}
func (keys) CurrentIndexKeyID(context.Context) (string, error) { return "ik_1", nil }

// fixture は方式と、メモリの Storage と、2 人のユーザー。
type fixture struct {
	k     *kt.KDC
	m     *Method
	st    port.Storage
	realm string
	users []string
	// resolved は結び付けの規則（email・ldap）の偽物の引き当ての呼び出し。
	resolved []string
	// directory は ldap の規則で返すユーザー（値ごと）。
	directory map[string]string
	emails    map[string]string
}

func newFixture(t *testing.T, rc RealmConfig, entries ...kt.Entry) *fixture {
	t.Helper()
	k := kt.New(t, entries...)
	if rc.Keytab == "" {
		rc.Keytab = k.Path
	}
	if rc.ServicePrincipal == "" {
		rc.ServicePrincipal = kt.SPN
	}
	kit := testkit.New(t)
	m, err := New(rc, method.Scoped(kit.Cache, Name, "r"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{k: k, m: m, st: kit.Storage, realm: id.New(id.Realm), users: []string{id.New(id.User), id.New(id.User)},
		directory: map[string]string{}, emails: map[string]string{}}
	if err := f.st.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		for _, u := range f.users {
			if err := pii.New(keys{}).CreateDataKey(ctx, tx.DataKeys(), u, time.Now()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// EmailUser と DirectoryUser は port.MethodPrincipals の偽物。
func (f *fixture) EmailUser(_ context.Context, email string) (string, error) {
	f.resolved = append(f.resolved, "email:"+email)
	if u, ok := f.emails[email]; ok {
		return u, nil
	}
	return "", errs.New(errs.KindNotFound, "user")
}

func (f *fixture) DirectoryUser(_ context.Context, conn, attr, value string) (string, error) {
	f.resolved = append(f.resolved, "ldap:"+conn+":"+attr+":"+value)
	if value == "down@"+kt.Realm {
		return "", errs.New(errs.KindUnavailable, "directory down")
	}
	if u, ok := f.directory[value]; ok {
		return u, nil
	}
	return "", errs.New(errs.KindNotFound, "user")
}

func (f *fixture) env(tx port.Tx, userID string, usage port.MethodUsage, token []byte) port.MethodEnv {
	e := port.MethodEnv{RealmID: f.realm, UserID: userID, Usage: usage, Now: time.Now(), Negotiate: token, ClientIP: "192.0.2.10"}
	st := &method.Store{Tx: tx, Crypter: pii.New(keys{}), RealmID: f.realm, Info: f.m.Info(), Now: time.Now()}
	if tx == nil {
		st.Storage = f.st
	}
	e.Credentials = st
	if usage == port.UsageFirstFactor {
		e.Principals = f
	}
	return e
}

// login は 1要素目をコアと同じ形で呼ぶ（Begin と Complete はトランザクションの外）。
func (f *fixture) login(t *testing.T, token []byte) (port.MethodResult, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := f.m.Begin(ctx, f.env(nil, "", port.UsageFirstFactor, nil), port.MethodRequest{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return f.m.Complete(ctx, f.env(nil, "", port.UsageFirstFactor, token), port.MethodRequest{State: ch.State})
}

// enroll は本人の登録（始めはトランザクションの外、完了は中）。
func (f *fixture) enroll(t *testing.T, userID string, token []byte) (port.MethodEnrollment, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := f.m.EnrollBegin(ctx, f.env(nil, userID, "", token), port.MethodRequest{})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	var out port.MethodEnrollment
	err = f.st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = f.m.EnrollComplete(ctx, f.env(tx, userID, "", nil), port.MethodRequest{State: ch.State})
		return err
	})
	return out, err
}

func rejectedErr(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("err = %v, want authentication failed", err)
	}
}

func TestEnrollAndLogin(t *testing.T) {
	f := newFixture(t, RealmConfig{})
	en, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{}))
	if err != nil {
		t.Fatal(err)
	}
	var s summary
	if err := json.Unmarshal(en.Payload, &s); err != nil || s.Principal != "alice@"+kt.Realm {
		t.Fatalf("summary = %s, %v", en.Payload, err)
	}
	r, err := f.login(t, f.k.Token(t, kt.Opts{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Credential.ID != en.Credential.ID || r.Credential.UserID != f.users[0] || !slices.Equal(r.AMR, []string{"wia"}) {
		t.Fatalf("result = %+v", r)
	}
	// SPNEGO で包まないトークンも受ける。
	if _, err := f.login(t, f.k.Token(t, kt.Opts{Raw: true})); err != nil {
		t.Fatalf("raw token: %v", err)
	}
	// 登録していないプリンシパル。
	_, err = f.login(t, f.k.Token(t, kt.Opts{CName: []string{"bob"}}))
	rejectedErr(t, err)
	// 同じプリンシパルを別の人が登録できない。
	if _, err := f.enroll(t, f.users[1], f.k.Token(t, kt.Opts{})); !errors.Is(err, ErrExists) {
		t.Fatalf("second enroll = %v", err)
	}
	// 登録の始めはトークンを求める。形の誤りは 400。
	if _, err := f.m.EnrollBegin(context.Background(), f.env(nil, f.users[1], "", nil), port.MethodRequest{}); !errors.Is(err, port.ErrNegotiate) {
		t.Fatalf("enroll without token = %v", err)
	}
	if _, err := f.m.EnrollBegin(context.Background(), f.env(nil, f.users[1], "", []byte("x")), port.MethodRequest{}); !errors.Is(err, errs.Invalid) {
		t.Fatalf("enroll with a bad token = %v", err)
	}
}

func TestEnrollLimit(t *testing.T) {
	f := newFixture(t, RealmConfig{MaxCredentials: 1})
	if _, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{CName: []string{"alice2"}})); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v", err)
	}
}

func TestNegotiateRequired(t *testing.T) {
	f := newFixture(t, RealmConfig{})
	_, err := f.login(t, nil)
	if !errors.Is(err, port.ErrNegotiate) || errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("err = %v", err)
	}
	// 空のトークン（形の誤り）はチャレンジを繰り返さずに拒む。
	_, err = f.login(t, []byte{})
	rejectedErr(t, err)
}

func TestFirstFactorOnly(t *testing.T) {
	f := newFixture(t, RealmConfig{})
	ctx := context.Background()
	if _, err := f.m.Begin(ctx, f.env(nil, f.users[0], port.UsageSecondFactor, nil), port.MethodRequest{}); err == nil {
		t.Fatal("second factor begin accepted")
	}
	if _, err := f.m.Complete(ctx, f.env(nil, f.users[0], port.UsageSecondFactor, f.k.Token(t, kt.Opts{})), port.MethodRequest{}); err == nil {
		t.Fatal("second factor complete accepted")
	}
	if (&Method{}).Info().Supports(port.UsageSecondFactor) {
		t.Fatal("kerberos supports the second factor")
	}
}

func TestUnconfigured(t *testing.T) {
	var m Method
	_, err := m.Complete(context.Background(), port.MethodEnv{Usage: port.UsageFirstFactor, Negotiate: []byte{1}}, port.MethodRequest{})
	rejectedErr(t, err)
}

func TestRejectsBadTickets(t *testing.T) {
	f := newFixture(t, RealmConfig{ServicePrincipal: kt.SPN + "@" + kt.Realm, AcceptedRealms: []string{kt.Realm}},
		kt.Entry{SPN: kt.SPN, Realm: kt.Realm, EType: etypeID.AES256_CTS_HMAC_SHA1_96},
		kt.Entry{SPN: "HTTP/other.example.com", Realm: kt.Realm, EType: etypeID.AES256_CTS_HMAC_SHA1_96},
		kt.Entry{SPN: kt.SPN, Realm: kt.Realm, EType: etypeID.RC4_HMAC},
		kt.Entry{SPN: kt.SPN, Realm: "OTHER.EXAMPLE.COM", EType: etypeID.AES256_CTS_HMAC_SHA1_96},
	)
	for _, cname := range []string{"alice", "Alice"} {
		if _, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{CName: []string{cname}})); err != nil {
			t.Fatal(err)
		}
	}
	forged := kt.New(t, kt.Entry{SPN: kt.SPN, Realm: kt.Realm, Password: "another", EType: etypeID.AES256_CTS_HMAC_SHA1_96})
	now := time.Now().UTC()
	cases := map[string][]byte{
		"another service":           f.k.Token(t, kt.Opts{SPN: "HTTP/other.example.com"}),
		"service in another realm":  f.k.Token(t, kt.Opts{SRealm: "OTHER.EXAMPLE.COM"}),
		"client realm not accepted": f.k.Token(t, kt.Opts{CRealm: "OTHER.EXAMPLE.COM"}),
		"rc4":                       f.k.Token(t, kt.Opts{EType: etypeID.RC4_HMAC}),
		"forged service key":        forged.Token(t, kt.Opts{}),
		"expired":                   f.k.Token(t, kt.Opts{Start: now.Add(-20 * time.Hour), End: now.Add(-10 * time.Hour)}),
		"not yet valid":             f.k.Token(t, kt.Opts{Start: now.Add(time.Hour), End: now.Add(10 * time.Hour)}),
		"authenticator for another": f.k.Token(t, kt.Opts{AuthName: []string{"Alice"}}),
		"clock skew":                f.k.Token(t, kt.Opts{AuthTime: now.Add(-time.Hour)}),
		"service principal client":  f.k.Token(t, kt.Opts{CName: []string{"host", "pc1"}}),
		"enterprise name":           f.k.Token(t, kt.Opts{CName: []string{"alice@corp.example.com"}}),
		"ntlm":                      append([]byte("NTLMSSP\x00"), 1, 0, 0, 0),
		"ntlm in spnego":            kt.SPNEGOInit(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}}, []byte("NTLMSSP\x00\x01\x00\x00\x00")),
		"kerberos not first":        f.k.Token(t, kt.Opts{MechTypes: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}, gssapi.OIDKRB5.OID()}}),
		"no mech types":             kt.SPNEGOInit(t, []asn1.ObjectIdentifier{}, kt.KRB5Token(t, gssapi.OIDKRB5.OID(), []byte{1, 0}, []byte{0x30, 0})),
		"krb error token":           kt.KRB5Token(t, gssapi.OIDKRB5.OID(), []byte{3, 0}, []byte{0x30, 0}),
		"garbage":                   []byte{0x60, 0x03, 0x06, 0x01, 0x00},
		"too large":                 make([]byte, maxToken+1),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.login(t, tok)
			rejectedErr(t, err)
			t.Log(err)
		})
	}
}

func TestReplay(t *testing.T) {
	f := newFixture(t, RealmConfig{})
	if _, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{})); err != nil {
		t.Fatal(err)
	}
	tok := f.k.Token(t, kt.Opts{})
	if _, err := f.login(t, tok); err != nil {
		t.Fatal(err)
	}
	_, err := f.login(t, tok)
	rejectedErr(t, err)

	// 別のインスタンス（gokrb5 のプロセスの中のキャッシュを通った後）でも、共有の EphemeralStore で拒む。
	ap, err := parseAPReq(f.k.Token(t, kt.Opts{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.m.replayed(ctx, ap); err != nil {
		t.Fatal(err)
	}
	rejectedErr(t, f.m.replayed(ctx, ap))
}

func TestCaseInsensitiveNames(t *testing.T) {
	f := newFixture(t, RealmConfig{CaseInsensitiveNames: true})
	if _, err := f.enroll(t, f.users[0], f.k.Token(t, kt.Opts{CName: []string{"Alice"}})); err != nil {
		t.Fatal(err)
	}
	r, err := f.login(t, f.k.Token(t, kt.Opts{CName: []string{"ALICE"}}))
	if err != nil || r.Credential.UserID != f.users[0] {
		t.Fatalf("login = %+v, %v", r, err)
	}
	// 既定は区別する。
	g := newFixture(t, RealmConfig{})
	if _, err := g.enroll(t, g.users[0], g.k.Token(t, kt.Opts{CName: []string{"Alice"}})); err != nil {
		t.Fatal(err)
	}
	_, err = g.login(t, g.k.Token(t, kt.Opts{CName: []string{"alice"}}))
	rejectedErr(t, err)
}

func TestMappingEmail(t *testing.T) {
	f := newFixture(t, RealmConfig{Mapping: Mapping{Rule: RuleEmail, EmailDomains: map[string]string{kt.Realm: "example.com"}}})
	f.emails["alice@example.com"] = f.users[0]
	r, err := f.login(t, f.k.Token(t, kt.Opts{}))
	if err != nil || r.Credential.UserID != f.users[0] {
		t.Fatalf("login = %+v, %v", r, err)
	}
	// 2 回目は同じ認証情報を使う。
	r2, err := f.login(t, f.k.Token(t, kt.Opts{}))
	if err != nil || r2.Credential.ID != r.Credential.ID {
		t.Fatalf("second login = %+v, %v", r2, err)
	}
	// メールが別の人に移れば、前の結び付けを無効化して作り直す。
	f.emails["alice@example.com"] = f.users[1]
	r3, err := f.login(t, f.k.Token(t, kt.Opts{}))
	if err != nil || r3.Credential.UserID != f.users[1] || r3.Credential.ID == r.Credential.ID {
		t.Fatalf("remapped login = %+v, %v", r3, err)
	}
	cs, err := f.env(nil, "", "", nil).Credentials.List(context.Background(), f.users[0])
	if err != nil || len(cs) != 0 {
		t.Fatalf("old mapping = %v, %v", cs, err)
	}
	// 引き当てられなければ拒む。
	_, err = f.login(t, f.k.Token(t, kt.Opts{CName: []string{"bob"}}))
	rejectedErr(t, err)
	if !slices.Contains(f.resolved, "email:bob@example.com") {
		t.Fatalf("resolved = %v", f.resolved)
	}
	// 本人の登録は使わない。
	if _, err := f.m.EnrollBegin(context.Background(), f.env(nil, f.users[0], "", f.k.Token(t, kt.Opts{})), port.MethodRequest{}); !errors.Is(err, errNotEnrollable) {
		t.Fatalf("enroll = %v", err)
	}
}

func TestMappingLDAP(t *testing.T) {
	f := newFixture(t, RealmConfig{Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "corp-ad"}}})
	f.directory["alice@"+kt.Realm] = f.users[0]
	r, err := f.login(t, f.k.Token(t, kt.Opts{}))
	if err != nil || r.Credential.UserID != f.users[0] {
		t.Fatalf("login = %+v, %v", r, err)
	}
	if !slices.Contains(f.resolved, "ldap:corp-ad:userPrincipalName:alice@"+kt.Realm) {
		t.Fatalf("resolved = %v", f.resolved)
	}
	// ディレクトリの障害は利用者の失敗にしない。
	_, err = f.login(t, f.k.Token(t, kt.Opts{CName: []string{"down"}}))
	if !errors.Is(err, errs.Unavailable) {
		t.Fatalf("err = %v", err)
	}
	// 名前で探す。
	g := newFixture(t, RealmConfig{Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "corp-ad", Attribute: "sAMAccountName", Value: ValueName}}})
	g.directory["alice"] = g.users[1]
	r, err = g.login(t, g.k.Token(t, kt.Opts{}))
	if err != nil || r.Credential.UserID != g.users[1] {
		t.Fatalf("login = %+v, %v", r, err)
	}
}

func TestMappingWithoutResolver(t *testing.T) {
	f := newFixture(t, RealmConfig{Mapping: Mapping{Rule: RuleEmail}})
	e := f.env(nil, "", port.UsageFirstFactor, f.k.Token(t, kt.Opts{}))
	e.Principals = nil
	if _, err := f.m.Complete(context.Background(), e, port.MethodRequest{}); err == nil || errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrolledRuleOnly(t *testing.T) {
	// email の規則で作った結び付けは、enrollment に戻すと使わない。
	k := kt.New(t)
	st := testkit.New(t).Storage
	email, err := New(RealmConfig{Keytab: k.Path, ServicePrincipal: kt.SPN, Mapping: Mapping{Rule: RuleEmail}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{k: k, m: email, st: st, realm: id.New(id.Realm), users: []string{id.New(id.User)}, emails: map[string]string{}}
	if err := st.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return pii.New(keys{}).CreateDataKey(ctx, tx.DataKeys(), f.users[0], time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	f.emails["alice@corp.example.com"] = f.users[0]
	if _, err := f.login(t, k.Token(t, kt.Opts{})); err != nil {
		t.Fatal(err)
	}
	if f.m, err = New(RealmConfig{Keytab: k.Path, ServicePrincipal: kt.SPN}, nil); err != nil {
		t.Fatal(err)
	}
	_, err = f.login(t, k.Token(t, kt.Opts{}))
	rejectedErr(t, err)
}

func TestConfig(t *testing.T) {
	k := kt.New(t)
	rc4 := kt.New(t, kt.Entry{SPN: kt.SPN, Realm: kt.Realm, EType: etypeID.RC4_HMAC})
	two := kt.New(t, kt.Entry{SPN: kt.SPN, Realm: kt.Realm, EType: etypeID.AES256_CTS_HMAC_SHA1_96},
		kt.Entry{SPN: kt.SPN, Realm: "OTHER.EXAMPLE.COM", EType: etypeID.AES256_CTS_HMAC_SHA1_96})
	ok := func(rc RealmConfig) RealmConfig {
		if rc.Keytab == "" {
			rc.Keytab = k.Path
		}
		if rc.ServicePrincipal == "" {
			rc.ServicePrincipal = kt.SPN
		}
		return rc
	}
	bad := map[string]RealmConfig{
		"no keytab":          {ServicePrincipal: kt.SPN},
		"missing keytab":     {Keytab: "/nonexistent/http.keytab", ServicePrincipal: kt.SPN},
		"no spn":             {Keytab: k.Path},
		"spn without host":   ok(RealmConfig{ServicePrincipal: "HTTP"}),
		"spn not in keytab":  ok(RealmConfig{ServicePrincipal: "HTTP/other.example.com"}),
		"spn in other realm": ok(RealmConfig{ServicePrincipal: kt.SPN + "@OTHER.EXAMPLE.COM"}),
		"rc4 only":           {Keytab: rc4.Path, ServicePrincipal: kt.SPN},
		"ambiguous realm":    {Keytab: two.Path, ServicePrincipal: kt.SPN},
		"bad realm":          ok(RealmConfig{AcceptedRealms: []string{"BAD REALM"}}),
		"skew":               ok(RealmConfig{MaxClockSkew: "1h"}),
		"limit":              ok(RealmConfig{MaxCredentials: -1}),
		"rule":               ok(RealmConfig{Mapping: Mapping{Rule: "subject"}}),
		"ldap without conn":  ok(RealmConfig{Mapping: Mapping{Rule: RuleLDAP}}),
		"ldap bad attribute": ok(RealmConfig{Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "c", Attribute: "a)(b"}}}),
		"ldap bad value":     ok(RealmConfig{Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "c", Value: "dn"}}}),
		"ldap name with two realms": ok(RealmConfig{AcceptedRealms: []string{kt.Realm, "B.EXAMPLE"},
			Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "c", Value: ValueName}}}),
		"email unknown realm":  ok(RealmConfig{Mapping: Mapping{Rule: RuleEmail, EmailDomains: map[string]string{"B.EXAMPLE": "b.example"}}}),
		"email bad domain":     ok(RealmConfig{Mapping: Mapping{Rule: RuleEmail, EmailDomains: map[string]string{kt.Realm: "a@b"}}}),
		"enrollment with ldap": ok(RealmConfig{Mapping: Mapping{LDAP: LDAPMapping{Connection: "c"}}}),
	}
	for name, rc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := New(rc, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, rc := range map[string]RealmConfig{
		"default":        ok(RealmConfig{}),
		"rc4 allowed":    {Keytab: rc4.Path, ServicePrincipal: kt.SPN, AllowRC4: true},
		"explicit realm": {Keytab: two.Path, ServicePrincipal: kt.SPN + "@OTHER.EXAMPLE.COM"},
		"ldap":           ok(RealmConfig{Mapping: Mapping{Rule: RuleLDAP, LDAP: LDAPMapping{Connection: "c"}}}),
		"email":          ok(RealmConfig{Mapping: Mapping{Rule: RuleEmail}}),
		"trusted realms": ok(RealmConfig{AcceptedRealms: []string{kt.Realm, "EMEA." + kt.Realm}, MaxClockSkew: "2m"}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(rc, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSetup(t *testing.T) {
	k := kt.New(t)
	decode := func(y string) func(any) error {
		return func(v any) error {
			c := v.(*Config)
			*c = Config{Realms: map[string]RealmConfig{}}
			for _, line := range strings.Split(y, ";") {
				slug, spn, _ := strings.Cut(line, "=")
				c.Realms[slug] = RealmConfig{Keytab: k.Path, ServicePrincipal: spn}
			}
			return nil
		}
	}
	a, err := (&Method{}).Setup(context.Background(), port.MethodSetup{RealmSlug: "default", Decode: decode("default=" + kt.SPN)})
	if err != nil || a == nil {
		t.Fatalf("setup = %v, %v", a, err)
	}
	if a, err := (&Method{}).Setup(context.Background(), port.MethodSetup{RealmSlug: "other", Decode: decode("default=" + kt.SPN)}); err != nil || a != nil {
		t.Fatalf("realm without settings = %v, %v", a, err)
	}
	// 他の realm の誤りでも起動を止める。
	if _, err := (&Method{}).Setup(context.Background(), port.MethodSetup{RealmSlug: "default",
		Decode: decode("default=" + kt.SPN + ";b=HTTP/nope.example.com")}); err == nil {
		t.Fatal("bad settings of another realm accepted")
	}
}
