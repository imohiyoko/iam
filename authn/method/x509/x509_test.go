package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
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

// fixture はルート・中間 CA・レスポンダーと、メモリの Storage。
type fixture struct {
	root, inter *ca
	resp        *responder
	rootResp    *responder
	url         string
	st          port.Storage
	realm       string
	users       []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	// 中間 CA の失効はルートの CRL で確かめる。
	rootResp, rootSrv := newResponder(t, nil)
	f := &fixture{root: newCA(t, "Root", nil), rootResp: rootResp}
	rootResp.issuer = f.root
	f.inter = newCA(t, "Issuing", f.root, rootSrv.URL+"/crl")
	resp, srv := newResponder(t, f.inter)
	f.resp, f.url = resp, srv.URL
	f.st, f.realm = testkit.New(t).Storage, id.New(id.Realm)
	f.users = []string{id.New(id.User), id.New(id.User)}
	if err := f.st.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		for _, u := range f.users {
			if err := pii.New(keys{}).CreateDataKey(ctx, tx.DataKeys(), u, t0); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) leaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	if o.cn == "" {
		o.cn = "alice"
	}
	if o.ocsp == nil {
		o.ocsp = []string{f.url + "/ocsp"}
	}
	if o.crl == nil {
		o.crl = []string{f.url + "/crl"}
	}
	return newLeaf(t, f.inter, o)
}

func (f *fixture) method(t *testing.T, edit func(*RealmConfig)) *Method {
	t.Helper()
	rc := RealmConfig{TrustAnchors: []string{pemOf(f.root.cert)}}
	if edit != nil {
		edit(&rc)
	}
	m, err := New(rc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := method.Check(m); err != nil {
		t.Fatal(err)
	}
	return m
}

func chainOf(cs ...*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

// call は方式をコアと同じ形で呼ぶ（ログインと登録の始めはトランザクションの外、登録の完了はトランザクションの中。ADR 0101）。
type call struct {
	m      *Method
	f      *fixture
	userID string
	usage  port.MethodUsage
}

func (c call) env(tx port.Tx, chain [][]byte) port.MethodEnv {
	e := port.MethodEnv{RealmID: c.f.realm, UserID: c.userID, Usage: c.usage, Now: t0, ClientCertificates: chain}
	st := &method.Store{Tx: tx, Crypter: pii.New(keys{}), RealmID: c.f.realm, Info: c.m.Info(), Now: t0}
	if tx == nil {
		st.Storage = c.f.st
	}
	e.Credentials = st
	return e
}

func (c call) login(t *testing.T, begin, complete [][]byte) (port.MethodResult, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := c.m.Begin(ctx, c.env(nil, begin), port.MethodRequest{})
	if err != nil {
		return port.MethodResult{}, err
	}
	return c.m.Complete(ctx, c.env(nil, complete), port.MethodRequest{State: ch.State})
}

func (c call) enroll(t *testing.T, chain [][]byte) (port.MethodEnrollment, error) {
	t.Helper()
	return c.enrollWith(t, chain, chain)
}

func (c call) enrollWith(t *testing.T, begin, complete [][]byte) (port.MethodEnrollment, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := c.m.EnrollBegin(ctx, c.env(nil, begin), port.MethodRequest{})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	var en port.MethodEnrollment
	err = c.f.st.Tx(ctx, func(ctx context.Context, tx port.Tx) (err error) {
		en, err = c.m.EnrollComplete(ctx, c.env(tx, complete), port.MethodRequest{State: ch.State})
		return err
	})
	return en, err
}

func failed(err error) bool { return errors.Is(err, errs.AuthenticationFailed) }

func TestEnrollAndLoginByFingerprint(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, nil)
	alice := f.leaf(t, leafOpts{})
	chain := chainOf(alice, f.inter.cert)
	en, err := call{m: m, f: f, userID: f.users[0]}.enroll(t, chain)
	if err != nil {
		t.Fatal(err)
	}
	var sum summary
	if err := json.Unmarshal(en.Payload, &sum); err != nil || sum.Fingerprint != Fingerprint(alice.Raw) || sum.Mapping != MappingFingerprint {
		t.Fatalf("enroll payload = %s, %v", en.Payload, err)
	}
	// 1要素目：証明書から本人の認証情報を引く。ハードウェアの CA でなければ pop。
	r, err := call{m: m, f: f, usage: port.UsageFirstFactor}.login(t, chain, chain)
	if err != nil || r.Credential.ID != en.Credential.ID || r.Credential.UserID != f.users[0] || !slices.Equal(r.AMR, []string{"pop"}) {
		t.Fatalf("login = %+v, %v", r, err)
	}
	// 2要素目は本人のものに限る。
	if _, err := (call{m: m, f: f, userID: f.users[1], usage: port.UsageSecondFactor}).login(t, chain, chain); !failed(err) {
		t.Fatalf("second factor of another user = %v", err)
	}
	if _, err := (call{m: m, f: f, userID: f.users[0], usage: port.UsageSecondFactor}).login(t, chain, chain); err != nil {
		t.Fatalf("second factor = %v", err)
	}
	// 登録を始めた証明書と違う証明書では完了できない。
	if _, err := (call{m: m, f: f, userID: f.users[1]}).enrollWith(t, chainOf(f.leaf(t, leafOpts{}), f.inter.cert), chain); !failed(err) {
		t.Fatalf("certificate switched during the enrollment = %v", err)
	}
	// 同じ証明書は別の人が登録できない。
	if _, err := (call{m: m, f: f, userID: f.users[1]}).enroll(t, chain); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate enrollment = %v", err)
	}
	// 登録していない証明書（同じ人の更新後でも、指紋の規則では別物）は通らない。
	renewed := f.leaf(t, leafOpts{})
	if _, err := (call{m: m, f: f, usage: port.UsageFirstFactor}).login(t, chainOf(renewed, f.inter.cert), chainOf(renewed, f.inter.cert)); !failed(err) {
		t.Fatalf("unenrolled certificate = %v", err)
	}
	// フローを始めた証明書と違う証明書では完了できない。
	if _, err := (call{m: m, f: f, usage: port.UsageFirstFactor}).login(t, chainOf(renewed, f.inter.cert), chain); !failed(err) {
		t.Fatalf("certificate switched during the flow = %v", err)
	}
	// 証明書が無ければ始められない。
	if _, err := (call{m: m, f: f, usage: port.UsageFirstFactor}).login(t, nil, nil); !failed(err) {
		t.Fatalf("no certificate = %v", err)
	}
}

func TestMappingUPNSurvivesRenewal(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, func(rc *RealmConfig) { rc.Mapping = MappingUPN })
	first := f.leaf(t, leafOpts{upns: []string{"Alice@Corp.Example"}})
	if _, err := (call{m: m, f: f, userID: f.users[0]}).enroll(t, chainOf(first, f.inter.cert)); err != nil {
		t.Fatal(err)
	}
	renewed := f.leaf(t, leafOpts{upns: []string{"alice@corp.example"}})
	r, err := call{m: m, f: f, usage: port.UsageFirstFactor}.login(t, chainOf(renewed, f.inter.cert), chainOf(renewed, f.inter.cert))
	if err != nil || r.Credential.UserID != f.users[0] {
		t.Fatalf("login with renewed certificate = %+v, %v", r, err)
	}
	// UPN が無い・2つある証明書は拒む（誰のものか決まらない）。
	for _, upns := range [][]string{nil, {"a@corp.example", "b@corp.example"}} {
		c := f.leaf(t, leafOpts{upns: upns, emails: []string{"x@corp.example"}})
		if _, err := (call{m: m, f: f, usage: port.UsageFirstFactor}).login(t, chainOf(c, f.inter.cert), chainOf(c, f.inter.cert)); !failed(err) {
			t.Errorf("upns %v = %v", upns, err)
		}
	}
}

func TestMappingEmailAndDN(t *testing.T) {
	f := newFixture(t)
	c := f.leaf(t, leafOpts{emails: []string{"Bob@Example.com"}, cn: "bob"})
	p := f.method(t, func(rc *RealmConfig) { rc.Mapping = MappingEmail }).p
	if v, err := p.identifier(c); err != nil || v != "bob@example.com" {
		t.Fatalf("email = %q, %v", v, err)
	}
	p = f.method(t, func(rc *RealmConfig) { rc.Mapping = MappingSubjectDN }).p
	if v, err := p.identifier(c); err != nil || v != "CN=bob,O=Example" {
		t.Fatalf("dn = %q, %v", v, err)
	}
	two := f.leaf(t, leafOpts{emails: []string{"a@example.com", "b@example.com"}})
	p = f.method(t, func(rc *RealmConfig) { rc.Mapping = MappingEmail }).p
	if _, err := p.identifier(two); !failed(err) {
		t.Fatalf("two emails = %v", err)
	}
}

func TestChainValidation(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationNone })
	other := newCA(t, "Other", nil)
	otherLeaf := newLeaf(t, other, leafOpts{cn: "mallory"})
	cases := map[string][][]byte{
		"untrusted anchor":      chainOf(otherLeaf, other.cert),
		"expired":               chainOf(f.leaf(t, leafOpts{notAfter: t0.Add(-time.Minute)}), f.inter.cert),
		"missing intermediate":  chainOf(f.leaf(t, leafOpts{})),
		"server auth only":      chainOf(f.leaf(t, leafOpts{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}), f.inter.cert),
		"any eku":               chainOf(f.leaf(t, leafOpts{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}), f.inter.cert),
		"no digital signature":  chainOf(f.leaf(t, leafOpts{ku: x509.KeyUsageKeyEncipherment}), f.inter.cert),
		"CA as client":          chainOf(f.leaf(t, leafOpts{isCA: true}), f.inter.cert),
		"garbage":               {[]byte("not a certificate")},
		"too long":              chainOf(f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert, f.inter.cert),
		"intermediate as leaf":  chainOf(f.inter.cert),
		"root presented alone":  chainOf(f.root.cert),
		"empty first":           {nil},
		"oversized certificate": {bytes.Repeat([]byte{0x30}, maxCertBytes+1)},
	}
	for name, chain := range cases {
		if _, err := m.check(context.Background(), port.MethodEnv{Now: t0, ClientCertificates: chain}); !failed(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 中間 CA を設定で補えば、クライアントが送らなくてよい。
	m = f.method(t, func(rc *RealmConfig) {
		rc.Revocation.Mode, rc.Intermediates = RevocationNone, []string{pemOf(f.inter.cert)}
	})
	if _, err := m.check(context.Background(), port.MethodEnv{Now: t0, ClientCertificates: chainOf(f.leaf(t, leafOpts{}))}); err != nil {
		t.Fatalf("configured intermediate = %v", err)
	}
	// 独自の拡張鍵用途（スマートカードのログイン）を受ける設定。
	m = f.method(t, func(rc *RealmConfig) {
		rc.Revocation.Mode, rc.ExtKeyUsages = RevocationNone, []string{"smartcard_logon"}
	})
	sc := f.leaf(t, leafOpts{ekuOIDs: []asn1.ObjectIdentifier{oidSmartcardLogon}})
	if _, err := m.check(context.Background(), port.MethodEnv{Now: t0, ClientCertificates: chainOf(sc, f.inter.cert)}); err != nil {
		t.Fatalf("smartcard logon = %v", err)
	}
	if _, err := m.check(context.Background(), port.MethodEnv{Now: t0, ClientCertificates: chainOf(f.leaf(t, leafOpts{}), f.inter.cert)}); !failed(err) {
		t.Fatalf("client auth when only smartcard logon is accepted = %v", err)
	}
}

func preflight(m *Method, chain [][]byte) error {
	_, err := m.check(context.Background(), port.MethodEnv{Now: t0, ClientCertificates: chain})
	return err
}

func TestRevocationOCSP(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationOCSP; rc.Revocation.LeafOnly = true })
	good, bad := f.leaf(t, leafOpts{}), f.leaf(t, leafOpts{})
	f.resp.revoked[bad.SerialNumber.String()] = true
	if err := preflight(m, chainOf(good, f.inter.cert)); err != nil {
		t.Fatalf("good = %v", err)
	}
	if err := preflight(m, chainOf(bad, f.inter.cert)); !failed(err) {
		t.Fatalf("revoked = %v", err)
	}
	// 結果は nextUpdate まで持つ（レスポンダーが落ちても通る）。
	f.resp.down = true
	n := f.resp.requests
	if err := preflight(m, chainOf(good, f.inter.cert)); err != nil || f.resp.requests != n {
		t.Fatalf("cached = %v (requests %d -> %d)", err, n, f.resp.requests)
	}
	// 分からないときは既定で拒む。fail_open なら通すが、失効していれば拒む。
	fresh := f.leaf(t, leafOpts{})
	if err := preflight(m, chainOf(fresh, f.inter.cert)); !failed(err) {
		t.Fatalf("unavailable, fail closed = %v", err)
	}
	open := f.method(t, func(rc *RealmConfig) {
		rc.Revocation.Mode, rc.Revocation.FailOpen, rc.Revocation.LeafOnly = RevocationOCSP, true, true
	})
	if err := preflight(open, chainOf(fresh, f.inter.cert)); err != nil {
		t.Fatalf("unavailable, fail open = %v", err)
	}
	f.resp.down = false
	if err := preflight(open, chainOf(bad, f.inter.cert)); !failed(err) {
		t.Fatalf("revoked, fail open = %v", err)
	}
	// unknown は分からないとして扱う。
	f.resp.unknown = true
	if err := preflight(f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationOCSP; rc.Revocation.LeafOnly = true }),
		chainOf(f.leaf(t, leafOpts{}), f.inter.cert)); !failed(err) {
		t.Fatalf("unknown = %v", err)
	}
	// 中間 CA は OCSP の URL を持たないので、ocsp だけでは中間 CA の失効が分からず拒む（leaf_only なら本人だけ確かめる）。
	f.resp.unknown = false
	if err := preflight(f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationOCSP }), chainOf(good, f.inter.cert)); !failed(err) {
		t.Fatalf("intermediate without responder = %v", err)
	}
	// ocsp_crl なら中間 CA はルートの CRL で確かめる。中間 CA が失効していれば拒む。
	full := f.method(t, nil)
	if err := preflight(full, chainOf(good, f.inter.cert)); err != nil {
		t.Fatalf("full chain = %v", err)
	}
	f.rootResp.revoked[f.inter.cert.SerialNumber.String()] = true
	if err := preflight(f.method(t, nil), chainOf(good, f.inter.cert)); !failed(err) {
		t.Fatalf("revoked intermediate = %v", err)
	}
}

// 委ねた署名者は id-kp-OCSPSigning を持たなければならない（同じ CA の別の証明書の鍵で作った Good を通さない。RFC 6960 4.2.2.2）。
func TestRevocationOCSPDelegatedSigner(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationOCSP; rc.Revocation.LeafOnly = true })
	f.resp.signer = newOCSPSigner(t, f.inter, x509.ExtKeyUsageOCSPSigning)
	if err := preflight(m, chainOf(f.leaf(t, leafOpts{}), f.inter.cert)); err != nil {
		t.Fatalf("delegated signer = %v", err)
	}
	f.resp.signer = newOCSPSigner(t, f.inter, x509.ExtKeyUsageClientAuth)
	if err := preflight(m, chainOf(f.leaf(t, leafOpts{}), f.inter.cert)); !failed(err) {
		t.Fatalf("signer without OCSPSigning = %v", err)
	}
}

func TestRevocationCRL(t *testing.T) {
	f := newFixture(t)
	good, bad := f.leaf(t, leafOpts{ocsp: []string{}}), f.leaf(t, leafOpts{ocsp: []string{}})
	f.resp.revoked[bad.SerialNumber.String()] = true
	// ocsp_crl：OCSP の URL が無ければ CRL を見る。
	m := f.method(t, func(rc *RealmConfig) { rc.Revocation.LeafOnly = true })
	if err := preflight(m, chainOf(good, f.inter.cert)); err != nil {
		t.Fatalf("good = %v", err)
	}
	if err := preflight(m, chainOf(bad, f.inter.cert)); !failed(err) {
		t.Fatalf("revoked = %v", err)
	}
	// 古い CRL は使わない。
	f.resp.crlNext = t0.Add(-time.Hour)
	stale := f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationCRL; rc.Revocation.LeafOnly = true })
	if err := preflight(stale, chainOf(good, f.inter.cert)); !failed(err) {
		t.Fatalf("stale CRL = %v", err)
	}
	// 別の CA が署名した CRL は当てはまらない。
	f.resp.crlNext = t0.Add(time.Hour)
	f.resp.issuer = newCA(t, "Impostor", nil)
	if err := preflight(f.method(t, func(rc *RealmConfig) { rc.Revocation.Mode = RevocationCRL; rc.Revocation.LeafOnly = true }),
		chainOf(good, f.inter.cert)); !failed(err) {
		t.Fatalf("CRL of another issuer = %v", err)
	}
}

func TestHardwareIssuerAMR(t *testing.T) {
	f := newFixture(t)
	soft := f.method(t, nil)
	if soft.Info().AAL != 2 {
		t.Fatalf("AAL without hardware issuers = %d", soft.Info().AAL)
	}
	for _, pin := range []bool{false, true} {
		m := f.method(t, func(rc *RealmConfig) {
			rc.HardwareIssuers = []HardwareIssuer{{Certificate: pemOf(f.inter.cert), PINActivation: pin}}
		})
		if m.Info().AAL != 3 {
			t.Fatalf("AAL with hardware issuers = %d", m.Info().AAL)
		}
		c := f.leaf(t, leafOpts{})
		chain := chainOf(c, f.inter.cert)
		if _, err := (call{m: m, f: f, userID: f.users[0]}).enroll(t, chain); err != nil {
			t.Fatal(err)
		}
		r, err := call{m: m, f: f, usage: port.UsageFirstFactor}.login(t, chain, chain)
		want := []string{"sc"}
		if pin {
			want = []string{"sc", "pin", "mfa"}
		}
		if err != nil || !slices.Equal(r.AMR, want) {
			t.Fatalf("pin=%v amr = %v, %v", pin, r.AMR, err)
		}
		if r, err := (call{m: m, f: f, userID: f.users[0], usage: port.UsageSecondFactor}).login(t, chain, chain); err != nil || slices.Contains(r.AMR, "mfa") {
			t.Fatalf("pin=%v second factor amr = %v, %v", pin, r.AMR, err)
		}
	}
	// 本人の証明書を直接発行していない CA（ルート）をハードウェアにしても、ハードウェアとはみなさない。
	m := f.method(t, func(rc *RealmConfig) { rc.HardwareIssuers = []HardwareIssuer{{Certificate: pemOf(f.root.cert)}} })
	c := f.leaf(t, leafOpts{})
	chain := chainOf(c, f.inter.cert)
	if _, err := (call{m: m, f: f, userID: f.users[1]}).enroll(t, chain); err != nil {
		t.Fatal(err)
	}
	if r, err := (call{m: m, f: f, usage: port.UsageFirstFactor}).login(t, chain, chain); err != nil || !slices.Equal(r.AMR, []string{"pop"}) {
		t.Fatalf("root as hardware issuer amr = %v, %v", r.AMR, err)
	}
}

func TestEnrollLimitAndInvalid(t *testing.T) {
	f := newFixture(t)
	m := f.method(t, func(rc *RealmConfig) { rc.MaxCredentials = 1 })
	if _, err := (call{m: m, f: f, userID: f.users[0]}).enroll(t, chainOf(f.leaf(t, leafOpts{}), f.inter.cert)); err != nil {
		t.Fatal(err)
	}
	if _, err := (call{m: m, f: f, userID: f.users[0]}).enroll(t, chainOf(f.leaf(t, leafOpts{}), f.inter.cert)); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit = %v", err)
	}
	if _, err := (call{m: m, f: f, userID: f.users[1]}).enroll(t, nil); codeOf(err) != "client_certificate_required" {
		t.Fatalf("no certificate = %v", err)
	}
	other := newCA(t, "Other", nil)
	if _, err := (call{m: m, f: f, userID: f.users[1]}).enroll(t, chainOf(newLeaf(t, other, leafOpts{cn: "x"}), other.cert)); codeOf(err) != "certificate_invalid" {
		t.Fatalf("untrusted = %v", err)
	}
}

func TestConfigure(t *testing.T) {
	f := newFixture(t)
	setup := func(realm string, c Config) port.MethodSetup {
		return port.MethodSetup{RealmSlug: realm, Decode: func(v any) error { *(v.(*Config)) = c; return nil }}
	}
	a, err := (&Method{}).Setup(context.Background(), setup("other", Config{Realms: map[string]RealmConfig{"default": {TrustAnchors: []string{pemOf(f.root.cert)}}}}))
	if err != nil || a != nil {
		t.Fatalf("realm without settings = %v, %v", a, err)
	}
	if a, err = (&Method{}).Setup(context.Background(), setup("default", Config{Realms: map[string]RealmConfig{"default": {TrustAnchors: []string{pemOf(f.root.cert)}}}})); err != nil || a == nil {
		t.Fatalf("configured realm = %v, %v", a, err)
	}
	if _, err := (&Method{}).Setup(context.Background(), setup("default", Config{Realms: map[string]RealmConfig{
		"default": {TrustAnchors: []string{pemOf(f.root.cert)}}, "other": {}}})); err == nil {
		t.Fatal("invalid settings of another realm accepted")
	}
	for name, rc := range map[string]RealmConfig{
		"no anchors":     {},
		"leaf as anchor": {TrustAnchors: []string{pemOf(f.leaf(t, leafOpts{}))}},
		"missing file":   {TrustAnchors: []string{"/nonexistent/root.pem"}},
		"mapping":        {TrustAnchors: []string{pemOf(f.root.cert)}, Mapping: "cn"},
		"mode":           {TrustAnchors: []string{pemOf(f.root.cert)}, Revocation: Revocation{Mode: "maybe"}},
		"eku":            {TrustAnchors: []string{pemOf(f.root.cert)}, ExtKeyUsages: []string{"1.x"}},
		"ocsp url":       {TrustAnchors: []string{pemOf(f.root.cert)}, Revocation: Revocation{OCSPURL: "ldap://x"}},
		"timeout":        {TrustAnchors: []string{pemOf(f.root.cert)}, Revocation: Revocation{Timeout: "1h"}},
	} {
		if _, err := New(rc, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// 設定の無い方式は何も通さない。
	var zero Method
	if _, err := zero.Begin(context.Background(), port.MethodEnv{ClientCertificates: chainOf(f.root.cert)}, port.MethodRequest{}); !failed(err) {
		t.Fatalf("unconfigured = %v", err)
	}
}

func TestParseSANUPNs(t *testing.T) {
	der := sanWithUPNs(t, []string{"a@b"}, []string{"c@d"})
	got, err := parseSANUPNs(der)
	if err != nil || !slices.Equal(got, []string{"a@b"}) {
		t.Fatalf("parse = %v, %v", got, err)
	}
	for _, bad := range [][]byte{nil, {0x30}, append(bytes.Clone(der), 0)} {
		if _, err := parseSANUPNs(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func FuzzParseSANUPNs(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x0c, 0xa0, 0x0a, 0x06, 0x02, 0x2a, 0x03, 0xa0, 0x04, 0x0c, 0x02, 0x61, 0x62})
	f.Fuzz(func(t *testing.T, b []byte) {
		upns, err := parseSANUPNs(b)
		if err != nil {
			return
		}
		for _, u := range upns {
			if u == "" || !utf8Valid(u) {
				t.Fatalf("invalid upn %q", u)
			}
		}
	})
}

func codeOf(err error) string {
	if e, ok := errors.AsType[*errs.Error](err); ok {
		return e.Code
	}
	return ""
}
