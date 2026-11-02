package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/passkey"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/authn/method/passkey/passkeytest"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

const origin = "https://login.example.com"

var (
	yubiKey  = uuid.MustParse("cb69481e-8ff7-4039-93ec-0a2729a154a8")
	otherKey = uuid.MustParse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
)

// env はコアのサービス（credential.Service）と passkey の方式を組んだもの。
type env struct {
	k   *testkit.Kit
	m   *passkey.Method
	svc *credential.Service
	acc *account.Service
	sm  *session.Manager
}

func setup(t *testing.T) *env {
	t.Helper()
	k := testkit.New(t)
	e := &env{k: k}
	e.sm = &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	e.acc = &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode}}
	e.use(t, nil)
	return e
}

// use は方式を att（nil なら attestation のフィーチャーが止まっている）で作り直す。データは Storage に残る。
func (e *env) use(t *testing.T, att *passkey.Attestation) {
	t.Helper()
	m, err := passkey.New(passkey.Config{RPID: "example.com", RPName: "Example", Origins: []string{origin}}, att)
	if err != nil {
		t.Fatal(err)
	}
	set, err := method.Active(func(string) bool { return false }, m)
	if err != nil {
		t.Fatal(err)
	}
	e.m, e.acc.Methods, e.sm.Methods = m, set, set
	e.svc = &credential.Service{Storage: e.k.Storage, Cache: e.k.Cache, Crypter: e.k.Crypter, Clock: e.k.Clock, Accounts: e.acc,
		Sessions: e.sm, Methods: set}
}

func (e *env) user(t *testing.T, email string) port.User {
	t.Helper()
	var u port.User
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		c, err := e.acc.CreateWithEmail(ctx, tx, e.k.RealmID, email, port.VerifiedViaCode, audit.Actor{}, "")
		u = c.User
		return err
	})
	return u
}

func payload(t *testing.T, cred []byte, name string) json.RawMessage {
	t.Helper()
	in := map[string]any{"credential": json.RawMessage(cred)}
	if name != "" {
		in["name"] = name
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// register は汎用の登録で passkey を作る。
func (e *env) register(t *testing.T, u port.User, a *passkeytest.Authenticator, name string) (port.Credential, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := e.svc.EnrollBegin(ctx, e.k.RealmID, u.ID, passkey.Name, nil, credential.EnrollOptions{RecentAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Create(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return e.finishRegister(u, ch.FlowID, payload(t, resp, name))
}

func (e *env) finishRegister(u port.User, flowID string, p json.RawMessage) (port.Credential, error) {
	var out port.Credential
	err := e.k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		en, err := e.svc.EnrollComplete(ctx, tx, credential.EnrollInput{RealmID: e.k.RealmID, UserID: u.ID, Method: passkey.Name,
			FlowID: flowID, Payload: p, Actor: audit.Actor{Type: "user", ID: u.PublicID}})
		out = en.Credential
		return err
	})
	if err != nil {
		e.svc.EnrollFailed(context.Background(), e.k.RealmID, passkey.Name, credential.Client{}, err)
	}
	return out, err
}

// data は登録した passkey のデータを読む。
func (e *env) data(t *testing.T, c port.Credential) passkey.Data {
	t.Helper()
	var d passkey.Data
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Credentials().Get(ctx, e.k.RealmID, c.ID)
		if err != nil {
			return err
		}
		_, d, err = passkey.Read(ctx, tx, e.k.Crypter, cur)
		return err
	})
	return d
}

type loggedIn struct {
	is     session.Issued
	userID string
}

func (e *env) login(t *testing.T, a *passkeytest.Authenticator) (loggedIn, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := e.svc.Begin(ctx, e.k.RealmID, "", passkey.Name, port.UsageFirstFactor, nil, credential.Client{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Get(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	is, uid, err := e.svc.Login(ctx, e.k.RealmID, passkey.Name, ch.FlowID, payload(t, resp, ""), credential.Client{}, "")
	return loggedIn{is: is, userID: uid}, err
}

// verify は方式を直接呼んで2要素目を確かめる（本人 userID のフロー。begin は beginUser で始める）。
func (e *env) verify(t *testing.T, beginUser, userID string, a *passkeytest.Authenticator) (port.MethodResult, error) {
	t.Helper()
	ctx := context.Background()
	ch, err := e.m.Begin(ctx, e.methodEnv(beginUser), port.MethodRequest{})
	if err != nil {
		return port.MethodResult{}, err
	}
	resp, err := a.Get(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return e.m.Complete(ctx, e.methodEnv(userID), port.MethodRequest{Payload: payload(t, resp, ""), State: ch.State})
}

func (e *env) methodEnv(userID string) port.MethodEnv {
	now := e.k.Clock.Now()
	return port.MethodEnv{RealmID: e.k.RealmID, UserID: userID, Now: now, Credentials: &method.Store{Storage: e.k.Storage,
		Crypter: e.k.Crypter, RealmID: e.k.RealmID, Info: e.m.Info(), Now: now}}
}

// lastEvent は種類 typ の最後の監査ログの詳細を返す。
func (e *env) lastEvent(t *testing.T, typ string) map[string]any {
	t.Helper()
	var out map[string]any
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		recs, err := tx.Audit().Scan(ctx, 1, 1000)
		for _, r := range recs {
			var ev struct {
				Type    string         `json:"type"`
				Details map[string]any `json:"details"`
			}
			if json.Unmarshal(r.Payload, &ev) == nil && ev.Type == typ {
				out = ev.Details
			}
		}
		return err
	})
	if out == nil {
		t.Fatalf("no %s event", typ)
	}
	return out
}

func TestInfo(t *testing.T) {
	e := setup(t)
	i := e.m.Info()
	if i.Name != "passkey" || i.Feature != "" || !i.OneShot || !i.ReserveRevokedLookups || i.AAL != 2 ||
		!i.Supports(port.UsageFirstFactor) || !i.Supports(port.UsageSecondFactor) || !i.Supports(port.UsageStepUp) {
		t.Fatalf("info = %+v", i)
	}
	if err := method.Check(e.m); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterAndLogin(t *testing.T) {
	e := setup(t)
	u := e.user(t, "alice@example.com")
	a := passkeytest.New(origin)
	c, err := e.register(t, u, a, "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	d := e.data(t, c)
	if d.Name != "Laptop" || d.Alg != -7 || c.UserID != u.ID || c.Method != "passkey" || !c.ReserveLookup || len(c.Lookup) == 0 {
		t.Fatalf("registered = %+v / %+v", c, d)
	}
	if string(a.UserHandle) != u.PublicID || string(d.UserHandle) != u.PublicID {
		t.Fatalf("user handle = %q / %q, want the public user ID", a.UserHandle, d.UserHandle)
	}
	if ev := e.lastEvent(t, "passkey.registered"); ev["passkey_id"] != c.PublicID || ev["credential_id"] != c.PublicID || ev["alg"] != float64(-7) {
		t.Fatalf("passkey.registered = %v", ev)
	}
	res, err := e.login(t, a)
	if err != nil {
		t.Fatal(err)
	}
	s := res.is.Session
	if res.userID != u.PublicID || !slices.Equal(s.AuthMethods, []string{"hwk", "user"}) || !slices.Equal(s.AuthCredentialIDs, []string{c.ID}) ||
		s.Restriction != port.RestrictionNone {
		t.Fatalf("login = %+v / %+v", res, s)
	}
	if d := e.data(t, c); d.SignCount != 1 {
		t.Fatalf("sign count after login = %d", d.SignCount)
	}
	if ev := e.lastEvent(t, "login.succeeded"); ev["passkey_id"] != c.PublicID || ev["method"] != "passkey" {
		t.Fatalf("login.succeeded = %v", ev)
	}
	// 2回目のログインで回数が進む。
	if _, err := e.login(t, a); err != nil {
		t.Fatal(err)
	}
	if d := e.data(t, c); d.SignCount != 2 {
		t.Fatalf("sign count after the second login = %d", d.SignCount)
	}
	// 名前が誤っていれば登録しない（errs.Invalid）。
	if _, err := e.register(t, u, passkeytest.New(origin), strings.Repeat("x", 65)); !errors.Is(err, passkey.ErrName) {
		t.Fatalf("long name = %v", err)
	}
}

func TestLoginRejects(t *testing.T) {
	e := setup(t)
	u := e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	if _, err := e.register(t, u, a, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.login(t, a); err != nil { // 回数を 1 にしておく
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		setup func(a *passkeytest.Authenticator)
	}{
		{"no user verification", func(a *passkeytest.Authenticator) { a.Flags = passkeytest.FlagUP }},
		{"wrong origin", func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example.net" }},
		{"sign count went back", func(a *passkeytest.Authenticator) { a.SignCount = 0 }},
		{"unknown credential", func(a *passkeytest.Authenticator) { a.CredentialID = []byte("unknown-credential") }},
		{"other user handle", func(a *passkeytest.Authenticator) { a.UserHandle = []byte("usr_someoneelse") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := *a
			c.setup(&b)
			if _, err := e.login(t, &b); !errors.Is(err, errs.AuthenticationFailed) {
				t.Fatalf("login = %v, want authentication_failed", err)
			}
		})
	}
	// 壊れた入力も同じ失敗。
	ctx := context.Background()
	for _, p := range []string{`{}`, `{"credential":null}`, `{"credential":{"id":"x"}}`, `[]`} {
		ch, err := e.svc.Begin(ctx, e.k.RealmID, "", passkey.Name, port.UsageFirstFactor, nil, credential.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.svc.Login(ctx, e.k.RealmID, passkey.Name, ch.FlowID, json.RawMessage(p), credential.Client{}, ""); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("payload %s = %v", p, err)
		}
	}
}

// チャレンジは1回限り（失敗しても使えない）で、方式の期限（5 分）が効く。
func TestChallengeIsOneShot(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "carol@example.com")
	a := passkeytest.New(origin)
	if _, err := e.register(t, u, a, ""); err != nil {
		t.Fatal(err)
	}
	ch, err := e.svc.Begin(ctx, e.k.RealmID, "", passkey.Name, port.UsageFirstFactor, nil, credential.Client{})
	if err != nil {
		t.Fatal(err)
	}
	bad := *a
	bad.Flags = passkeytest.FlagUP
	resp, err := bad.Get(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Login(ctx, e.k.RealmID, passkey.Name, ch.FlowID, payload(t, resp, ""), credential.Client{}, ""); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("first attempt = %v", err)
	}
	good, err := a.Get(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Login(ctx, e.k.RealmID, passkey.Name, ch.FlowID, payload(t, good, ""), credential.Client{}, ""); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("retry with the same flow = %v", err)
	}

	// 登録のフローは期限（5 分）を過ぎると使えない（コアのフローの期限より短い）。
	ch, err = e.svc.EnrollBegin(ctx, e.k.RealmID, u.ID, passkey.Name, nil, credential.EnrollOptions{RecentAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	created, err := passkeytest.New(origin).Create(ch.Payload)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Clock.Advance(6 * time.Minute)
	if _, err := e.finishRegister(u, ch.FlowID, payload(t, created, "")); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("expired flow = %v", err)
	}
	// 別の人のフローでは登録できない。
	other := e.user(t, "dave@example.com")
	ch, err = e.svc.EnrollBegin(ctx, e.k.RealmID, u.ID, passkey.Name, nil, credential.EnrollOptions{RecentAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if created, err = passkeytest.New(origin).Create(ch.Payload); err != nil {
		t.Fatal(err)
	}
	if _, err := e.finishRegister(other, ch.FlowID, payload(t, created, "")); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("finish by another user = %v", err)
	}
}

func TestRevokedPasskey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "carol@example.com")
	if _, err := e.register(t, u, passkeytest.New(origin), "Backup"); err != nil { // 最後の手段にしない
		t.Fatal(err)
	}
	a := passkeytest.New(origin)
	c, err := e.register(t, u, a, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.register(t, u, a, ""); !errors.Is(err, passkey.ErrPasskeyExists) {
		t.Fatalf("register twice = %v, want passkey_exists", err)
	}
	res, err := e.login(t, a)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.acc.RevokePasskey(ctx, tx, e.k.RealmID, u.ID, c.PublicID, audit.Actor{Type: "user", ID: u.PublicID}, "")
		return err
	})
	if _, err := e.login(t, a); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("login with revoked passkey = %v", err)
	}
	// その passkey で作ったセッションも使えない。
	if _, err := e.sm.Validate(ctx, e.k.RealmID, res.is.Token); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("session of revoked passkey = %v", err)
	}
	// 同じ credential は再登録できない（4.6）。別の人でも、持ち主を消した後でも。
	if _, err := e.register(t, u, a, ""); !errors.Is(err, passkey.ErrPasskeyRevoked) {
		t.Fatalf("re-register revoked = %v, want passkey_revoked", err)
	}
	if ev := e.lastEvent(t, "passkey.registration_failed"); ev["method"] != "passkey" {
		t.Fatalf("passkey.registration_failed = %v", ev)
	}
	other := e.user(t, "eve@example.com")
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Users().Erase(ctx, e.k.RealmID, u.ID, e.k.Clock.Now())
	})
	if _, err := e.register(t, other, a, ""); !errors.Is(err, passkey.ErrPasskeyRevoked) {
		t.Fatalf("re-register revoked after erase = %v, want passkey_revoked", err)
	}
	// 新しい認証器なら登録できる。
	if _, err := e.register(t, other, passkeytest.New(origin), ""); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySecondFactor(t *testing.T) {
	e := setup(t)
	alice, bob := e.user(t, "alice@example.com"), e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	c, err := e.register(t, alice, a, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.verify(t, bob.ID, bob.ID, a); !errors.Is(err, errs.NotFound) {
		t.Fatalf("verify without passkeys = %v", err)
	}
	// 2要素目では本人確認（UV）を求めない。
	a.Flags = passkeytest.FlagUP
	r, err := e.verify(t, alice.ID, alice.ID, a)
	if err != nil || r.Credential.ID != c.ID || !slices.Equal(r.AMR, []string{"hwk"}) {
		t.Fatalf("verify = %+v, %v", r, err)
	}
	// 別の人の passkey では通らない。
	if _, err := e.register(t, bob, passkeytest.New(origin), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.verify(t, bob.ID, bob.ID, a); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("verify with another user's passkey = %v", err)
	}
}

// 統合（11.6）で移した passkey は、統合元の user handle のまま1要素目にも2要素目にも使える。
func TestMergedPasskey(t *testing.T) {
	e := setup(t)
	alice, bob := e.user(t, "alice@example.com"), e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	if _, err := e.register(t, bob, a, ""); err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Credentials().ListByUser(ctx, e.k.RealmID, bob.ID, "")
		if err != nil {
			return err
		}
		for _, c := range cs {
			ct, err := method.Reseal(ctx, tx, e.k.Crypter, c, alice.ID)
			if err != nil {
				return err
			}
			if err := tx.Credentials().UpdateData(ctx, e.k.RealmID, c.ID, c.Data, ct, c.DataVersion); err != nil {
				return err
			}
		}
		_, err = tx.Credentials().MoveUser(ctx, e.k.RealmID, bob.ID, alice.ID)
		return err
	})
	res, err := e.login(t, a)
	if err != nil || res.userID != alice.PublicID {
		t.Fatalf("login with merged passkey = %+v, %v", res, err)
	}
	a.Flags = passkeytest.FlagUP
	if _, err := e.verify(t, alice.ID, alice.ID, a); err != nil {
		t.Fatalf("verify merged passkey: %v", err)
	}
}

// attested は attestation のフィーチャーを動かす。vendor が yubiKey の attestation のルート（MDS に載せる）。
func (e *env) attested(t *testing.T, policy *attestation.Policy) *passkeytest.CA {
	t.Helper()
	mds, vendor := passkeytest.NewCA("MDS Root"), passkeytest.NewCA("Vendor Root")
	m := attestation.New(attestation.Config{Root: mds.DER, Clock: e.k.Clock})
	if err := m.Load(mds.MDSBlob(1, "2027-01-01", passkeytest.MDSEntry(yubiKey.String(), "YubiKey 5", [][]byte{vendor.DER}, "FIDO_CERTIFIED_L2"))); err != nil {
		t.Fatal(err)
	}
	e.use(t, &passkey.Attestation{Metadata: m, Conveyance: "direct", Policy: policy})
	return vendor
}

func key(aaguid uuid.UUID, ca *passkeytest.CA) *passkeytest.Authenticator {
	a := passkeytest.New(origin)
	a.AAGUID = aaguid[:]
	if ca != nil {
		a.Attestation = ca.PackedAttestation(aaguid[:])
	}
	return a
}

func TestAttestationRegister(t *testing.T) {
	e := setup(t)
	vendor := e.attested(t, &attestation.Policy{RequireAttestation: true, AllowedAAGUIDs: []string{yubiKey.String()}})
	u := e.user(t, "alice@example.com")
	ch, err := e.svc.EnrollBegin(context.Background(), e.k.RealmID, u.ID, passkey.Name, nil, credential.EnrollOptions{RecentAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ch.Payload), `"attestation":"direct"`) {
		t.Fatalf("options do not ask for attestation: %s", ch.Payload)
	}

	// 信頼の起点に連なる attestation で、許可した AAGUID なら登録できる。
	c, err := e.register(t, u, key(yubiKey, vendor), "")
	if err != nil {
		t.Fatal(err)
	}
	if d := e.data(t, c); !d.Attested || d.AttestationFormat != "packed" || attestation.FormatAAGUID(d.AAGUID) != yubiKey.String() {
		t.Fatalf("registered = %+v", d)
	}
	ev := e.lastEvent(t, "passkey.registered")
	if ev["aaguid"] != yubiKey.String() || ev["attested"] != true || ev["decision"] != "allowed" || ev["authenticator_name"] != "YubiKey 5" {
		t.Fatalf("passkey.registered details = %v", ev)
	}
	for _, tc := range []struct {
		name string
		a    *passkeytest.Authenticator
	}{
		{"no attestation", key(yubiKey, nil)},
		{"untrusted chain", key(yubiKey, passkeytest.NewCA("Rogue"))},
		{"not allowed", key(otherKey, nil)},
	} {
		_, err := e.register(t, u, tc.a, "")
		if !errors.Is(err, passkey.ErrNotAllowed) {
			t.Fatalf("%s: err = %v, want ErrNotAllowed", tc.name, err)
		}
		if ev := e.lastEvent(t, "passkey.registration_failed"); ev["decision"] != "denied" || ev["reason"] != attestation.ReasonAttestationRequired || ev["tier"] != "realm" {
			t.Fatalf("%s: passkey.registration_failed details = %v", tc.name, ev)
		}
	}
	// attestation を求めない段では、自己申告の AAGUID で許可の一覧を判定する。
	e.m.Attestation().Policy = &attestation.Policy{AllowedAAGUIDs: []string{yubiKey.String()}}
	if _, err := e.register(t, u, key(otherKey, nil), ""); !errors.Is(err, passkey.ErrNotAllowed) {
		t.Fatalf("other aaguid: err = %v", err)
	}
	if ev := e.lastEvent(t, "passkey.registration_failed"); ev["reason"] != attestation.ReasonNotAllowed || ev["aaguid"] != otherKey.String() {
		t.Fatalf("details = %v", ev)
	}
	if c, err := e.register(t, u, key(yubiKey, nil), ""); err != nil {
		t.Fatal(err)
	} else if d := e.data(t, c); d.Attested || d.AttestationFormat != "none" {
		t.Fatalf("self-declared aaguid = %+v", d)
	}
}

func TestAttestationLogin(t *testing.T) {
	e := setup(t)
	alice := e.user(t, "alice@example.com")
	// フィーチャーを動かす前に登録した passkey（attestation を確かめていない既存の行）。
	legacy := key(yubiKey, nil)
	if _, err := e.register(t, alice, legacy, ""); err != nil {
		t.Fatal(err)
	}
	vendor := e.attested(t, nil)
	bob := e.user(t, "bob@example.com")
	good := key(yubiKey, vendor)
	if _, err := e.register(t, bob, good, ""); err != nil {
		t.Fatal(err)
	}
	// ポリシーが無ければ、既存の行もログインできる。
	if _, err := e.login(t, legacy); err != nil {
		t.Fatalf("legacy login: %v", err)
	}
	if ev := e.lastEvent(t, "login.succeeded"); ev["aaguid"] != yubiKey.String() || ev["decision"] != "allowed" {
		t.Fatalf("login.succeeded details = %v", ev)
	}
	// attestation を必須にすると、既存の行ではログインできない（登録し直す）。本人確認の後なので理由を返す。
	e.m.Attestation().Policy = &attestation.Policy{RequireAttestation: true}
	_, err := e.login(t, legacy)
	var na *passkey.NotAllowedError
	if !errors.As(err, &na) {
		t.Fatalf("legacy login with require_attestation: err = %v", err)
	}
	if d, ok := errors.AsType[errs.Denial](err); !ok || d.Reasons()[0] != passkey.CodeNotAllowed {
		t.Fatalf("denial = %v", err)
	}
	if ev := e.lastEvent(t, "login.failed"); ev["reason"] != attestation.ReasonAttestationRequired || ev["aaguid"] != yubiKey.String() {
		t.Fatalf("login.failed details = %v", ev)
	}
	if _, err := e.login(t, good); err != nil {
		t.Fatalf("attested login: %v", err)
	}
	// 拒否の一覧に入れた認証器は、登録済みでもログインできない。2要素目でも同じ。
	e.m.Attestation().Policy = &attestation.Policy{DeniedAAGUIDs: []string{yubiKey.String()}}
	if _, err := e.login(t, good); !errors.As(err, &na) || na.Decision.Reason != attestation.ReasonDenied {
		t.Fatalf("denied login: err = %v", err)
	}
	if _, err := e.verify(t, bob.ID, bob.ID, good); !errors.As(err, &na) {
		t.Fatalf("second factor: err = %v", err)
	}
	// フィーチャーが止まっていれば判定しない。
	e.use(t, nil)
	if _, err := e.login(t, good); err != nil {
		t.Fatalf("login without the feature: %v", err)
	}
}

func TestDataAndNames(t *testing.T) {
	if _, err := passkey.Decode([]byte(`{}`)); err == nil {
		t.Fatal("data without a credential decoded")
	}
	if _, err := passkey.Decode([]byte(`nope`)); err == nil {
		t.Fatal("broken data decoded")
	}
	for _, bad := range []string{"", "   ", strings.Repeat("あ", 65), "a\x00b", "a\nb"} {
		if _, err := passkey.ValidName(bad); !errors.Is(err, passkey.ErrName) {
			t.Fatalf("name %q = %v", bad, err)
		}
	}
	if n, err := passkey.ValidName("  Laptop  "); err != nil || n != "Laptop" {
		t.Fatalf("name = %q, %v", n, err)
	}
}
