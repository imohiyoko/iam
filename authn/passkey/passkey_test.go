package passkey_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

const origin = "https://login.example.com"

type env struct {
	k   *testkit.Kit
	svc *passkey.Service
	acc *account.Service
	sm  *session.Manager
}

func setup(t *testing.T) *env {
	t.Helper()
	k := testkit.New(t)
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	acc := &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode}}
	svc, err := passkey.New(passkey.Config{RPID: "example.com", RPName: "Example", Origins: []string{origin}},
		passkey.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Accounts: acc, Sessions: sm})
	if err != nil {
		t.Fatal(err)
	}
	return &env{k: k, svc: svc, acc: acc, sm: sm}
}

// user はメール1つのユーザーを作る。
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

func (e *env) register(t *testing.T, u port.User, a *passkeytest.Authenticator) (port.Passkey, error) {
	t.Helper()
	ctx := context.Background()
	st, err := e.svc.BeginRegister(ctx, e.k.RealmID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Create(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	return e.svc.FinishRegister(ctx, e.k.RealmID, u.ID, passkey.Register{FlowID: st.FlowID, Response: resp, Name: "Laptop"})
}

func (e *env) login(t *testing.T, a *passkeytest.Authenticator) (passkey.Result, error) {
	t.Helper()
	ctx := context.Background()
	st, err := e.svc.BeginLogin(ctx, e.k.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Get(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	return e.svc.FinishLogin(ctx, e.k.RealmID, passkey.Login{FlowID: st.FlowID, Response: resp})
}

func TestRegisterAndLogin(t *testing.T) {
	e := setup(t)
	u := e.user(t, "alice@example.com")
	a := passkeytest.New(origin)
	p, err := e.register(t, u, a)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Laptop" || p.Alg != -7 || p.UserID != u.ID || p.PublicID == "" {
		t.Fatalf("registered = %+v", p)
	}
	if string(a.UserHandle) != u.PublicID {
		t.Fatalf("user handle = %q, want the public user ID", a.UserHandle)
	}
	res, err := e.login(t, a)
	if err != nil {
		t.Fatal(err)
	}
	s := res.Session.Session
	if res.UserID != u.PublicID || !slices.Equal(s.AuthMethods, []string{"hwk", "user"}) || !slices.Equal(s.AuthCredentialIDs, []string{p.ID}) {
		t.Fatalf("login = %+v / %+v", res, s)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		got, err := tx.Passkeys().GetByPublicID(ctx, e.k.RealmID, p.PublicID)
		if err != nil || got.SignCount != 1 || got.LastUsedAt == nil {
			t.Errorf("after login = %+v, %v", got, err)
		}
		return nil
	})
	// 2回目のログインで回数が進む。
	if _, err := e.login(t, a); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRejects(t *testing.T) {
	e := setup(t)
	u := e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	if _, err := e.register(t, u, a); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		setup func(a *passkeytest.Authenticator)
	}{
		{"no user verification", func(a *passkeytest.Authenticator) { a.Flags = passkeytest.FlagUP }},
		{"wrong origin", func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example.net" }},
		{"sign count went back", func(a *passkeytest.Authenticator) { a.SignCount = 0 }},
		{"unknown credential", func(a *passkeytest.Authenticator) { a.CredentialID = []byte("unknown-credential") }},
		{"other user handle", func(a *passkeytest.Authenticator) { a.UserHandle = []byte("usr_someoneelse") }},
	}
	if _, err := e.login(t, a); err != nil { // 回数を 1 にしておく
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := *a
			c.setup(&b)
			if _, err := e.login(t, &b); !errors.Is(err, errs.AuthenticationFailed) {
				t.Fatalf("login = %v, want authentication_failed", err)
			}
		})
	}
}

func TestFlowIsOneTimeAndBound(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	alice, bob := e.user(t, "alice@example.com"), e.user(t, "bob@example.com")
	a := passkeytest.New(origin)

	st, err := e.svc.BeginRegister(ctx, e.k.RealmID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Create(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	// 別のユーザーでは完了できず、試した時点でフローは使い終わる。
	if _, err := e.svc.FinishRegister(ctx, e.k.RealmID, bob.ID, passkey.Register{FlowID: st.FlowID, Response: resp}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("finish by another user = %v", err)
	}
	if _, err := e.svc.FinishRegister(ctx, e.k.RealmID, alice.ID, passkey.Register{FlowID: st.FlowID, Response: resp}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reuse of flow = %v", err)
	}

	// ログインのフローでは登録できない。
	lst, err := e.svc.BeginLogin(ctx, e.k.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishRegister(ctx, e.k.RealmID, alice.ID, passkey.Register{FlowID: lst.FlowID, Response: resp}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("register with a login flow = %v", err)
	}

	// 期限を過ぎたフローは使えない。
	st, err = e.svc.BeginRegister(ctx, e.k.RealmID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = a.Create(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Clock.Advance(6 * time.Minute)
	if _, err := e.svc.FinishRegister(ctx, e.k.RealmID, alice.ID, passkey.Register{FlowID: st.FlowID, Response: resp}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("expired flow = %v", err)
	}
}

func TestRevokedPasskey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "carol@example.com")
	a := passkeytest.New(origin)
	p, err := e.register(t, u, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.register(t, u, a); !errors.Is(err, passkey.ErrPasskeyExists) {
		t.Fatalf("register twice = %v, want passkey_exists", err)
	}
	res, err := e.login(t, a)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.acc.RevokePasskey(ctx, tx, e.k.RealmID, u.ID, p.PublicID, audit.Actor{Type: "user", ID: u.PublicID}, "")
		return err
	})
	if _, err := e.login(t, a); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("login with revoked passkey = %v", err)
	}
	// その passkey で作ったセッションも使えない。
	if _, err := e.sm.Validate(ctx, e.k.RealmID, res.Session.Token); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("session of revoked passkey = %v", err)
	}
	// 同じ credential は再登録できない（4.6）。
	if _, err := e.register(t, u, a); !errors.Is(err, passkey.ErrPasskeyRevoked) {
		t.Fatalf("re-register revoked = %v, want passkey_revoked", err)
	}
	// 新しい認証器なら登録できる。
	if _, err := e.register(t, u, passkeytest.New(origin)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySecondFactor(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	alice, bob := e.user(t, "alice@example.com"), e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	p, err := e.register(t, alice, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BeginVerify(ctx, e.k.RealmID, bob.ID); !errors.Is(err, errs.NotFound) {
		t.Fatalf("verify without passkeys = %v", err)
	}
	verify := func(userID string, a *passkeytest.Authenticator) (port.Passkey, error) {
		st, err := e.svc.BeginVerify(ctx, e.k.RealmID, alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.Get(st.Options)
		if err != nil {
			t.Fatal(err)
		}
		var got port.Passkey
		err = e.k.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			got, err = e.svc.Verify(ctx, tx, e.k.RealmID, userID, st.FlowID, resp)
			return err
		})
		return got, err
	}
	// 2要素目では本人確認（UV）を求めない。
	a.Flags = passkeytest.FlagUP
	got, err := verify(alice.ID, a)
	if err != nil || got.ID != p.ID {
		t.Fatalf("verify = %+v, %v", got, err)
	}
	if _, err := verify(bob.ID, a); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("verify with another user's flow = %v", err)
	}
}

// 統合（11.6）で移した passkey は、統合元の user handle のまま2要素目に使える。
func TestVerifyMergedPasskey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	alice, bob := e.user(t, "alice@example.com"), e.user(t, "bob@example.com")
	a := passkeytest.New(origin)
	if _, err := e.register(t, bob, a); err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := tx.Passkeys().MoveUser(ctx, e.k.RealmID, bob.ID, alice.ID, []byte(bob.PublicID))
		return err
	})
	st, err := e.svc.BeginVerify(ctx, e.k.RealmID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.Flags = passkeytest.FlagUP
	resp, err := a.Get(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.svc.Verify(ctx, tx, e.k.RealmID, alice.ID, st.FlowID, resp)
		return err
	})
}
