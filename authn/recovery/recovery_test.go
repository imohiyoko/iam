package recovery_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/recovery"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

type env struct {
	k     *testkit.Kit
	s     *recovery.Service
	user  port.User
	email string
}

func setup(t *testing.T) env {
	t.Helper()
	k := testkit.New(t)
	acc := &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode}}
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: time.Hour, ValidityMaxDelay: time.Minute}}
	s := &recovery.Service{Storage: k.Storage, Crypter: k.Crypter, Clock: k.Clock, Accounts: acc, Sessions: sm,
		Notify: &notify.Service{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}, Params: password.Params{Memory: 8, Time: 1, Threads: 1}}
	var u port.User
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		c, err := acc.CreateWithEmail(ctx, tx, k.RealmID, "pat@example.com", port.VerifiedViaCode, audit.Actor{}, "")
		u = c.User
		return err
	})
	return env{k: k, s: s, user: u, email: "pat@example.com"}
}

func (e env) generate(t *testing.T) []string {
	t.Helper()
	var codes []string
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		codes, err = e.s.Generate(ctx, tx, e.k.RealmID, e.user.ID, audit.Actor{Type: "user", ID: e.user.PublicID}, "")
		return err
	})
	return codes
}

func (e env) redeem(email, code string) (session.Issued, error) {
	is, _, err := e.s.Redeem(context.Background(), e.k.RealmID, email, code, recovery.Client{}, "")
	return is, err
}

func TestCodesAreSingleUseAndNormalized(t *testing.T) {
	e := setup(t)
	codes := e.generate(t)
	if len(codes) != recovery.Count {
		t.Fatalf("codes = %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 || seen[c[:4]] {
			t.Fatalf("code %q (lookups must be unique)", c)
		}
		seen[c[:4]] = true
	}
	// 小文字・区切りなしでも通り、復旧専用のセッションになる。
	is, err := e.redeem(e.email, strings.ToLower(strings.ReplaceAll(codes[0], "-", "")))
	if err != nil || is.Session.Restriction != port.RestrictionRecovery || recovery.Via(is.Session.AuthMethods) != recovery.ViaCode {
		t.Fatalf("redeem = %+v, %v", is.Session, err)
	}
	if _, err := e.redeem(e.email, codes[0]); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reuse = %v", err)
	}
	// lookup が合っても、残りが違えば通らない（使い終えない）。
	wrong := codes[1][:5] + "0000-0000-0000"[:14]
	if _, err := e.redeem(e.email, wrong); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("wrong secret = %v", err)
	}
	if _, err := e.redeem(e.email, codes[1]); err != nil {
		t.Fatalf("after wrong secret = %v", err)
	}
	for _, c := range []struct{ email, code string }{
		{"eve@example.com", codes[2]}, {e.email, "not-a-code"}, {"not an email", codes[2]}, {e.email, ""},
	} {
		if _, err := e.redeem(c.email, c.code); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("%+v = %v", c, err)
		}
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		n, err := recovery.Remaining(ctx, tx, e.k.RealmID, e.user.ID)
		if n != recovery.Count-2 {
			t.Errorf("remaining = %d", n)
		}
		return err
	})
	// 作り直すと古いコードは使えない。Initial は持っていれば作らない。
	again := e.generate(t)
	if _, err := e.redeem(e.email, codes[3]); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("old code after regenerate = %v", err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		got, err := e.s.Initial(ctx, tx, e.k.RealmID, e.user.ID, audit.Actor{}, "")
		if got != nil {
			t.Errorf("initial with codes = %v", got)
		}
		return err
	})
	if _, err := e.redeem(e.email, again[0]); err != nil {
		t.Fatalf("new code = %v", err)
	}
}

// security_risk で止められていても復旧できる。ほかの停止では理由つきで拒む（4.12）。
func TestRedeemWhileSuspended(t *testing.T) {
	e := setup(t)
	codes := e.generate(t)
	acc := &account.Service{Clock: e.k.Clock}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, _, err := acc.SuspendUser(ctx, tx, e.k.RealmID, e.user, account.Suspend{Category: account.CategorySecurityRisk, Reason: "x"}, audit.Actor{}, "")
		return err
	})
	if _, err := e.redeem(e.email, codes[0]); err != nil {
		t.Fatalf("security_risk = %v", err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, _, err := acc.SuspendUser(ctx, tx, e.k.RealmID, e.user, account.Suspend{Category: account.CategoryTOSViolation, Reason: "x"}, audit.Actor{}, "")
		return err
	})
	_, err := e.redeem(e.email, codes[1])
	if d, ok := errors.AsType[errs.Denial](err); !ok || d.Reasons()[0] != "suspended.tos_violation" {
		t.Fatalf("tos_violation = %v", err)
	}
}

func TestComplete(t *testing.T) {
	e := setup(t)
	codes := e.generate(t)
	ctx := context.Background()
	// 別のセッションも持っている。
	var other session.Issued
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		other, err = e.s.Sessions.Issue(ctx, tx, session.Issue{RealmID: e.k.RealmID, UserID: e.user.ID, AuthMethods: []string{"otp"}})
		return err
	})
	is, err := e.redeem(e.email, codes[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.s.Complete(ctx, e.k.RealmID, other.Session.ID, recovery.Client{}); !errors.Is(err, recovery.ErrNotRecovery) {
		t.Fatalf("complete with a normal session = %v", err)
	}
	if _, _, err := e.s.Complete(ctx, e.k.RealmID, is.Session.ID, recovery.Client{}); !errors.Is(err, recovery.ErrNoNewMethod) {
		t.Fatalf("complete without a new method = %v", err)
	}
	e.k.Clock.Advance(time.Second)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.TOTP().Create(ctx, port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: e.k.RealmID,
			UserID: e.user.ID, SecretCiphertext: []byte("x"), CreatedAt: e.k.Clock.Now()})
	})
	fresh, revoked, err := e.s.Complete(ctx, e.k.RealmID, is.Session.ID, recovery.Client{})
	if err != nil || len(fresh) != recovery.Count || len(revoked) != 2 {
		t.Fatalf("complete = %d codes, %v, %v", len(fresh), revoked, err)
	}
	for _, tok := range []string{other.Token, is.Token} {
		if _, err := e.s.Sessions.Validate(ctx, e.k.RealmID, tok); err == nil {
			t.Fatal("session survived recovery")
		}
	}
	if _, err := e.redeem(e.email, codes[1]); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("old code after complete = %v", err)
	}
	if _, _, err := e.s.Complete(ctx, e.k.RealmID, is.Session.ID, recovery.Client{}); !errors.Is(err, recovery.ErrNotRecovery) {
		t.Fatalf("complete twice = %v", err)
	}
}
