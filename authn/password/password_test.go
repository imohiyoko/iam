package password_test

import (
	"context"
	"crypto/sha1" // #nosec G505 -- テストの偽の確認
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

var fast = pwm.Params{Memory: 8, Time: 1, Threads: 1}

// fakeBreach は決まったパスワードを漏洩済みとする。
type fakeBreach struct {
	bad  map[string]bool
	fail bool
}

func (f *fakeBreach) Breached(_ context.Context, h string) (bool, error) {
	if f.fail {
		return false, errors.New("unavailable")
	}
	return f.bad[h], nil
}

func sha(s string) string {
	sum := sha1.Sum([]byte(s)) // #nosec G401
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

type env struct {
	k      *testkit.Kit
	svc    *password.Service
	acc    *account.Service
	breach *fakeBreach
}

func setup(t *testing.T) *env {
	t.Helper()
	k := testkit.New(t)
	acc := &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode}}
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	w, err := warning.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	sm.Warnings = w
	b := &fakeBreach{bad: map[string]bool{sha("password1234567890"): true}}
	pm := &pwm.Method{Params: fast, Breach: b}
	methods, err := method.Active(func(string) bool { return false }, pm)
	if err != nil {
		t.Fatal(err)
	}
	acc.Methods, sm.Methods = methods, methods
	limit := &ratelimit.Limiter{Cache: k.Cache, Clock: k.Clock, Window: time.Minute, Limit: 5}
	cs := &credential.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Accounts: acc, Sessions: sm,
		Methods: methods, PerLogin: limit}
	return &env{k: k, acc: acc, breach: b, svc: &password.Service{Storage: k.Storage, Crypter: k.Crypter, Clock: k.Clock, Accounts: acc,
		Sessions: sm, Credentials: cs, Method: pm, PerAccount: limit}}
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

const good = "a long and memorable passphrase"

func TestSetAndLogin(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "alice@example.com")
	for _, c := range []struct {
		pw   string
		want error
	}{
		{"short", pwm.ErrTooShort},
		{strings.Repeat("x", pwm.MaxLength+1), pwm.ErrTooLong},
		{"password1234567890", pwm.ErrBreached},
	} {
		if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, c.pw, "", true, "", audit.Actor{}, ""); !errors.Is(err, c.want) {
			t.Errorf("set %q = %v, want %v", c.pw, err, c.want)
		}
	}
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, good, "", false, "", audit.Actor{}, ""); !errors.Is(err, pwm.ErrReauthRequired) {
		t.Fatalf("first set without recent auth = %v", err)
	}
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, good, "", true, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "Alice@Example.com", Password: good})
	if err != nil || res.UserID != u.PublicID || res.Session.Session.AuthMethods[0] != "pwd" {
		t.Fatalf("login = %+v, %v", res, err)
	}
	// 合成済みの文字（NFKC）は同じパスワードとして扱う。
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "alice@example.com", Password: "ａ long and memorable passphrase"}); err != nil {
		t.Fatalf("login with full-width a = %v", err)
	}
	for _, in := range []password.Login{
		{Email: "alice@example.com", Password: "wrong password here!!"},
		{Email: "nobody@example.com", Password: good},
		{Email: "not an email", Password: good},
	} {
		if _, err := e.svc.Login(ctx, e.k.RealmID, in); !errors.Is(err, errs.AuthenticationFailed) {
			t.Errorf("login %+v = %v", in, err)
		}
	}
	// 変更には今のパスワードが要る。
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, "another long passphrase", "wrong", true, "", audit.Actor{}, ""); !errors.Is(err, pwm.ErrCurrentPassword) {
		t.Fatalf("change with wrong current = %v", err)
	}
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, "another long passphrase", good, false, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "alice@example.com", Password: good}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("old password = %v", err)
	}
}

func TestLoginRateLimitedAndBreachWarning(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "bob@example.com")
	// 設定の時は確認できなかった（障害）が、後で漏洩が分かった。
	e.breach.fail = true
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, "password1234567890", "", true, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	e.breach.fail = false
	res, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "bob@example.com", Password: "password1234567890"})
	if err != nil || len(res.Session.Warnings) != 1 || res.Session.Warnings[0].Code != warning.CodePasswordBreached {
		t.Fatalf("login = %+v, %v", res.Session.Warnings, err)
	}
	for range 4 {
		_, _ = e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "bob@example.com", Password: "nope nope nope nope"})
	}
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "BOB@example.com", Password: "password1234567890"}); err == nil {
		t.Fatal("6th attempt should be rate limited")
	} else if _, ok := errors.AsType[*ratelimit.ExceededError](err); !ok {
		t.Fatalf("6th attempt = %v", err)
	}
}

func TestRemove(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "carol@example.com")
	if err := e.svc.Remove(ctx, e.k.RealmID, u.ID, good, "", audit.Actor{}, ""); !errors.Is(err, password.ErrNoPassword) {
		t.Fatalf("remove without password = %v", err)
	}
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, good, "", true, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Remove(ctx, e.k.RealmID, u.ID, "wrong", "", audit.Actor{}, ""); !errors.Is(err, pwm.ErrCurrentPassword) {
		t.Fatalf("remove with wrong current = %v", err)
	}
	// メールのコードが使えなければ、パスワードが最後のログインの手段。
	e.acc.VerifiedVia = nil
	if err := e.svc.Remove(ctx, e.k.RealmID, u.ID, good, "", audit.Actor{}, ""); !errors.Is(err, account.ErrLastMethod) {
		t.Fatalf("remove last method = %v", err)
	}
	e.acc.VerifiedVia = []port.VerifiedVia{port.VerifiedViaCode}
	if err := e.svc.Remove(ctx, e.k.RealmID, u.ID, good, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "carol@example.com", Password: good}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("login after remove = %v", err)
	}
}

// failingStorage はトランザクションをすべて失敗させる（基盤の障害）。
type failingStorage struct{ port.Storage }

var errDown = errors.New("storage down")

func (failingStorage) Tx(context.Context, func(context.Context, port.Tx) error) error { return errDown }

func TestLoginDoesNotHideInfrastructureErrors(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "dave@example.com")
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, good, "", true, "", audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	// 正規化で 128 文字に縮んでも、入力が上限を超えれば設定できない（ログインで受け取れないため）。
	decomposed := strings.Repeat("\u1100\u1161\u11A8", pwm.MaxLength)
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, decomposed, good, true, "", audit.Actor{}, ""); !errors.Is(err, pwm.ErrTooLong) {
		t.Fatalf("set oversized input = %v", err)
	}
	// 上限を超える入力は照合せずに認証の失敗にする。
	long := strings.Repeat("a", pwm.MaxInputBytes+1)
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "dave@example.com", Password: long}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("too long = %v", err)
	}
	e.svc.Storage, e.svc.Credentials.Storage = failingStorage{e.k.Storage}, failingStorage{e.k.Storage}
	if _, err := e.svc.Login(ctx, e.k.RealmID, password.Login{Email: "dave@example.com", Password: good}); !errors.Is(err, errDown) {
		t.Fatalf("storage failure = %v, want it returned as is", err)
	}
}

func TestSetAndRemoveRevokeOtherSessions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user(t, "erin@example.com")
	issue := func() string {
		var id string
		e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			is, err := e.svc.Sessions.Issue(ctx, tx, session.Issue{RealmID: e.k.RealmID, UserID: u.ID, AuthMethods: []string{"otp"}})
			id = is.Session.ID
			return err
		})
		return id
	}
	revoked := func(id string) bool {
		var r bool
		e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			s, err := tx.Sessions().Get(ctx, e.k.RealmID, id)
			r = s.RevokedAt != nil
			return err
		})
		return r
	}
	keep, other := issue(), issue()
	if _, err := e.svc.Set(ctx, e.k.RealmID, u.ID, good, "", true, keep, audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	if revoked(keep) || !revoked(other) {
		t.Fatalf("after set: keep revoked=%v, other revoked=%v", revoked(keep), revoked(other))
	}
	other = issue()
	if err := e.svc.Remove(ctx, e.k.RealmID, u.ID, good, keep, audit.Actor{}, ""); err != nil {
		t.Fatal(err)
	}
	if revoked(keep) || !revoked(other) {
		t.Fatalf("after remove: keep revoked=%v, other revoked=%v", revoked(keep), revoked(other))
	}
}
