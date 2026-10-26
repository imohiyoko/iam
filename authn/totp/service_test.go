package totp_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/totp"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

func setup(t *testing.T) (*testkit.Kit, *totp.Service) {
	t.Helper()
	k := testkit.New(t)
	acc := &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode}}
	return k, &totp.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Accounts: acc, Issuer: "Example"}
}

func secretOf(t *testing.T, e totp.Enrollment) []byte {
	t.Helper()
	u, err := url.Parse(e.URI)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("secret") != e.Secret {
		t.Fatalf("uri secret %q != %q", u.Query().Get("secret"), e.Secret)
	}
	b, err := totp.DecodeSecret(e.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func confirm(k *testkit.Kit, s *totp.Service, userID, flowID, code string) (port.TOTPCredential, error) {
	var c port.TOTPCredential
	err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		c, err = s.ConfirmEnroll(ctx, tx, k.RealmID, userID, flowID, code, audit.Actor{}, "")
		return err
	})
	return c, err
}

func verify(k *testkit.Kit, s *totp.Service, userID, code string) error {
	return k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		_, err := s.Verify(ctx, tx, k.RealmID, userID, code)
		return err
	})
}

func TestEnrollAndVerify(t *testing.T) {
	k, s := setup(t)
	ctx := context.Background()
	u, other := k.SeedUser(t), k.SeedUser(t)
	e, err := s.BeginEnroll(ctx, k.RealmID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret := secretOf(t, e)
	now := k.Clock.Now()
	code := totp.Code(secret, totp.Step(now))
	// 別のユーザーでは完了できない（フローは使い終わる）。
	if _, err := confirm(k, s, other.ID, e.FlowID, code); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("confirm by another user = %v", err)
	}
	e, _ = s.BeginEnroll(ctx, k.RealmID, u.ID)
	secret = secretOf(t, e)
	code = totp.Code(secret, totp.Step(now))
	// 違うコードでは失敗するが、上限まではやり直せる。
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	if _, err := confirm(k, s, u.ID, e.FlowID, wrong); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("wrong code = %v", err)
	}
	c, err := confirm(k, s, u.ID, e.FlowID, code)
	if err != nil || c.LastUsedStep != totp.Step(now) {
		t.Fatalf("confirm = %+v, %v", c, err)
	}
	// 1人に1つ。
	if _, err := s.BeginEnroll(ctx, k.RealmID, u.ID); !errors.Is(err, totp.ErrTOTPExists) {
		t.Fatalf("enroll twice = %v", err)
	}
	// 登録に使った窓のコードは、照合に再利用できない。
	if err := verify(k, s, u.ID, code); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reuse of enrollment code = %v", err)
	}
	k.Clock.Advance(30 * time.Second)
	next := totp.Code(secret, totp.Step(k.Clock.Now()))
	if err := verify(k, s, u.ID, next); err != nil {
		t.Fatal(err)
	}
	if err := verify(k, s, u.ID, next); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reuse = %v", err)
	}
	if err := verify(k, s, other.ID, totp.Code(secret, totp.Step(k.Clock.Now())+1)); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("other user's code = %v", err)
	}
	// 無効化した TOTP では通らない。
	k.Clock.Advance(30 * time.Second)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := (&account.Service{Clock: k.Clock}).RevokeTOTP(ctx, tx, k.RealmID, u.ID, c.PublicID, audit.Actor{}, "")
		return err
	})
	if err := verify(k, s, u.ID, totp.Code(secret, totp.Step(k.Clock.Now()))); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("revoked = %v", err)
	}
}

func TestEnrollExpiresAndAttempts(t *testing.T) {
	k, s := setup(t)
	ctx := context.Background()
	u := k.SeedUser(t)
	e, _ := s.BeginEnroll(ctx, k.RealmID, u.ID)
	secret := secretOf(t, e)
	for range 5 {
		if _, err := confirm(k, s, u.ID, e.FlowID, "abcdef"); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("wrong code = %v", err)
		}
	}
	// 上限の後は正しいコードでも通らない。
	if _, err := confirm(k, s, u.ID, e.FlowID, totp.Code(secret, totp.Step(k.Clock.Now()))); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("after max attempts = %v", err)
	}
	e, _ = s.BeginEnroll(ctx, k.RealmID, u.ID)
	secret = secretOf(t, e)
	k.Clock.Advance(11 * time.Minute)
	if _, err := confirm(k, s, u.ID, e.FlowID, totp.Code(secret, totp.Step(k.Clock.Now()))); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("expired = %v", err)
	}
}

func TestVerifyRateLimited(t *testing.T) {
	k, s := setup(t)
	s.PerUser = &ratelimit.Limiter{Cache: k.Cache, Clock: k.Clock, Window: 10 * time.Minute, Limit: 3}
	u := k.SeedUser(t)
	for range 3 {
		_ = verify(k, s, u.ID, "123456")
	}
	if _, ok := errors.AsType[*ratelimit.ExceededError](verify(k, s, u.ID, "123456")); !ok {
		t.Fatal("want rate limited")
	}
}

func TestVerifyReturnsInfrastructureErrors(t *testing.T) {
	k, s := setup(t)
	ctx := context.Background()
	u := k.SeedUser(t)
	e, err := s.BeginEnroll(ctx, k.RealmID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret := secretOf(t, e)
	if _, err := confirm(k, s, u.ID, e.FlowID, totp.Code(secret, totp.Step(k.Clock.Now()))); err != nil {
		t.Fatal(err)
	}
	// データキーが無いと秘密を戻せない。これは基盤の障害で、コードの不一致として隠さない。
	if err := k.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.DataKeys().Delete(ctx, u.ID)
	}); err != nil {
		t.Fatal(err)
	}
	k.Clock.Advance(time.Minute)
	err = verify(k, s, u.ID, totp.Code(secret, totp.Step(k.Clock.Now())))
	if err == nil || errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("verify without data key = %v, want an infrastructure error", err)
	}
}
