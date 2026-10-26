package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

func check(t *testing.T, k *testkit.Kit, u port.User, since time.Time) (*time.Time, []string) {
	t.Helper()
	var next *time.Time
	var codes []string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Users().Get(ctx, k.RealmID, u.ID)
		if err != nil {
			return err
		}
		next, err = account.Check(ctx, tx, cur, since, k.Clock.Now())
		if d, ok := errors.AsType[*account.UnavailableError](err); ok {
			codes = d.Reasons()
			return nil
		}
		return err
	})
	return next, codes
}

func suspend(t *testing.T, k *testkit.Kit, s *account.Service, u port.User, in account.Suspend) (port.Suspension, bool) {
	t.Helper()
	var sp port.Suspension
	var created bool
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		sp, created, err = s.SuspendUser(ctx, tx, k.RealmID, u, in, audit.Actor{Type: "user", ID: "usr_admin"}, "")
		return err
	})
	return sp, created
}

func at(t time.Time) *time.Time { return &t }

// 予約した停止は開始の時刻ちょうどに効き、終わりの時刻ちょうどに解ける。境界のイベントは時刻の後に1回だけ出る（4.7、4.8）。
func TestSuspensionBoundaries(t *testing.T) {
	k := testkit.New(t)
	s := &account.Service{Clock: k.Clock}
	u := k.SeedUser(t)
	t0 := k.Clock.Now()
	start, end := t0.Add(time.Hour), t0.Add(2*time.Hour)
	sp, _ := suspend(t, k, s, u, account.Suspend{Category: account.CategoryBilling, Reason: "unpaid", StartsAt: &start, EndsAt: &end})

	next, codes := check(t, k, u, t0)
	if codes != nil || next == nil || !next.Equal(start) {
		t.Fatalf("before start: next=%v codes=%v", next, codes)
	}
	k.Clock.Advance(time.Hour - time.Nanosecond)
	if _, codes := check(t, k, u, k.Clock.Now()); codes != nil {
		t.Fatalf("just before start: %v", codes)
	}
	k.Clock.Advance(time.Nanosecond)
	if _, codes := check(t, k, u, k.Clock.Now()); !slices.Equal(codes, []string{"suspended.billing"}) {
		t.Fatalf("at start: %v", codes)
	}
	k.Clock.Advance(time.Hour)
	if _, codes := check(t, k, u, k.Clock.Now()); codes != nil {
		t.Fatalf("at end: %v", codes)
	}
	// 停止をまたいだセッション（認証が停止の前）は、停止が終わっても戻らない。
	if _, codes := check(t, k, u, t0); !slices.Equal(codes, []string{"suspended.billing"}) {
		t.Fatalf("session spanning suspension: %v", codes)
	}

	sch := &eventlog.Scheduler{Storage: k.Storage, Clock: k.Clock}
	n, err := sch.Fire(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("fire = %d, %v", n, err)
	}
	if n, _ := sch.Fire(context.Background()); n != 0 {
		t.Fatalf("second fire = %d", n)
	}
	var types []string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, k.RealmID, 1, 100)
		for _, r := range rs {
			e, _ := audit.Unmarshal(r.Payload)
			types = append(types, e.Type)
		}
		return err
	})
	if !slices.Equal(types, []string{"user.suspended", account.EventSuspensionStarted, account.EventSuspensionEnded}) {
		t.Fatalf("audit = %v (suspension %s)", types, sp.PublicID)
	}
}

// 重ねた停止は全部が解けるまで止まり、コードは種別ごとに1つ。解除は予約の取り消しも兼ねる。
func TestSuspensionStackAndLift(t *testing.T) {
	k := testkit.New(t)
	s := &account.Service{Clock: k.Clock, ExtraCategories: []string{"fraud_review"}}
	u := k.SeedUser(t)
	a, _ := suspend(t, k, s, u, account.Suspend{Category: account.CategoryTOSViolation, Reason: "r"})
	b, _ := suspend(t, k, s, u, account.Suspend{Category: "fraud_review", Reason: "r", EndsAt: at(k.Clock.Now().Add(time.Hour))})
	suspend(t, k, s, u, account.Suspend{Category: account.CategoryTOSViolation, Reason: "r"})
	if _, codes := check(t, k, u, k.Clock.Now()); !slices.Equal(codes, []string{"suspended.fraud_review", "suspended.tos_violation"}) {
		t.Fatalf("stacked: %v", codes)
	}
	k.Clock.Advance(time.Minute)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		ss, err := tx.Suspensions().ListByTarget(ctx, k.RealmID, port.SuspensionTargetUser, u.ID)
		for _, x := range ss {
			if x.Category == account.CategoryTOSViolation {
				if _, err := s.LiftSuspension(ctx, tx, k.RealmID, x, "resolved", audit.Actor{Type: "user", ID: "usr_admin"}, ""); err != nil {
					return err
				}
			}
		}
		return err
	})
	if _, codes := check(t, k, u, k.Clock.Now()); !slices.Equal(codes, []string{"suspended.fraud_review"}) {
		t.Fatalf("after lifting tos: %v", codes)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.LiftSuspension(ctx, tx, k.RealmID, b, "resolved", audit.Actor{}, "")
		return err
	})
	if _, codes := check(t, k, u, k.Clock.Now()); codes != nil {
		t.Fatalf("after lifting all: %v", codes)
	}
	// 解除した停止の終わりのイベントは出ない。
	k.Clock.Advance(2 * time.Hour)
	if n, err := (&eventlog.Scheduler{Storage: k.Storage, Clock: k.Clock}).Fire(context.Background()); err != nil || n != 0 {
		t.Fatalf("fire after lift = %d, %v (%s)", n, err, a.PublicID)
	}
	// 始まる前に解除した予約は効かない。
	start := k.Clock.Now().Add(time.Hour)
	c, _ := suspend(t, k, s, u, account.Suspend{Category: account.CategoryBilling, Reason: "r", StartsAt: &start})
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.LiftSuspension(ctx, tx, k.RealmID, c, "resolved", audit.Actor{}, "")
		return err
	})
	k.Clock.Advance(2 * time.Hour)
	if next, codes := check(t, k, u, k.Clock.Now()); codes != nil || next != nil {
		t.Fatalf("lifted reservation: %v %v", next, codes)
	}
}

func TestSuspendValidation(t *testing.T) {
	k := testkit.New(t)
	s := &account.Service{Clock: k.Clock}
	u := k.SeedUser(t)
	now := k.Clock.Now()
	cases := []struct {
		in   account.Suspend
		want error
	}{
		{account.Suspend{Category: "nope", Reason: "r"}, account.ErrUnknownCategory},
		{account.Suspend{Category: account.CategoryBilling, Reason: "r", EndsAt: at(now)}, account.ErrInvalidPeriod},
		{account.Suspend{Category: account.CategoryBilling, Reason: "r", StartsAt: at(now.Add(time.Hour)), EndsAt: at(now.Add(time.Minute))}, account.ErrInvalidPeriod},
		{account.Suspend{Category: account.CategoryBilling, Reason: string(make([]byte, 1001))}, account.ErrReason},
		{account.Suspend{Category: account.CategoryBilling, Reason: "  "}, account.ErrReason},
	}
	for _, c := range cases {
		err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			_, _, err := s.SuspendUser(ctx, tx, k.RealmID, u, c.in, audit.Actor{}, "")
			return err
		})
		if !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.in, err, c.want)
		}
	}
	// external_ref で冪等。
	a, created := suspend(t, k, s, u, account.Suspend{Category: account.CategoryBilling, Reason: "r", ExternalRef: "inv_1"})
	b, again := suspend(t, k, s, u, account.Suspend{Category: account.CategoryBilling, Reason: "r", ExternalRef: "inv_1"})
	if !created || again || a.ID != b.ID {
		t.Fatalf("idempotent: %v %v %s %s", created, again, a.ID, b.ID)
	}
}

// 有効期間の始まりと終わりは時刻ちょうどに効く。終わりは次の再検証の期限になる。
func TestValidityBoundaries(t *testing.T) {
	k := testkit.New(t)
	s := &account.Service{Clock: k.Clock}
	u := k.SeedUser(t)
	from, until := k.Clock.Now().Add(time.Hour), k.Clock.Now().Add(3*time.Hour)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.SetValidity(ctx, tx, k.RealmID, u, &from, &until, audit.Actor{}, "")
		return err
	})
	if _, codes := check(t, k, u, k.Clock.Now()); !slices.Equal(codes, []string{account.CodeOutsideValidity}) {
		t.Fatalf("before from: %v", codes)
	}
	k.Clock.Advance(time.Hour)
	next, codes := check(t, k, u, k.Clock.Now())
	if codes != nil || next == nil || !next.Equal(until) {
		t.Fatalf("at from: %v %v", next, codes)
	}
	k.Clock.Advance(2 * time.Hour)
	if _, codes := check(t, k, u, k.Clock.Now()); !slices.Equal(codes, []string{account.CodeOutsideValidity}) {
		t.Fatalf("at until: %v", codes)
	}
	if n, err := (&eventlog.Scheduler{Storage: k.Storage, Clock: k.Clock}).Fire(context.Background()); err != nil || n != 2 {
		t.Fatalf("fire = %d, %v", n, err)
	}
	// 置き換えると、未発火の予約は取り消される。
	later := k.Clock.Now().Add(time.Hour)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cur, _ := tx.Users().Get(ctx, k.RealmID, u.ID)
		if _, err := s.SetValidity(ctx, tx, k.RealmID, cur, nil, &later, audit.Actor{}, ""); err != nil {
			return err
		}
		_, err := s.SetValidity(ctx, tx, k.RealmID, cur, nil, nil, audit.Actor{}, "")
		return err
	})
	k.Clock.Advance(2 * time.Hour)
	if n, _ := (&eventlog.Scheduler{Storage: k.Storage, Clock: k.Clock}).Fire(context.Background()); n != 0 {
		t.Fatalf("fire after reset = %d", n)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.SetValidity(ctx, tx, k.RealmID, u, &until, &from, audit.Actor{}, "")
		if !errors.Is(err, account.ErrInvalidPeriod) {
			t.Errorf("until before from = %v", err)
		}
		return nil
	})
}

// 削除済みのユーザーは理由を返さない。
func TestCheckInactive(t *testing.T) {
	k := testkit.New(t)
	u := k.SeedUser(t)
	u.Status = port.UserDeleted
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := account.Check(ctx, tx, u, k.Clock.Now(), k.Clock.Now())
		if !errors.Is(err, account.ErrInactive) {
			t.Errorf("deleted = %v", err)
		}
		return nil
	})
}
