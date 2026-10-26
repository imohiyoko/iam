package org_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/port"
)

func codes(err error) []string {
	if ue, ok := errors.AsType[*account.UnavailableError](err); ok {
		return ue.Codes
	}
	return nil
}

func TestCheck(t *testing.T) {
	k := testkit.New(t)
	accounts := &account.Service{Clock: k.Clock, Crypter: k.Crypter}
	s := &org.Service{Clock: k.Clock, Crypter: k.Crypter, Accounts: accounts}
	u := k.SeedUser(t)
	actor := audit.Actor{Type: "operator", ID: "op"}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		now := k.Clock.Now()
		personal, err := s.CreatePersonal(ctx, tx, u, actor, "")
		if err != nil {
			return err
		}
		pm, err := tx.Memberships().GetByUserOrg(ctx, u.RealmID, u.ID, personal.ID)
		if err != nil {
			return err
		}
		// 個人 Org は止められず、常に使える。
		if _, err := s.SetOrgValidity(ctx, tx, personal, nil, &now, actor, ""); !errors.Is(err, org.ErrPersonalOrg) {
			t.Fatalf("personal validity = %v", err)
		}
		if next, err := org.Check(ctx, tx, personal, pm, now); err != nil || next != nil {
			t.Fatalf("personal = %v, %v", next, err)
		}

		acme, m, err := s.Create(ctx, tx, u, "Acme", false, actor, "")
		if err != nil {
			return err
		}
		later, end := now.Add(time.Hour), now.Add(2*time.Hour)
		// 予約した停止と有効期間の終わりのうち、早いほうが次の判定の時刻。
		if _, _, err := accounts.Suspend(ctx, tx, u.RealmID, org.MembershipTarget(m), account.Suspend{Category: account.CategoryCustomerRequest, Reason: "x", StartsAt: &later}, actor, ""); err != nil {
			return err
		}
		if acme, err = s.SetOrgValidity(ctx, tx, acme, nil, &end, actor, ""); err != nil {
			return err
		}
		if next, err := org.Check(ctx, tx, acme, m, now); err != nil || next == nil || !next.Equal(later) {
			t.Fatalf("before = %v, %v", next, err)
		}
		// Org と Membership の理由を合わせて返す。
		if _, _, err := accounts.Suspend(ctx, tx, u.RealmID, org.OrgTarget(acme), account.Suspend{Category: account.CategoryBilling, Reason: "x"}, actor, ""); err != nil {
			return err
		}
		k.Clock.Advance(2 * time.Hour)
		_, err = org.Check(ctx, tx, acme, m, k.Clock.Now())
		if got := codes(err); !slices.Equal(got, []string{"outside_validity", "suspended.billing", "suspended.customer_request"}) {
			t.Fatalf("after = %v", err)
		}
		// 使えない Org はログインの候補から外れ、明示的に指定すれば理由を返す。
		if got, err := s.Pick(ctx, tx, u, session.OrgPick{}); err != nil || got.OrgID != personal.ID {
			t.Fatalf("pick = %+v, %v", got, err)
		}
		if _, err := s.Pick(ctx, tx, u, session.OrgPick{Explicit: acme.ID}); len(codes(err)) != 3 {
			t.Fatalf("pick explicit = %v", err)
		}
		// 所属が終わっていれば ErrNoAvailableOrg。
		m.Status = port.MembershipEnded
		if _, err := org.Check(ctx, tx, acme, m, k.Clock.Now()); !errors.Is(err, org.ErrNoAvailableOrg) {
			t.Fatalf("ended = %v", err)
		}
		return nil
	})
}
