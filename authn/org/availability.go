package org

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Check は Membership m とその Org o が now に使えるかを時刻から計算する（design.md 4.7、4.8、ADR 0058）。
// 使えなければ *account.UnavailableError（Org と Membership の理由を合わせる）、active でない Membership は ErrNoAvailableOrg。
// 個人 Org は個別に止められず、有効期間も持たない（本人の可否はユーザーの検証で見る）。
// Org の停止は措置の間だけ Org の操作を止めるもので、解除すれば戻る（セッションを失効させるユーザーの停止とは違い、since は now）。
// next は now より後で可否が次に変わりうる最も早い時刻で、無ければ nil。
func Check(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, now time.Time) (*time.Time, error) {
	if m.Status != port.MembershipActive {
		return nil, ErrNoAvailableOrg
	}
	if o.Kind == port.OrgPersonal {
		return nil, nil
	}
	var codes []string
	collect := func(next *time.Time, err error) (*time.Time, error) {
		if ue, ok := errors.AsType[*account.UnavailableError](err); ok {
			codes = append(codes, ue.Codes...)
			return nil, nil
		}
		return next, err
	}
	n1, err := collect(account.CheckWindow(ctx, tx, o.RealmID, port.SuspensionTargetOrg, o.ID, o.ValidFrom, o.ValidUntil, now, now))
	if err != nil {
		return nil, err
	}
	n2, err := collect(account.CheckWindow(ctx, tx, m.RealmID, port.SuspensionTargetMembership, m.ID, m.ValidFrom, m.ValidUntil, now, now))
	if err != nil {
		return nil, err
	}
	if len(codes) > 0 {
		slices.Sort(codes)
		return nil, &account.UnavailableError{Codes: slices.Compact(codes)}
	}
	switch {
	case n1 == nil:
		return n2, nil
	case n2 == nil || n1.Before(*n2):
		return n1, nil
	}
	return n2, nil
}

// CheckActive はセッションの active な Org（内部 ID）が本人にとって now に使えるかを返す（Check。5.3）。
// 所属が無ければ ErrNoAvailableOrg。
func (s *Service) CheckActive(ctx context.Context, tx port.Tx, realmID, userID, orgID string, now time.Time) (*time.Time, error) {
	o, err := tx.Orgs().Get(ctx, realmID, orgID)
	if err != nil {
		return nil, err
	}
	m, err := tx.Memberships().GetByUserOrg(ctx, realmID, userID, orgID)
	if errors.Is(err, errs.NotFound) {
		return nil, ErrNoAvailableOrg
	}
	if err != nil {
		return nil, err
	}
	return Check(ctx, tx, o, m, now)
}
