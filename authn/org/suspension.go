package org

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org と Membership の停止と有効期間（design.md 4.7、4.8、ADR 0058）。停止そのものは account.Service.Suspend で作る。

// ErrSelfTarget は自分の Membership を止める・変えるなど、本人を対象にした Org の管理操作（4.7）。
var ErrSelfTarget = errs.WithCode(errs.KindPermissionDenied, "self_target", "cannot target own membership")

// OrgTarget は Org の停止の対象。
func OrgTarget(o port.Org) account.Target {
	return account.Target{Type: port.SuspensionTargetOrg, ID: o.ID, PublicID: o.PublicID}
}

// MembershipTarget は Membership の停止の対象。
func MembershipTarget(m port.Membership) account.Target {
	return account.Target{Type: port.SuspensionTargetMembership, ID: m.ID, PublicID: m.PublicID}
}

// Suspendable は Org とその Membership を止めたり有効期間を付けたりできるかを確かめる。個人 Org はできない（4.7）。
func Suspendable(o port.Org) error {
	if o.Kind == port.OrgPersonal {
		return ErrPersonalOrg
	}
	return nil
}

// ManageMember は Org の管理者 actor が Membership target を止める・変えることができるかを確かめる（4.7）。
// 本人は対象にできず、owner は owner だけが対象にできる（招待と同じ）。権限（org:suspend など）は呼び出し側が見る。
func ManageMember(actor, target port.Membership) error {
	if actor.UserID == target.UserID {
		return ErrSelfTarget
	}
	if target.Role == port.OrgOwner && actor.Role != port.OrgOwner {
		return errs.WithCode(errs.KindPermissionDenied, errs.CodePermissionDenied, "only an owner can manage an owner")
	}
	return nil
}

// SetOrgValidity は Org の有効期間を置き換える（nil は制限なし。4.8）。境界のイベントを予約し直す。
func (s *Service) SetOrgValidity(ctx context.Context, tx port.Tx, o port.Org, from, until *time.Time, actor audit.Actor, requestID string) (port.Org, error) {
	if err := Suspendable(o); err != nil {
		return port.Org{}, err
	}
	if err := account.ValidPeriod(from, until); err != nil {
		return port.Org{}, err
	}
	now := s.Clock.Now()
	if err := tx.Orgs().SetValidity(ctx, o.RealmID, o.ID, from, until, now); err != nil {
		return port.Org{}, err
	}
	o.ValidFrom, o.ValidUntil, o.UpdatedAt = from, until, now
	return o, s.Accounts.ValidityChanged(ctx, tx, o.RealmID, OrgTarget(o), from, until, actor, requestID)
}

// SetMembershipValidity は Membership の有効期間を置き換える（4.8）。
func (s *Service) SetMembershipValidity(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, from, until *time.Time, actor audit.Actor, requestID string) (port.Membership, error) {
	if err := Suspendable(o); err != nil {
		return port.Membership{}, err
	}
	if m.Status == port.MembershipEnded {
		return port.Membership{}, errs.New(errs.KindNotFound, "membership")
	}
	if err := account.ValidPeriod(from, until); err != nil {
		return port.Membership{}, err
	}
	m.ValidFrom, m.ValidUntil, m.UpdatedAt = from, until, s.Clock.Now()
	if err := tx.Memberships().Update(ctx, m); err != nil {
		return port.Membership{}, err
	}
	return m, s.Accounts.ValidityChanged(ctx, tx, o.RealmID, MembershipTarget(m), from, until, actor, requestID)
}
