package org

import (
	"context"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 退会・除名・オーナーの譲渡（design.md 4.10、ADR 0059）。

// Membership の終了の理由。
const (
	EndedLeft       = "left"
	EndedRemoved    = "removed"
	EndedOrgDeleted = "org_deleted"
)

var (
	// ErrLastOwner は最後のオーナーを外そうとしたこと。先に譲るか Org を削除する（4.10）。
	ErrLastOwner = errs.WithCode(errs.KindFailedPrecondition, "last_owner", "transfer ownership or delete the org first")
	// ErrNotMember は譲渡先が active なメンバーでないこと。
	ErrNotMember = errs.WithCode(errs.KindFailedPrecondition, "not_member", "target is not an active member")
)

// Ended は Membership を終えた結果。
type Ended struct {
	Membership port.Membership
	// Sessions は個人 Org に移したセッションの ID（呼び出し側が検証結果のキャッシュを消す）。
	Sessions []string
}

// Leave は本人が共有 Org から退会する（4.10。個人ユーザーには常に許す）。最後のオーナーは抜けられない。
func (s *Service) Leave(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, actor audit.Actor, requestID string) (Ended, error) {
	return s.end(ctx, tx, o, m, EndedLeft, actor, requestID)
}

// Remove は Org の管理者 by が target を除名する（ended_reason = removed）。本人と、owner でない管理者からの owner は対象にできない。
func (s *Service) Remove(ctx context.Context, tx port.Tx, o port.Org, by, target port.Membership, actor audit.Actor, requestID string) (Ended, error) {
	if err := ManageMember(by, target); err != nil {
		return Ended{}, err
	}
	return s.end(ctx, tx, o, target, EndedRemoved, actor, requestID)
}

// end は Membership を終える。終了の時刻を有効期間の終わりにし、結び付けたメールを外し、
// その Org を active にしているセッションを個人 Org に移す（4.10）。Group 所属とロール付与は M4 で外す。
func (s *Service) end(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, reason string, actor audit.Actor, requestID string) (Ended, error) {
	if err := Suspendable(o); err != nil {
		return Ended{}, err
	}
	if m.Status == port.MembershipEnded {
		return Ended{}, errs.New(errs.KindNotFound, "membership")
	}
	if m.Role == port.OrgOwner && m.Status == port.MembershipActive && reason != EndedOrgDeleted {
		n, err := tx.Memberships().CountActive(ctx, o.RealmID, o.ID, port.OrgOwner)
		if err != nil {
			return Ended{}, err
		}
		if n <= 1 {
			return Ended{}, ErrLastOwner
		}
	}
	now := s.Clock.Now()
	m.Status, m.EndedReason, m.EmailID, m.UpdatedAt = port.MembershipEnded, reason, "", now
	if m.ValidUntil == nil || m.ValidUntil.After(now) {
		m.ValidUntil = new(now)
	}
	if err := tx.Memberships().Update(ctx, m); err != nil {
		return Ended{}, err
	}
	u, err := tx.Users().Get(ctx, o.RealmID, m.UserID)
	if err != nil {
		return Ended{}, err
	}
	p, err := s.EnsurePersonal(ctx, tx, u, requestID)
	if err != nil {
		return Ended{}, err
	}
	moved, err := tx.Sessions().MoveOrg(ctx, o.RealmID, u.ID, o.ID, p.ID)
	if err != nil {
		return Ended{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "membership.ended", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"membership_id": m.PublicID, "user_id": u.PublicID, "reason": reason},
	})
	return Ended{Membership: m, Sessions: moved}, err
}

// Transfer は owner の from から、同じ Org の active なメンバー to にオーナーを譲る（4.10）。to は owner に、from は admin になる。
// 権限（org:transfer）は呼び出し側が見る。
func (s *Service) Transfer(ctx context.Context, tx port.Tx, o port.Org, from, to port.Membership, actor audit.Actor, requestID string) (port.Membership, port.Membership, error) {
	if err := Suspendable(o); err != nil {
		return port.Membership{}, port.Membership{}, err
	}
	if from.Role != port.OrgOwner {
		return port.Membership{}, port.Membership{}, errs.WithCode(errs.KindPermissionDenied, errs.CodePermissionDenied, "only an owner can transfer")
	}
	if from.UserID == to.UserID {
		return port.Membership{}, port.Membership{}, ErrSelfTarget
	}
	if to.OrgID != o.ID || to.Status != port.MembershipActive {
		return port.Membership{}, port.Membership{}, ErrNotMember
	}
	now := s.Clock.Now()
	to.Role, to.UpdatedAt = port.OrgOwner, now
	from.Role, from.UpdatedAt = port.OrgAdmin, now
	if err := tx.Memberships().Update(ctx, to); err != nil {
		return port.Membership{}, port.Membership{}, err
	}
	if err := tx.Memberships().Update(ctx, from); err != nil {
		return port.Membership{}, port.Membership{}, err
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.ownership_transferred", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"from_membership_id": from.PublicID, "to_membership_id": to.PublicID},
	})
	return from, to, err
}
