package org

import (
	"context"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 管理ユーザー（design.md 11.3、フィーチャー org_managed_users、ADR 0076）。
//
// 個人ユーザーは本人が所有する。管理ユーザーは Org が所有する（users.managed_org_id）。既存のユーザーを管理ユーザーにするには、
// Org の owner が求め（memberships.management_requested_at）、本人が受け入れる。対象は、この Org で使うメール
// （結び付けたメールか primary）が確認済みで、そのドメインを Org が証明済みのメンバーに限る。
// 管理ユーザーはその Org を自分で抜けられず、自分でアカウントを消せない。Org が除名・削除・手放すと個人ユーザーに戻る。

const (
	EventManagementRequested = "org.management.requested"
	EventManagementDeclined  = "org.management.declined"
	EventManagementCanceled  = "org.management.canceled"
	EventUserManaged         = "user.managed"
	EventUserReleased        = "user.management_released"
)

var (
	// ErrManagedUser は管理ユーザーには（本人が）できない操作（Org を抜ける・アカウントを消す）。
	ErrManagedUser = errs.WithCode(errs.KindFailedPrecondition, "managed_user", "the account is managed by an org")
	// ErrAlreadyManaged は対象が既にこの Org の管理ユーザーであること。
	ErrAlreadyManaged = errs.WithCode(errs.KindConflict, "already_managed", "already managed by the org")
	// ErrManagedByAnotherOrg は対象が別の Org の管理ユーザーであること。
	ErrManagedByAnotherOrg = errs.WithCode(errs.KindConflict, "managed_by_another_org", "managed by another org")
	// ErrEmailDomainNotVerified は対象のメールが未確認か、そのドメインを Org が証明していないこと。
	ErrEmailDomainNotVerified = errs.WithCode(errs.KindFailedPrecondition, "email_domain_not_verified",
		"the member's email is not in a domain verified by the org")
	// ErrNoManagementRequest は管理の求めが無いこと。
	ErrNoManagementRequest = errs.WithCode(errs.KindFailedPrecondition, "no_management_request", "no management request")
	// ErrNotManaged は対象がこの Org の管理ユーザーでも、求めの途中でもないこと。
	ErrNotManaged = errs.WithCode(errs.KindFailedPrecondition, "not_managed", "not managed by the org")
)

// IsManaged は u が o の管理ユーザーか。
func IsManaged(u port.User, o port.Org) bool { return u.ManagedOrgID != "" && u.ManagedOrgID == o.ID }

// managedDomain は m（この Org で使うメール）が確認済みで、そのドメインを o が証明済みかを確かめる。
// ドメインはブラインドインデックスで比べる（復号しない。最小化モードでも判定できる）。
func (s *Service) managedDomain(ctx context.Context, tx port.Tx, o port.Org, m port.Membership) error {
	ds, err := tx.OrgDomains().ListByOrg(ctx, o.RealmID, o.ID)
	if err != nil {
		return err
	}
	var verified []string
	for _, d := range ds {
		if d.VerifiedAt != nil {
			verified = append(verified, d.Domain)
		}
	}
	ok, err := s.emailInDomains(ctx, tx, m, verified)
	if err == nil && !ok {
		err = ErrEmailDomainNotVerified
	}
	return err
}

// managedState は対象のユーザーが管理を受けられるか（既に管理されていないか）を確かめる。
func managedState(u port.User, o port.Org) error {
	switch {
	case IsManaged(u, o):
		return ErrAlreadyManaged
	case u.ManagedOrgID != "":
		return ErrManagedByAnotherOrg
	}
	return nil
}

// RequestManagement は target のユーザーに、o による管理を求める。求め済みなら何もしない。権限（org:settings）は呼び出し側が見る。
func (s *Service) RequestManagement(ctx context.Context, tx port.Tx, o port.Org, target port.Membership, actor audit.Actor, requestID string) (port.Membership, error) {
	if o.Kind != port.OrgShared {
		return port.Membership{}, ErrPersonalOrg
	}
	if target.Status != port.MembershipActive {
		return port.Membership{}, ErrNotMember
	}
	u, err := tx.Users().Get(ctx, o.RealmID, target.UserID)
	if err != nil {
		return port.Membership{}, err
	}
	if err := managedState(u, o); err != nil {
		return port.Membership{}, err
	}
	if err := s.managedDomain(ctx, tx, o, target); err != nil {
		return port.Membership{}, err
	}
	if target.ManagementRequestedAt != nil {
		return target, nil
	}
	now := s.Clock.Now()
	target.ManagementRequestedAt, target.UpdatedAt = &now, now
	if err := tx.Memberships().Update(ctx, target); err != nil {
		return port.Membership{}, err
	}
	return target, s.recordManaged(ctx, tx, o, EventManagementRequested, target, u, actor, requestID)
}

// AcceptManagement は本人（m のユーザー）が管理の求めを受け入れ、o の管理ユーザーになる。
func (s *Service) AcceptManagement(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, actor audit.Actor, requestID string) (port.User, error) {
	if m.ManagementRequestedAt == nil || m.Status != port.MembershipActive {
		return port.User{}, ErrNoManagementRequest
	}
	u, err := tx.Users().Get(ctx, o.RealmID, m.UserID)
	if err != nil {
		return port.User{}, err
	}
	if err := managedState(u, o); err != nil {
		return port.User{}, err
	}
	// 求めの後にメールやドメインが変わっていないか、受け入れの時点で確かめ直す。
	if err := s.managedDomain(ctx, tx, o, m); err != nil {
		return port.User{}, err
	}
	now := s.Clock.Now()
	if err := tx.Users().SetManagedOrg(ctx, o.RealmID, u.ID, o.ID, now); err != nil {
		return port.User{}, err
	}
	u.ManagedOrgID, u.ManagedAt, u.UpdatedAt = o.ID, &now, now
	m.ManagementRequestedAt, m.UpdatedAt = nil, now
	if err := tx.Memberships().Update(ctx, m); err != nil {
		return port.User{}, err
	}
	return u, s.recordManaged(ctx, tx, o, EventUserManaged, m, u, actor, requestID)
}

// DeclineManagement は本人が管理の求めを断る。
func (s *Service) DeclineManagement(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, actor audit.Actor, requestID string) error {
	if m.ManagementRequestedAt == nil {
		return ErrNoManagementRequest
	}
	return s.clearRequest(ctx, tx, o, m, EventManagementDeclined, actor, requestID)
}

// ReleaseManagement は Org が target の管理を手放す（個人ユーザーに戻す）。求めの途中なら求めを取り消す。
// 権限（org:settings）は呼び出し側が見る。
func (s *Service) ReleaseManagement(ctx context.Context, tx port.Tx, o port.Org, target port.Membership, actor audit.Actor, requestID string) error {
	u, err := tx.Users().Get(ctx, o.RealmID, target.UserID)
	if err != nil {
		return err
	}
	switch {
	case IsManaged(u, o):
		return s.release(ctx, tx, o, target, u, actor, requestID)
	case target.ManagementRequestedAt != nil:
		return s.clearRequest(ctx, tx, o, target, EventManagementCanceled, actor, requestID)
	}
	return ErrNotManaged
}

func (s *Service) clearRequest(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, typ string, actor audit.Actor, requestID string) error {
	u, err := tx.Users().Get(ctx, o.RealmID, m.UserID)
	if err != nil {
		return err
	}
	now := s.Clock.Now()
	m.ManagementRequestedAt, m.UpdatedAt = nil, now
	if err := tx.Memberships().Update(ctx, m); err != nil {
		return err
	}
	return s.recordManaged(ctx, tx, o, typ, m, u, actor, requestID)
}

// release は u を個人ユーザーに戻す（Org が手放す・除名・Org の削除）。
func (s *Service) release(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, u port.User, actor audit.Actor, requestID string) error {
	if err := tx.Users().SetManagedOrg(ctx, o.RealmID, u.ID, "", s.Clock.Now()); err != nil {
		return err
	}
	return s.recordManaged(ctx, tx, o, EventUserReleased, m, u, actor, requestID)
}

func (s *Service) recordManaged(ctx context.Context, tx port.Tx, o port.Org, typ string, m port.Membership, u port.User, actor audit.Actor, requestID string) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID,
		Actor: actor, RequestID: requestID, Details: map[string]any{"membership_id": m.PublicID, "user_id": u.PublicID}})
	return err
}
