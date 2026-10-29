package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org の管理者による Membership の停止と有効期間（design.md 4.7、4.8、ADR 0058）。種別は customer_request だけ。

func orgSuspension(sp port.Suspension, m port.Membership, now time.Time) publicapi.OrgSuspension {
	end := sp.EndsAt
	if sp.LiftedAt != nil && (end == nil || sp.LiftedAt.Before(*end)) {
		end = sp.LiftedAt
	}
	return publicapi.OrgSuspension{Id: sp.PublicID, MembershipId: m.PublicID, Category: sp.Category, Reason: sp.Reason,
		StartsAt: sp.StartsAt, EndsAt: sp.EndsAt, CreatedAt: sp.CreatedAt, LiftedAt: sp.LiftedAt,
		Active: !sp.StartsAt.After(now) && (end == nil || end.After(now))}
}

// orgTarget は Org の管理者 au が perm で操作する、同じ Org の Membership を返す。個人 Org は ErrPersonalOrg。
// 本人と、owner でない管理者からの owner は対象にできない（org.ManageMember）。
func (s publicServer) orgTarget(ctx context.Context, tx port.Tx, au auth, orgPublicID, membershipPublicID, perm string) (port.Org, port.Membership, error) {
	o, actor, err := s.orgMember(ctx, tx, au, orgPublicID, perm)
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	m, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, membershipPublicID)
	if err == nil && (m.OrgID != o.ID || m.Status == port.MembershipEnded) {
		err = errs.New(errs.KindNotFound, "membership")
	}
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	if err := org.Suspendable(o); err != nil {
		return port.Org{}, port.Membership{}, err
	}
	return o, m, org.ManageMember(actor, m)
}

func (s publicServer) UpdateOrgMember(ctx context.Context, req publicapi.UpdateOrgMemberRequestObject) (publicapi.UpdateOrgMemberResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.UpdateOrgMember401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.UpdateOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case req.Body == nil:
		return publicapi.UpdateOrgMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var out publicapi.OrgMember
	var userID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, m, err := s.orgTarget(ctx, tx, au, req.Id, req.MembershipId, role.PermOrgInvite)
		if err != nil {
			return err
		}
		if m, err = s.a.orgs.SetMembershipValidity(ctx, tx, o, m, req.Body.ValidFrom, req.Body.ValidUntil, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		userID = m.UserID
		out, err = s.orgMemberView(ctx, tx, m)
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.UpdateOrgMember409JSONResponse{ConflictJSONResponse: conflictOf(err, code)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.UpdateOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.UpdateOrgMember403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.UpdateOrgMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, userID)
	return publicapi.UpdateOrgMember200JSONResponse(out), nil
}

func (s publicServer) SuspendOrgMember(ctx context.Context, req publicapi.SuspendOrgMemberRequestObject) (publicapi.SuspendOrgMemberResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.SuspendOrgMember401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.SuspendOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case req.Body == nil:
		return publicapi.SuspendOrgMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	in := account.Suspend{Category: account.CategoryCustomerRequest, Reason: req.Body.Reason, StartsAt: req.Body.StartsAt, EndsAt: req.Body.EndsAt}
	var out publicapi.OrgSuspension
	var userID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, m, err := s.orgTarget(ctx, tx, au, req.Id, req.MembershipId, role.PermOrgSuspend)
		if err != nil {
			return err
		}
		sp, _, err := s.a.accounts.Suspend(ctx, tx, s.a.realm.ID, org.MembershipTarget(m), in, au.Actor(), requestID(ctx))
		if err != nil {
			return err
		}
		userID, out = m.UserID, orgSuspension(sp, m, s.a.deps.Clock.Now())
		return nil
	})
	if code, ok := stateCode(err); ok {
		return publicapi.SuspendOrgMember409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.SuspendOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.SuspendOrgMember403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.SuspendOrgMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, userID)
	return publicapi.SuspendOrgMember201JSONResponse(out), nil
}

func (s publicServer) ListOrgMemberSuspensions(ctx context.Context, req publicapi.ListOrgMemberSuspensionsRequestObject) (publicapi.ListOrgMemberSuspensionsResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.ListOrgMemberSuspensions401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.ListOrgMemberSuspensions404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := publicapi.ListOrgMemberSuspensions200JSONResponse{Suspensions: []publicapi.OrgSuspension{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSuspend)
		if err != nil {
			return err
		}
		m, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, req.MembershipId)
		if err == nil && m.OrgID != o.ID {
			err = errs.New(errs.KindNotFound, "membership")
		}
		if err != nil {
			return err
		}
		ss, err := tx.Suspensions().ListByTarget(ctx, s.a.realm.ID, port.SuspensionTargetMembership, m.ID)
		now := s.a.deps.Clock.Now()
		for _, sp := range ss {
			// 運営者による停止は見せない（理由を含め、Org の管理者の扱う範囲ではない）。
			if sp.Category == account.CategoryCustomerRequest {
				out.Suspensions = append(out.Suspensions, orgSuspension(sp, m, now))
			}
		}
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgMemberSuspensions404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgMemberSuspensions403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func (s publicServer) LiftOrgSuspension(ctx context.Context, req publicapi.LiftOrgSuspensionRequestObject) (publicapi.LiftOrgSuspensionResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.LiftOrgSuspension401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.LiftOrgSuspension404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case req.Body == nil:
		return publicapi.LiftOrgSuspension400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var out publicapi.OrgSuspension
	var userID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, actor, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSuspend)
		if err != nil {
			return err
		}
		sp, err := tx.Suspensions().GetByPublicID(ctx, s.a.realm.ID, req.SuspensionId)
		if err == nil && (sp.TargetType != port.SuspensionTargetMembership || sp.Category != account.CategoryCustomerRequest) {
			err = errs.New(errs.KindNotFound, "suspension")
		}
		if err != nil {
			return err
		}
		m, err := tx.Memberships().Get(ctx, s.a.realm.ID, sp.TargetID)
		if err == nil && m.OrgID != o.ID {
			err = errs.New(errs.KindNotFound, "suspension")
		}
		if err != nil {
			return err
		}
		if err := org.ManageMember(actor, m); err != nil {
			return err
		}
		if sp, err = s.a.accounts.LiftSuspension(ctx, tx, s.a.realm.ID, sp, req.Body.Reason, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		userID, out = m.UserID, orgSuspension(sp, m, s.a.deps.Clock.Now())
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.LiftOrgSuspension404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.LiftOrgSuspension403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.LiftOrgSuspension400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, userID)
	return publicapi.LiftOrgSuspension200JSONResponse(out), nil
}
