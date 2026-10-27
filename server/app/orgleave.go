package app

import (
	"context"
	"errors"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 退会・除名・オーナーの譲渡（design.md 4.10、ADR 0059）。

func (s publicServer) LeaveMyOrg(ctx context.Context, req publicapi.LeaveMyOrgRequestObject) (publicapi.LeaveMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.LeaveMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.LeaveMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		// 停止中・有効期間の外でも抜けられる（本人が関係を断てることを保証する。ADR 0020）。
		o, m, err := s.membership(ctx, tx, au, req.Id)
		if err != nil {
			return err
		}
		_, err = s.a.orgs.Leave(ctx, tx, o, m, au.Actor(), requestID(ctx))
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.LeaveMyOrg409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.LeaveMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, au.PrincipalID)
	return publicapi.LeaveMyOrg204Response{}, nil
}

func (s publicServer) RemoveOrgMember(ctx context.Context, req publicapi.RemoveOrgMemberRequestObject) (publicapi.RemoveOrgMemberResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.RemoveOrgMember401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.RemoveOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var userID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, by, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgRemove)
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
		userID = m.UserID
		_, err = s.a.orgs.Remove(ctx, tx, o, by, m, au.Actor(), requestID(ctx))
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.RemoveOrgMember409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.RemoveOrgMember404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.RemoveOrgMember403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, userID)
	return publicapi.RemoveOrgMember204Response{}, nil
}

func (s publicServer) TransferMyOrg(ctx context.Context, req publicapi.TransferMyOrgRequestObject) (publicapi.TransferMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.TransferMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.TransferMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case req.Body == nil:
		return publicapi.TransferMyOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, from, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgTransfer)
		if err != nil {
			return err
		}
		to, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, req.Body.MembershipId)
		if errors.Is(err, errs.NotFound) {
			return org.ErrNotMember
		}
		if err != nil {
			return err
		}
		_, _, err = s.a.orgs.Transfer(ctx, tx, o, from, to, au.Actor(), requestID(ctx))
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.TransferMyOrg409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.TransferMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.TransferMyOrg403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.TransferMyOrg204Response{}, nil
}
