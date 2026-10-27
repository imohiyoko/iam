package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org の削除（design.md 4.10、ADR 0060）。

// orgOwner は本人が perm（org:delete）を持つ Org を返す。削除の予定がある Org は使えない（deletion_scheduled）ので、
// 可否（停止・有効期間）は見ない。
func (s publicServer) orgOwner(ctx context.Context, tx port.Tx, au auth, orgPublicID, perm string) (port.Org, error) {
	o, m, err := s.membership(ctx, tx, au, orgPublicID)
	if err != nil {
		return port.Org{}, err
	}
	if o.DeletedAt != nil {
		return port.Org{}, errs.New(errs.KindNotFound, "org")
	}
	if !role.OrgAllows(m, perm) {
		return port.Org{}, errOrgPermission
	}
	return o, nil
}

func (s publicServer) DeleteMyOrg(ctx context.Context, req publicapi.DeleteMyOrgRequestObject) (publicapi.DeleteMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.DeleteMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.DeleteMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var out publicapi.DeleteMyOrg200JSONResponse
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := s.orgOwner(ctx, tx, au, req.Id, role.PermOrgDelete)
		if err != nil {
			return err
		}
		if o, err = s.a.orgs.ScheduleDeletion(ctx, tx, o, s.a.orgs.DeletionGrace, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		out.DeletesAt, out.Deleted = *o.DeletionScheduledAt, o.DeletedAt != nil
		return nil
	})
	if code, ok := stateCode(err); ok {
		return publicapi.DeleteMyOrg409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.DeleteMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.DeleteMyOrg403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, au.PrincipalID)
	return out, nil
}

func (s publicServer) CancelMyOrgDeletion(ctx context.Context, req publicapi.CancelMyOrgDeletionRequestObject) (publicapi.CancelMyOrgDeletionResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.CancelMyOrgDeletion401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.CancelMyOrgDeletion404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := s.orgOwner(ctx, tx, au, req.Id, role.PermOrgDelete)
		if err != nil {
			return err
		}
		_, err = s.a.orgs.CancelDeletion(ctx, tx, o, au.Actor(), requestID(ctx))
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.CancelMyOrgDeletion409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.CancelMyOrgDeletion404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.CancelMyOrgDeletion403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CancelMyOrgDeletion204Response{}, nil
}

// orgDeletion は運営者による削除と取り消しの共通部分。
func (s adminServer) orgDeletion(ctx context.Context, publicID string, change func(ctx context.Context, tx port.Tx, o port.Org, p adminPrincipal) (port.Org, error)) (adminapi.Org, outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermOrgsDelete)
	if o, ok, err := outcomeOf(d, err); !ok {
		return adminapi.Org{}, o, err
	}
	if o, off := s.orgsOff(true); off {
		return adminapi.Org{}, o, nil
	}
	var out adminapi.Org
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, publicID)
		if err != nil {
			return err
		}
		if o, err = change(ctx, tx, o, p); err != nil {
			return err
		}
		out = orgView(o, "")
		return nil
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return adminapi.Org{}, o, err
	}
	return out, outcome{status: http.StatusOK}, nil
}

func (s adminServer) DeleteOrg(ctx context.Context, req adminapi.DeleteOrgRequestObject) (adminapi.DeleteOrgResponseObject, error) {
	out, o, err := s.orgDeletion(ctx, req.Id, func(ctx context.Context, tx port.Tx, o port.Org, p adminPrincipal) (port.Org, error) {
		grace := s.a.orgs.DeletionGrace
		if req.Body != nil && req.Body.Immediate != nil && *req.Body.Immediate {
			grace = 0
		}
		return s.a.orgs.ScheduleDeletion(ctx, tx, o, grace, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteOrg200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteOrg401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteOrg403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteOrg404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.DeleteOrg409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CancelOrgDeletion(ctx context.Context, req adminapi.CancelOrgDeletionRequestObject) (adminapi.CancelOrgDeletionResponseObject, error) {
	out, o, err := s.orgDeletion(ctx, req.Id, func(ctx context.Context, tx port.Tx, o port.Org, p adminPrincipal) (port.Org, error) {
		return s.a.orgs.CancelDeletion(ctx, tx, o, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CancelOrgDeletion200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CancelOrgDeletion401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.CancelOrgDeletion403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CancelOrgDeletion404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CancelOrgDeletion409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
