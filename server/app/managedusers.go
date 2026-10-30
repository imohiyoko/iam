package app

import (
	"context"
	"errors"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 管理ユーザー（design.md 11.3、ADR 0076）。Org の owner（org:settings）が求めて手放し、本人が受け入れて断る。

// managedResult は管理の操作の結果の分類。
type managedResult int

const (
	managedOK managedResult = iota
	managedUnauthenticated
	managedNotFound
	managedDenied
	managedConflict
)

// managedOutcome は err を分類する。code は 403 と 409 の本文のコード。
func managedOutcome(err error) (managedResult, string, error) {
	if c, ok := stateCode(err); ok {
		return managedConflict, c, nil
	}
	switch {
	case err == nil:
		return managedOK, "", nil
	case errors.Is(err, errs.NotFound):
		return managedNotFound, "", nil
	case errors.Is(err, errs.PermissionDenied):
		return managedDenied, "", nil
	}
	return 0, "", err
}

// managedTarget は Org の owner が対象のメンバーに fn を行う。
func (s publicServer) managedTarget(ctx context.Context, orgID, membershipID string, fn func(ctx context.Context, tx port.Tx, o port.Org, target port.Membership, au auth) error) (managedResult, string, error, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return managedUnauthenticated, "", nil, nil
	}
	if !s.domainsOn() {
		return managedNotFound, "", nil, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, orgID, role.PermOrgSettings)
		if err != nil {
			return err
		}
		m, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, membershipID)
		if err == nil && m.OrgID != o.ID {
			err = errs.New(errs.KindNotFound, "membership")
		}
		if err != nil {
			return err
		}
		return fn(ctx, tx, o, m, au)
	})
	r, code, err2 := managedOutcome(err)
	return r, code, err, err2
}

// managedSelf は本人が、自分の Membership に fn を行う。
func (s publicServer) managedSelf(ctx context.Context, orgID string, fn func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error) (managedResult, string, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return managedUnauthenticated, "", nil
	}
	if !s.domainsOn() {
		return managedNotFound, "", nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, m, err := s.orgMember(ctx, tx, au, orgID, "")
		if err != nil {
			return err
		}
		return fn(ctx, tx, o, m, au)
	})
	r, code, err := managedOutcome(err)
	if r == managedDenied {
		r = managedNotFound // 本人の操作に 403 は無い（使えない Org は無いものとして扱う）
	}
	return r, code, err
}

func (s publicServer) RequestOrgManagement(ctx context.Context, req publicapi.RequestOrgManagementRequestObject) (publicapi.RequestOrgManagementResponseObject, error) {
	r, code, cause, err := s.managedTarget(ctx, req.Id, req.MembershipId, func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error {
		_, err := s.a.orgs.RequestManagement(ctx, tx, o, m, au.Actor(), requestID(ctx))
		return err
	})
	switch r {
	case managedUnauthenticated:
		return publicapi.RequestOrgManagement401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case managedNotFound:
		return publicapi.RequestOrgManagement404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case managedDenied:
		return publicapi.RequestOrgManagement403JSONResponse{DeniedJSONResponse: orgDenied(cause)}, nil
	case managedConflict:
		return publicapi.RequestOrgManagement409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RequestOrgManagement204Response{}, nil
}

func (s publicServer) ReleaseOrgManagement(ctx context.Context, req publicapi.ReleaseOrgManagementRequestObject) (publicapi.ReleaseOrgManagementResponseObject, error) {
	r, code, cause, err := s.managedTarget(ctx, req.Id, req.MembershipId, func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error {
		return s.a.orgs.ReleaseManagement(ctx, tx, o, m, au.Actor(), requestID(ctx))
	})
	switch r {
	case managedUnauthenticated:
		return publicapi.ReleaseOrgManagement401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case managedNotFound:
		return publicapi.ReleaseOrgManagement404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case managedDenied:
		return publicapi.ReleaseOrgManagement403JSONResponse{DeniedJSONResponse: orgDenied(cause)}, nil
	case managedConflict:
		return publicapi.ReleaseOrgManagement409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.ReleaseOrgManagement204Response{}, nil
}

func (s publicServer) AcceptOrgManagement(ctx context.Context, req publicapi.AcceptOrgManagementRequestObject) (publicapi.AcceptOrgManagementResponseObject, error) {
	// 抜けることも自分で消すこともできなくなるので、直近の本人確認を求める（盗まれたセッションで受け入れさせない）。
	if au, ok := authFrom(ctx); ok && !s.recent(ctx, au, role.ActionMeAcceptManagement) {
		return publicapi.AcceptOrgManagement401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	r, code, err := s.managedSelf(ctx, req.Id, func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error {
		_, err := s.a.orgs.AcceptManagement(ctx, tx, o, m, au.Actor(), requestID(ctx))
		return err
	})
	switch r {
	case managedUnauthenticated:
		return publicapi.AcceptOrgManagement401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case managedNotFound:
		return publicapi.AcceptOrgManagement404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case managedConflict:
		return publicapi.AcceptOrgManagement409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.AcceptOrgManagement204Response{}, nil
}

func (s publicServer) DeclineOrgManagement(ctx context.Context, req publicapi.DeclineOrgManagementRequestObject) (publicapi.DeclineOrgManagementResponseObject, error) {
	r, code, err := s.managedSelf(ctx, req.Id, func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error {
		return s.a.orgs.DeclineManagement(ctx, tx, o, m, au.Actor(), requestID(ctx))
	})
	switch r {
	case managedUnauthenticated:
		return publicapi.DeclineOrgManagement401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case managedNotFound:
		return publicapi.DeclineOrgManagement404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case managedConflict:
		return publicapi.DeclineOrgManagement409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.DeclineOrgManagement204Response{}, nil
}

// DeleteManagedAccount は Org の owner が管理ユーザーのアカウントの削除を予約する（本人の削除と同じ猶予）。
func (s publicServer) DeleteManagedAccount(ctx context.Context, req publicapi.DeleteManagedAccountRequestObject) (publicapi.DeleteManagedAccountResponseObject, error) {
	var out publicapi.DeleteManagedAccount200JSONResponse
	var revoked []string
	r, code, cause, err := s.managedTarget(ctx, req.Id, req.MembershipId, func(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, au auth) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
		if err != nil {
			return err
		}
		if !org.IsManaged(u, o) {
			return org.ErrNotManaged
		}
		if u.ID == au.PrincipalID {
			return org.ErrSelfTarget
		}
		if revoked, err = s.a.sessions.RevokeAllTx(ctx, tx, s.a.realm.ID, u.ID, "", account.ReasonDeletionScheduled, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		if u, err = s.a.accounts.ScheduleDeletion(ctx, tx, u, s.a.accounts.DeletionGrace, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		out.DeletesAt, out.Deleted = u.DeletionScheduledAt, u.Status == port.UserDeleted
		return nil
	})
	switch r {
	case managedUnauthenticated:
		return publicapi.DeleteManagedAccount401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case managedNotFound:
		return publicapi.DeleteManagedAccount404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case managedDenied:
		return publicapi.DeleteManagedAccount403JSONResponse{DeniedJSONResponse: orgDenied(cause)}, nil
	case managedConflict:
		return publicapi.DeleteManagedAccount409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, revoked)
	return out, nil
}
