package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウントの削除（design.md 4.10、ADR 0061）。

func adminUser(u port.User) adminapi.AdminUser {
	v := adminapi.AdminUser{Id: u.PublicID, Status: adminapi.AdminUserStatus(u.Status), ValidFrom: u.ValidFrom, ValidUntil: u.ValidUntil,
		DeletionScheduledAt: u.DeletionScheduledAt}
	if u.LegalHold {
		v.LegalHold = &u.LegalHold
	}
	return v
}

func (s publicServer) DeleteMyAccount(ctx context.Context, _ publicapi.DeleteMyAccountRequestObject) (publicapi.DeleteMyAccountResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.DeleteMyAccount401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.recent(ctx, au, role.ActionMeDelete) {
		return publicapi.DeleteMyAccount401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: "reauthentication_required"}}, nil
	}
	var out publicapi.DeleteMyAccount200JSONResponse
	var revoked []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		if u.ManagedOrgID != "" {
			return org.ErrManagedUser // 管理ユーザーのアカウントは Org が扱う（ADR 0076）
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
	if code, ok := stateCode(err); ok {
		return publicapi.DeleteMyAccount409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, revoked)
	setCookie(ctx, s.a.clearSessionCookie())
	return out, nil
}

func (s publicServer) CancelMyAccountDeletion(ctx context.Context, req publicapi.CancelMyAccountDeletionRequestObject) (publicapi.CancelMyAccountDeletionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok || au.Restriction != port.RestrictionDeletion {
		return publicapi.CancelMyAccountDeletion401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	c := s.a.clientOf(ctx)
	var is session.Issued
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		if u.ManagedOrgID != "" {
			return org.ErrManagedUser // 管理ユーザーの削除は Org が決める（ADR 0076）
		}
		if _, err := s.a.accounts.CancelDeletion(ctx, tx, u, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		is, err = s.a.sessions.DeletionCancelled(ctx, tx, s.a.realm.ID, au.SessionID, c.IP, c.UserAgent, requestID(ctx))
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.CancelMyAccountDeletion409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if errors.Is(err, session.ErrNotRestricted) {
		return publicapi.CancelMyAccountDeletion401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if err != nil {
		return nil, err
	}
	s.a.sessions.Committed(ctx, s.a.realm.ID, is)
	var returnToken *bool
	if req.Body != nil {
		returnToken = req.Body.ReturnToken
	}
	return publicapi.CancelMyAccountDeletion200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, returnToken)), nil
}

// userChange は運営者による削除・取り消し・保留の共通部分。revoke なら同じトランザクションで全セッションを失効させる。
func (s adminServer) userChange(ctx context.Context, perm, publicID string, revoke bool, change func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) (port.User, error)) (adminapi.AdminUser, outcome, error) {
	p, d, err := s.a.authorize(ctx, perm)
	if o, ok, err := outcomeOf(d, err); !ok {
		return adminapi.AdminUser{}, o, err
	}
	var u port.User
	var revoked []string
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID); err != nil {
			return err
		}
		if revoke {
			if revoked, err = s.a.sessions.RevokeAllTx(ctx, tx, s.a.realm.ID, u.ID, "", account.ReasonDeletionScheduled, p.Actor, requestID(ctx)); err != nil {
				return err
			}
		}
		u, err = change(ctx, tx, u, p)
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return adminapi.AdminUser{}, o, err
	}
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, revoked)
	return adminUser(u), outcome{status: http.StatusOK}, nil
}

func (s adminServer) DeleteUser(ctx context.Context, req adminapi.DeleteUserRequestObject) (adminapi.DeleteUserResponseObject, error) {
	grace := s.a.accounts.DeletionGrace
	if req.Body != nil && req.Body.Immediate != nil && *req.Body.Immediate {
		grace = 0
	}
	out, o, err := s.userChange(ctx, role.PermUsersDelete, req.Id, true, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) (port.User, error) {
		return s.a.accounts.ScheduleDeletion(ctx, tx, u, grace, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteUser200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteUser401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteUser403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteUser404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.DeleteUser409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CancelUserDeletion(ctx context.Context, req adminapi.CancelUserDeletionRequestObject) (adminapi.CancelUserDeletionResponseObject, error) {
	out, o, err := s.userChange(ctx, role.PermUsersDelete, req.Id, false, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) (port.User, error) {
		return s.a.accounts.CancelDeletion(ctx, tx, u, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CancelUserDeletion200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CancelUserDeletion401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.CancelUserDeletion403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CancelUserDeletion404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CancelUserDeletion409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) SetUserLegalHold(ctx context.Context, req adminapi.SetUserLegalHoldRequestObject) (adminapi.SetUserLegalHoldResponseObject, error) {
	if req.Body == nil {
		return adminapi.SetUserLegalHold400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	out, o, err := s.userChange(ctx, role.PermUsersLegalHold, req.Id, false, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) (port.User, error) {
		return s.a.accounts.SetLegalHold(ctx, tx, u, req.Body.Hold, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SetUserLegalHold200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SetUserLegalHold400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SetUserLegalHold401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SetUserLegalHold403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SetUserLegalHold404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
