package app

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ユーザーの停止と有効期間（design.md 4.7、4.8、ADR 0053）。

// suspensionPerm は種別を停止・解除する権限。realm で足した種別は realm:owner（suspensions:*）だけ。
func suspensionPerm(category string) string {
	if slices.Contains(account.BuiltinCategories, category) {
		return role.SuspensionPerm(category)
	}
	return role.PermSuspensionsAny
}

func (s adminServer) suspensionView(sp port.Suspension, userPublicID string) adminapi.Suspension {
	now := s.a.deps.Clock.Now()
	end := sp.EndsAt
	if sp.LiftedAt != nil && (end == nil || sp.LiftedAt.Before(*end)) {
		end = sp.LiftedAt
	}
	v := adminapi.Suspension{Id: sp.PublicID, UserId: userPublicID, Category: sp.Category, Reason: sp.Reason,
		StartsAt: sp.StartsAt, EndsAt: sp.EndsAt, CreatedAt: sp.CreatedAt, LiftedAt: sp.LiftedAt,
		Active: !sp.StartsAt.After(now) && (end == nil || end.After(now))}
	if sp.ExternalRef != "" {
		v.ExternalRef = &sp.ExternalRef
	}
	if sp.CreatedBy != "" {
		v.CreatedBy = &sp.CreatedBy
	}
	if sp.LiftedBy != "" {
		v.LiftedBy = &sp.LiftedBy
	}
	return v
}

func (s adminServer) SuspendUser(ctx context.Context, req adminapi.SuspendUserRequestObject) (adminapi.SuspendUserResponseObject, error) {
	if req.Body == nil {
		return adminapi.SuspendUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	p, d, err := s.a.authorize(ctx, suspensionPerm(req.Body.Category))
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.SuspendUser401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.SuspendUser403JSONResponse(d.Body), nil
	}
	in := account.Suspend{Category: req.Body.Category, Reason: req.Body.Reason, StartsAt: req.Body.StartsAt, EndsAt: req.Body.EndsAt}
	if req.Body.ExternalRef != nil {
		in.ExternalRef = *req.Body.ExternalRef
	}
	var u port.User
	var out adminapi.Suspension
	var created bool
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		var sp port.Suspension
		if sp, created, err = s.a.accounts.SuspendUser(ctx, tx, s.a.realm.ID, u, in, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out = s.suspensionView(sp, u.PublicID)
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.SuspendUser404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.SuspendUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	if !created {
		return adminapi.SuspendUser200JSONResponse(out), nil
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, u.ID)
	return adminapi.SuspendUser201JSONResponse(out), nil
}

func (s adminServer) ListUserSuspensions(ctx context.Context, req adminapi.ListUserSuspensionsRequestObject) (adminapi.ListUserSuspensionsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermSuspensionsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListUserSuspensions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.ListUserSuspensions403JSONResponse(d.Body), nil
	}
	out := adminapi.Suspensions{Suspensions: []adminapi.Suspension{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		ss, err := tx.Suspensions().ListByTarget(ctx, s.a.realm.ID, port.SuspensionTargetUser, u.ID)
		for _, sp := range ss {
			out.Suspensions = append(out.Suspensions, s.suspensionView(sp, u.PublicID))
		}
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.ListUserSuspensions404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.ListUserSuspensions200JSONResponse(out), nil
}

func (s adminServer) LiftSuspension(ctx context.Context, req adminapi.LiftSuspensionRequestObject) (adminapi.LiftSuspensionResponseObject, error) {
	// 種別が分かるまでは一覧の権限で確かめ、権限の無い人に停止の有無を見せない。
	p, d, err := s.a.authorize(ctx, role.PermSuspensionsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.LiftSuspension401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.LiftSuspension403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.LiftSuspension400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var sp port.Suspension
	var u port.User
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if sp, err = tx.Suspensions().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		if sp.TargetType != port.SuspensionTargetUser {
			return errs.New(errs.KindNotFound, "suspension")
		}
		u, err = tx.Users().Get(ctx, s.a.realm.ID, sp.TargetID)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.LiftSuspension404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	if _, d, err = s.a.authorize(ctx, suspensionPerm(sp.Category)); err != nil {
		return nil, err
	} else if d != nil {
		return adminapi.LiftSuspension403JSONResponse(d.Body), nil
	}
	// 本人は自分の停止を解除できない（4.7）。
	if p.Type == port.PrincipalUser && p.ID == u.ID {
		return adminapi.LiftSuspension403JSONResponse(adminError(errs.CodePermissionDenied, "cannot lift own suspension")), nil
	}
	var out adminapi.Suspension
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Suspensions().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if cur, err = s.a.accounts.LiftSuspension(ctx, tx, s.a.realm.ID, cur, req.Body.Reason, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out = s.suspensionView(cur, u.PublicID)
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.LiftSuspension404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.LiftSuspension400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	return adminapi.LiftSuspension200JSONResponse(out), nil
}

func (s adminServer) UpdateUser(ctx context.Context, req adminapi.UpdateUserRequestObject) (adminapi.UpdateUserResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersUpdate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.UpdateUser401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.UpdateUser403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.UpdateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var u port.User
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		u, err = s.a.accounts.SetValidity(ctx, tx, s.a.realm.ID, u, req.Body.ValidFrom, req.Body.ValidUntil, p.Actor, requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.UpdateUser404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.UpdateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, u.ID)
	return adminapi.UpdateUser200JSONResponse{Id: u.PublicID, Status: adminapi.AdminUserStatus(u.Status), ValidFrom: u.ValidFrom, ValidUntil: u.ValidUntil}, nil
}
