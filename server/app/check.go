package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可の判定の API（design.md 4.5、ADR 0064）。判定は判定の材料のキャッシュを使う（反映の遅れは validity_max_delay まで）。

// checkResource は API の対象のリソースを判定の形にする。種類と ID は両方か、どちらも無しか。
func checkResource(typ, rid *string) (check.Resource, bool) {
	var r check.Resource
	if typ != nil {
		r.Type = *typ
	}
	if rid != nil {
		r.ID = *rid
	}
	return r, (r.Type == "") == (r.ID == "")
}

func (s adminServer) CheckAuthz(ctx context.Context, req adminapi.CheckAuthzRequestObject) (adminapi.CheckAuthzResponseObject, error) {
	_, d, err := s.a.authorizeWith(ctx, role.PermAuthzCheck, true)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CheckAuthz401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CheckAuthz403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.CheckAuthz400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	b := req.Body
	res, ok := checkResource(b.ResourceType, b.ResourceId)
	if !ok || !role.ValidPermission(b.Action) || (b.PrincipalType != nil && *b.PrincipalType != adminapi.CheckRequestPrincipalTypeUser) {
		return adminapi.CheckAuthz400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var r check.Request
	var reasons []string
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, b.PrincipalId)
		if err != nil {
			return err
		}
		// 使えないユーザーは何もできない（ログインと同じ規則。4.7、4.8）。
		now := s.a.deps.Clock.Now()
		if _, err := account.Check(ctx, tx, u, now, now); err != nil {
			if ue, ok := errors.AsType[*account.UnavailableError](err); ok {
				reasons = ue.Reasons()
				return nil
			}
			if errors.Is(err, account.ErrInactive) {
				reasons = []string{"inactive"}
				return nil
			}
			return err
		}
		r = check.Request{Principal: check.Principal{Type: port.PrincipalUser, ID: u.ID}, Action: b.Action, Resource: res}
		if b.OrgId != nil && s.a.orgs != nil {
			o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *b.OrgId)
			if err != nil {
				return err
			}
			r.OrgID = o.ID
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.CheckAuthz404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	case reasons != nil:
		return adminapi.CheckAuthz200JSONResponse{Allowed: false, Reasons: &reasons}, nil
	}
	allowed, err := s.a.authz.Check(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	return adminapi.CheckAuthz200JSONResponse{Allowed: allowed}, nil
}

func (s publicServer) CheckMyAuthz(ctx context.Context, req publicapi.CheckMyAuthzRequestObject) (publicapi.CheckMyAuthzResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CheckMyAuthz401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	b := req.Body
	if b == nil {
		return publicapi.CheckMyAuthz400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	res, ok := checkResource(b.ResourceType, b.ResourceId)
	if !ok || !role.ValidPermission(b.Action) {
		return publicapi.CheckMyAuthz400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	r := check.Request{Principal: check.Principal{Type: au.PrincipalType, ID: au.PrincipalID}, Action: b.Action, Resource: res, OrgID: au.ActiveOrgID}
	if b.OrgId != nil && s.a.orgs != nil {
		err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *b.OrgId)
			r.OrgID = o.ID
			return err
		})
		if errors.Is(err, errs.NotFound) {
			// 無い Org では何もできない（所属していない Org と区別しない）。
			return publicapi.CheckMyAuthz200JSONResponse{Allowed: false}, nil
		}
		if err != nil {
			return nil, err
		}
	}
	allowed, err := s.a.authz.Check(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	return publicapi.CheckMyAuthz200JSONResponse{Allowed: allowed}, nil
}
