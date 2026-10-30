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

// orgTarget は、対象が Org なら resource_id を判定先の Org（公開 ID）にして返す。org_id と食い違えば ok は false。
// 判定先を先に決め、その Org を内部 ID に直して所属を確かめるため（Checker はリソースの Org を判定先にする）。
func orgTarget(orgID *string, res check.Resource) (*string, check.Resource, bool) {
	if res.Type != check.ResourceOrg {
		return orgID, res, true
	}
	if orgID != nil && *orgID != res.ID {
		return nil, res, false
	}
	return &res.ID, check.Resource{}, true
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
	orgID := b.OrgId
	if ok {
		orgID, res, ok = orgTarget(orgID, res)
	}
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
		if orgID != nil && s.a.orgs != nil {
			o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *orgID)
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
	dec, err := s.a.authz.Decide(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	out := adminapi.CheckAuthz200JSONResponse{Allowed: dec.Allow}
	if len(dec.Unmet) > 0 {
		out.Unmet = &dec.Unmet
	}
	return out, nil
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
	orgID := b.OrgId
	if ok {
		orgID, res, ok = orgTarget(orgID, res)
	}
	if !ok || !role.ValidPermission(b.Action) {
		return publicapi.CheckMyAuthz400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	r := check.Request{Principal: check.Principal{Type: au.PrincipalType, ID: au.PrincipalID}, Action: b.Action, Resource: res, OrgID: au.ActiveOrgID,
		Context: sessionContext(au.Validated)}
	// realm の範囲の付与は所属を見ないので、判定の文脈の Org（指定したか、active な Org）に使える所属があるかを確かめる。
	if s.a.orgs != nil && (orgID != nil || r.OrgID != "") {
		member := false
		err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			if orgID != nil {
				o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *orgID)
				if err != nil {
					return err
				}
				r.OrgID = o.ID
			}
			var err error
			_, member, err = authzMembers{}.OrgRole(ctx, tx, s.a.realm.ID, r.Principal, r.OrgID, s.a.deps.Clock.Now())
			return err
		})
		if errors.Is(err, errs.NotFound) || (err == nil && !member) {
			// 無い Org と所属していない Org では何もできない（区別しない）。
			return publicapi.CheckMyAuthz200JSONResponse{Allowed: false}, nil
		}
		if err != nil {
			return nil, err
		}
	}
	d, err := s.a.authz.Decide(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	out := publicapi.CheckMyAuthz200JSONResponse{Allowed: d.Allow}
	if len(d.Unmet) > 0 {
		out.Unmet = &d.Unmet
	}
	return out, nil
}
