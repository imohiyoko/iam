package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org と Membership（design.md 4.4、4.11、11.13、ADR 0055）。フィーチャー org が動いていなければ 404。

func myOrg(j org.Joined, activeOrgID string) publicapi.MyOrg {
	v := publicapi.MyOrg{Id: j.Org.PublicID, Kind: publicapi.MyOrgKind(j.Org.Kind), Role: publicapi.MyOrgRole(j.Membership.Role),
		MembershipId: j.Membership.PublicID, Active: j.Org.ID == activeOrgID}
	if j.Org.Name != "" {
		v.Name = &j.Org.Name
	}
	st := publicapi.MyOrgStatus(j.Membership.Status)
	v.Status = &st
	return v
}

func (s publicServer) ListMyOrgs(ctx context.Context, _ publicapi.ListMyOrgsRequestObject) (publicapi.ListMyOrgsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyOrgs401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.ListMyOrgs404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	}
	out := publicapi.ListMyOrgs200JSONResponse{Orgs: []publicapi.MyOrg{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		js, err := s.a.orgs.ListForUser(ctx, tx, s.a.realm.ID, au.PrincipalID)
		for _, j := range js {
			out.Orgs = append(out.Orgs, myOrg(j, au.ActiveOrgID))
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s publicServer) CreateMyOrg(ctx context.Context, req publicapi.CreateMyOrgRequestObject) (publicapi.CreateMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CreateMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.CreateMyOrg404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	}
	if req.Body == nil {
		return publicapi.CreateMyOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var j org.Joined
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		j.Org, j.Membership, err = s.a.orgs.Create(ctx, tx, u, req.Body.Name, false, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, errs.Invalid):
		return publicapi.CreateMyOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.CreateMyOrg403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CreateMyOrg201JSONResponse(myOrg(j, au.ActiveOrgID)), nil
}

// ---------------------------------------------------------------------------

func orgView(o port.Org, ownerPublicID string) adminapi.Org {
	v := adminapi.Org{Id: o.PublicID, Kind: adminapi.OrgKind(o.Kind), CreatedAt: o.CreatedAt, ValidFrom: o.ValidFrom, ValidUntil: o.ValidUntil}
	if o.Name != "" {
		v.Name = &o.Name
	}
	if ownerPublicID != "" {
		v.PersonalOwnerId = &ownerPublicID
	}
	return v
}

// adminOrg は公開 ID の Org と、個人 Org の持ち主の公開 ID を返す。
func (s adminServer) adminOrg(ctx context.Context, tx port.Tx, publicID string) (port.Org, adminapi.Org, error) {
	o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, publicID)
	if err != nil {
		return port.Org{}, adminapi.Org{}, err
	}
	var owner string
	if o.Kind == port.OrgPersonal {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, o.PersonalOwnerID)
		if err != nil {
			return port.Org{}, adminapi.Org{}, err
		}
		owner = u.PublicID
	}
	return o, orgView(o, owner), nil
}

func (s adminServer) CreateOrg(ctx context.Context, req adminapi.CreateOrgRequestObject) (adminapi.CreateOrgResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermOrgsCreate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateOrg401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateOrg403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.CreateOrg404JSONResponse(adminError("org_disabled", "")), nil
	}
	if req.Body == nil {
		return adminapi.CreateOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var out adminapi.Org
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Body.OwnerId)
		if err != nil {
			return err
		}
		o, _, err := s.a.orgs.Create(ctx, tx, u, req.Body.Name, true, p.Actor, requestID(ctx))
		out = orgView(o, "")
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.CreateOrg404JSONResponse(adminError("not_found", "owner")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.CreateOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	return adminapi.CreateOrg201JSONResponse(out), nil
}

func (s adminServer) GetOrg(ctx context.Context, req adminapi.GetOrgRequestObject) (adminapi.GetOrgResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.GetOrg401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.GetOrg403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.GetOrg404JSONResponse(adminError("org_disabled", "")), nil
	}
	var out adminapi.Org
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		_, out, err = s.adminOrg(ctx, tx, req.Id)
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.GetOrg404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	return adminapi.GetOrg200JSONResponse(out), nil
}

func (s adminServer) ListOrgMemberships(ctx context.Context, req adminapi.ListOrgMembershipsRequestObject) (adminapi.ListOrgMembershipsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListOrgMemberships401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.ListOrgMemberships403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.ListOrgMemberships404JSONResponse(adminError("org_disabled", "")), nil
	}
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 200 {
		return adminapi.ListOrgMemberships400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", "limit must be within [1, 200]"))}, nil
	}
	out := adminapi.ListOrgMemberships200JSONResponse{Memberships: []adminapi.Membership{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.adminOrg(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		// 1件多く取り、続きがあるかを知る。
		ms, err := tx.Memberships().ListByOrg(ctx, s.a.realm.ID, o.ID, deref(req.Params.After), limit+1)
		if err != nil {
			return err
		}
		if len(ms) > limit {
			ms = ms[:limit]
			next := ms[limit-1].PublicID
			out.NextCursor = &next
		}
		for _, m := range ms {
			u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
			if err != nil {
				return err
			}
			v := adminapi.Membership{Id: m.PublicID, UserId: u.PublicID, OrgId: o.PublicID, Status: adminapi.MembershipStatus(m.Status),
				Role: adminapi.MembershipRole(m.Role), ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil, CreatedAt: m.CreatedAt}
			if m.EndedReason != "" {
				v.EndedReason = &m.EndedReason
			}
			out.Memberships = append(out.Memberships, v)
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.ListOrgMemberships404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	return out, nil
}
