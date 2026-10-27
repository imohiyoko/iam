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

// Org のドメインの所有証明（design.md 11.3、ADR 0075）。Org の owner（org:settings）が扱う。

func orgDomainOut(d port.OrgDomain) publicapi.OrgDomain {
	name, value := org.DomainRecord(d)
	st := publicapi.OrgDomainStatusPending
	if d.VerifiedAt != nil {
		st = publicapi.OrgDomainStatusVerified
	}
	return publicapi.OrgDomain{Id: d.PublicID, Domain: d.Domain, Status: st, TxtName: name, TxtValue: value, VerifiedAt: d.VerifiedAt,
		CheckedAt: d.CheckedAt, CreatedAt: d.CreatedAt}
}

// domainsOn はフィーチャー org と org_managed_users が動いているか。
func (s publicServer) domainsOn() bool { return s.a.orgs != nil && s.a.orgs.ManagedUsers }

func (s publicServer) ListOrgDomains(ctx context.Context, req publicapi.ListOrgDomainsRequestObject) (publicapi.ListOrgDomainsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListOrgDomains401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.ListOrgDomains404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := publicapi.ListOrgDomains200JSONResponse{Domains: []publicapi.OrgDomain{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		ds, err := s.a.orgs.Domains(ctx, tx, o)
		for _, d := range ds {
			out.Domains = append(out.Domains, orgDomainOut(d))
		}
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgDomains404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgDomains403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func (s publicServer) AddOrgDomain(ctx context.Context, req publicapi.AddOrgDomainRequestObject) (publicapi.AddOrgDomainResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.AddOrgDomain401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.AddOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.AddOrgDomain400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var out port.OrgDomain
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		out, err = s.a.orgs.AddDomain(ctx, tx, o, req.Body.Domain, au.Actor(), requestID(ctx))
		return err
	})
	if c, ok := stateCode(err); ok {
		return publicapi.AddOrgDomain409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.AddOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.AddOrgDomain403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.AddOrgDomain400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.AddOrgDomain201JSONResponse(orgDomainOut(out)), nil
}

// VerifyOrgDomain は DNS をトランザクションの外で引く。読む・引く・書くの間に消されたら 404。
func (s publicServer) VerifyOrgDomain(ctx context.Context, req publicapi.VerifyOrgDomainRequestObject) (publicapi.VerifyOrgDomainResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.VerifyOrgDomain401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.VerifyOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var d port.OrgDomain
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		d, err = s.a.orgs.Domain(ctx, tx, o, req.DomainId)
		return err
	})
	found := false
	if err == nil && d.VerifiedAt == nil {
		found, err = s.a.orgs.LookupDomain(ctx, d)
	}
	var checked error
	if err == nil {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
			if err != nil {
				return err
			}
			// 見つからなかったときも確かめた時刻は残す（ErrDomainNotProven ではトランザクションを取り消さない）。
			d, checked = s.a.orgs.MarkDomainChecked(ctx, tx, o, req.DomainId, d.Token, found, au.Actor(), requestID(ctx))
			if errors.Is(checked, org.ErrDomainNotProven) {
				return nil
			}
			return checked
		})
		if err == nil {
			err = checked
		}
	}
	if c, ok := stateCode(err); ok {
		return publicapi.VerifyOrgDomain409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.VerifyOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.VerifyOrgDomain403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Unavailable):
		return publicapi.VerifyOrgDomain503JSONResponse{Error: "dns_unavailable"}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.VerifyOrgDomain200JSONResponse(orgDomainOut(d)), nil
}

func (s publicServer) DeleteOrgDomain(ctx context.Context, req publicapi.DeleteOrgDomainRequestObject) (publicapi.DeleteOrgDomainResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.DeleteOrgDomain401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.DeleteOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		d, err := s.a.orgs.Domain(ctx, tx, o, req.DomainId)
		if err != nil {
			return err
		}
		return s.a.orgs.RemoveDomain(ctx, tx, o, d, au.Actor(), requestID(ctx))
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.DeleteOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.DeleteOrgDomain403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.DeleteOrgDomain204Response{}, nil
}
