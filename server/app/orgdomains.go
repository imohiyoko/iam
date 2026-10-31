package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org のドメインの所有証明（design.md 11.3、ADR 0075）。Org の owner（org:settings）と運営者（orgs:update）が扱う。

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

// verifyDomain は DNS をトランザクションの外で引く。load は各トランザクションで Org を読み直し、呼び出し側の権限を確かめる。
// 読む・引く・書くの間に消されたら errs.NotFound。DNS の障害だけを dnsDown で返す（Storage の errs.Unavailable と分ける）。
func (a *App) verifyDomain(ctx context.Context, load func(ctx context.Context, tx port.Tx) (port.Org, error), domainID string, actor audit.Actor) (d port.OrgDomain, dnsDown bool, err error) {
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := load(ctx, tx)
		if err != nil {
			return err
		}
		d, err = a.orgs.Domain(ctx, tx, o, domainID)
		return err
	})
	if err != nil {
		return d, false, err
	}
	found := false
	// 証明済みなら、確かめ直しで TXT が見つからなくなっている（猶予の間）ときだけ引く（ADR 0087）。
	if d.VerifiedAt == nil || d.MissingSince != nil {
		var lerr error
		if found, lerr = a.orgs.LookupDomain(ctx, d); lerr != nil {
			return d, errors.Is(lerr, errs.Unavailable), lerr
		}
	}
	var checked error
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := load(ctx, tx)
		if err != nil {
			return err
		}
		// 見つからなかったときも確かめた時刻は残す（ErrDomainNotProven ではトランザクションを取り消さない）。
		d, checked = a.orgs.MarkDomainChecked(ctx, tx, o, domainID, d.Token, found, actor, requestID(ctx))
		if errors.Is(checked, org.ErrDomainNotProven) {
			return nil
		}
		return checked
	})
	if err == nil {
		err = checked
	}
	return d, false, err
}

func (s publicServer) VerifyOrgDomain(ctx context.Context, req publicapi.VerifyOrgDomainRequestObject) (publicapi.VerifyOrgDomainResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.VerifyOrgDomain401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.VerifyOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	d, dnsDown, err := s.a.verifyDomain(ctx, func(ctx context.Context, tx port.Tx) (port.Org, error) {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		return o, err
	}, req.DomainId, au.Actor())
	if dnsDown {
		return publicapi.VerifyOrgDomain503JSONResponse{Error: "dns_unavailable"}, nil
	}
	if c, ok := stateCode(err); ok {
		return publicapi.VerifyOrgDomain409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.VerifyOrgDomain404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.VerifyOrgDomain403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
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

// 管理 API（権限 orgs:update）。

func adminOrgDomainOut(d port.OrgDomain) adminapi.OrgDomain {
	v := orgDomainOut(d)
	return adminapi.OrgDomain{Id: v.Id, Domain: v.Domain, Status: adminapi.OrgDomainStatus(v.Status), TxtName: v.TxtName, TxtValue: v.TxtValue,
		VerifiedAt: v.VerifiedAt, CheckedAt: v.CheckedAt, CreatedAt: v.CreatedAt}
}

// manageOrgDomains は権限 orgs:update とフィーチャーを確かめる。
func (s adminServer) manageOrgDomains(ctx context.Context) (adminPrincipal, outcome, bool, error) {
	p, d, err := s.a.authorize(ctx, role.PermOrgsUpdate)
	if o, ok, err := outcomeOf(d, err); !ok {
		return p, o, false, err
	}
	if o, off := s.orgsOff(true); off {
		return p, o, false, nil
	}
	if !s.a.orgs.ManagedUsers {
		return p, failed(http.StatusNotFound, "org_managed_users_disabled"), false, nil
	}
	return p, outcome{}, true, nil
}

func (s adminServer) adminDomainOrg(ctx context.Context, tx port.Tx, publicID string) (port.Org, error) {
	o, _, err := s.adminOrg(ctx, tx, publicID)
	if err == nil && o.DeletedAt != nil {
		err = errs.New(errs.KindNotFound, "org")
	}
	return o, err
}

func (s adminServer) AdminListOrgDomains(ctx context.Context, req adminapi.AdminListOrgDomainsRequestObject) (adminapi.AdminListOrgDomainsResponseObject, error) {
	out := adminapi.AdminListOrgDomains200JSONResponse{Domains: []adminapi.OrgDomain{}}
	_, o, ok, err := s.manageOrgDomains(ctx)
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			org, err := s.adminDomainOrg(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			ds, err := s.a.orgs.Domains(ctx, tx, org)
			for _, d := range ds {
				out.Domains = append(out.Domains, adminOrgDomainOut(d))
			}
			return err
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.AdminListOrgDomains401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.AdminListOrgDomains403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.AdminListOrgDomains404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) AdminAddOrgDomain(ctx context.Context, req adminapi.AdminAddOrgDomainRequestObject) (adminapi.AdminAddOrgDomainResponseObject, error) {
	var out port.OrgDomain
	o, ok, err := failed(http.StatusBadRequest, "invalid_request"), false, error(nil)
	if req.Body != nil {
		var p adminPrincipal
		p, o, ok, err = s.manageOrgDomains(ctx)
		if ok {
			err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				org, err := s.adminDomainOrg(ctx, tx, req.Id)
				if err != nil {
					return err
				}
				out, err = s.a.orgs.AddDomain(ctx, tx, org, req.Body.Domain, p.Actor, requestID(ctx))
				return err
			})
			o, ok, err = outcomeOf(nil, err)
		}
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.AdminAddOrgDomain201JSONResponse(adminOrgDomainOut(out)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.AdminAddOrgDomain400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.AdminAddOrgDomain401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.AdminAddOrgDomain403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.AdminAddOrgDomain404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.AdminAddOrgDomain409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) AdminVerifyOrgDomain(ctx context.Context, req adminapi.AdminVerifyOrgDomainRequestObject) (adminapi.AdminVerifyOrgDomainResponseObject, error) {
	var d port.OrgDomain
	p, o, ok, err := s.manageOrgDomains(ctx)
	if ok {
		var dnsDown bool
		d, dnsDown, err = s.a.verifyDomain(ctx, func(ctx context.Context, tx port.Tx) (port.Org, error) {
			return s.adminDomainOrg(ctx, tx, req.Id)
		}, req.DomainId, p.Actor)
		if dnsDown {
			o, ok, err = failed(http.StatusServiceUnavailable, "dns_unavailable"), false, nil
		} else {
			o, ok, err = outcomeOf(nil, err)
		}
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.AdminVerifyOrgDomain200JSONResponse(adminOrgDomainOut(d)), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.AdminVerifyOrgDomain401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.AdminVerifyOrgDomain403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.AdminVerifyOrgDomain404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.AdminVerifyOrgDomain409JSONResponse(o.body), nil
	case o.status == http.StatusServiceUnavailable:
		return adminapi.AdminVerifyOrgDomain503JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) AdminDeleteOrgDomain(ctx context.Context, req adminapi.AdminDeleteOrgDomainRequestObject) (adminapi.AdminDeleteOrgDomainResponseObject, error) {
	p, o, ok, err := s.manageOrgDomains(ctx)
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			org, err := s.adminDomainOrg(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			d, err := s.a.orgs.Domain(ctx, tx, org, req.DomainId)
			if err != nil {
				return err
			}
			return s.a.orgs.RemoveDomain(ctx, tx, org, d, p.Actor, requestID(ctx))
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.AdminDeleteOrgDomain204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.AdminDeleteOrgDomain401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.AdminDeleteOrgDomain403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.AdminDeleteOrgDomain404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
