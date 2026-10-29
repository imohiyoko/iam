package app

import (
	"context"
	"errors"
	"strings"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 専用 SSO（design.md 11.3、ADR 0077）。Org の owner（org:settings）が connection を扱う。フィーチャー org_managed_users。

func orgConnectionOut(c port.Connection) (publicapi.OrgConnection, error) {
	in, err := oauth.Info(c)
	return publicapi.OrgConnection{Id: c.ID, Issuer: in.Issuer, AuthorizationEndpoint: in.AuthURL, TokenEndpoint: in.TokenURL,
		ClientId: in.ClientID, Scopes: in.Scopes, RedirectUri: in.RedirectURI, CreatedAt: c.CreatedAt}, err
}

func (s publicServer) ListOrgConnections(ctx context.Context, req publicapi.ListOrgConnectionsRequestObject) (publicapi.ListOrgConnectionsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListOrgConnections401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.ListOrgConnections404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := publicapi.ListOrgConnections200JSONResponse{Connections: []publicapi.OrgConnection{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		cs, err := s.a.orgs.Connections(ctx, tx, o)
		if err != nil {
			return err
		}
		for _, c := range cs {
			v, err := orgConnectionOut(c)
			if err != nil {
				return err
			}
			out.Connections = append(out.Connections, v)
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgConnections404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgConnections403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func (s publicServer) AddOrgConnection(ctx context.Context, req publicapi.AddOrgConnectionRequestObject) (publicapi.AddOrgConnectionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.AddOrgConnection401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.AddOrgConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.AddOrgConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	b := req.Body
	in := oauth.OrgConnection{Issuer: b.Issuer, AuthURL: b.AuthorizationEndpoint, TokenURL: b.TokenEndpoint, ClientID: b.ClientId,
		ClientSecret: b.ClientSecret}
	if b.Scopes != nil {
		in.Scopes = *b.Scopes
	}
	var out publicapi.OrgConnection
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		c, err := s.a.oauth.NewOrgConnection(ctx, s.a.realm.ID, o.ID, in)
		if err != nil {
			return err
		}
		if err := s.a.orgs.AddConnection(ctx, tx, o, c, oauth.MaxOrgConnections, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		out, err = orgConnectionOut(c)
		return err
	})
	if c, ok := stateCode(err); ok {
		return publicapi.AddOrgConnection409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.AddOrgConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.AddOrgConnection403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.AddOrgConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCodeOr(err, "invalid_connection")}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.AddOrgConnection201JSONResponse(out), nil
}

func (s publicServer) DeleteOrgConnection(ctx context.Context, req publicapi.DeleteOrgConnectionRequestObject) (publicapi.DeleteOrgConnectionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.DeleteOrgConnection401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() {
		return publicapi.DeleteOrgConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		c, err := s.a.orgs.Connection(ctx, tx, o, req.ConnectionId)
		if err != nil {
			return err
		}
		return s.a.orgs.RemoveConnection(ctx, tx, o, c, au.Actor(), requestID(ctx))
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.DeleteOrgConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.DeleteOrgConnection403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.DeleteOrgConnection204Response{}, nil
}

// DiscoverSSO はアドレスのドメインを証明済みの Org の connection を返す（ホームレルム発見）。
func (s publicServer) DiscoverSSO(ctx context.Context, req publicapi.DiscoverSSORequestObject) (publicapi.DiscoverSSOResponseObject, error) {
	if req.Body == nil {
		return publicapi.DiscoverSSO400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	addr, err := account.NormalizeEmail(req.Body.Email)
	if err != nil {
		return publicapi.DiscoverSSO400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_email"}}, nil
	}
	out := publicapi.DiscoverSSO200JSONResponse{Connections: []string{}}
	if !s.domainsOn() {
		return out, nil
	}
	_, domain, _ := strings.Cut(addr, "@")
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		d, err := tx.OrgDomains().GetVerified(ctx, s.a.realm.ID, domain)
		if errors.Is(err, errs.NotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		cs, err := tx.Connections().ListByOwner(ctx, s.a.realm.ID, d.OrgID)
		for _, c := range cs {
			out.Connections = append(out.Connections, c.Slug)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
