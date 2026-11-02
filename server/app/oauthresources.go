package app

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 自前の API（リソースサーバー）の管理 API（RFC 8707、フィーチャー resource_indicators。ADR 0112）。

func oauthResourceOut(x port.OAuthResource) adminapi.OAuthResource {
	return adminapi.OAuthResource{Id: x.ID, Uri: x.URI, Name: x.Name, Scopes: nonNilStrings(x.Scopes), Clients: nonNilStrings(x.Clients),
		ServiceAccounts: nonNilStrings(x.ServiceAccounts), CreatedAt: x.CreatedAt, UpdatedAt: x.UpdatedAt}
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

func oauthResourceIn(b *adminapi.OAuthResourceInput) provider.ResourceInput {
	in := provider.ResourceInput{URI: b.Uri, Name: b.Name, Scopes: b.Scopes}
	if b.Clients != nil {
		in.Clients = *b.Clients
	}
	if b.ServiceAccounts != nil {
		in.ServiceAccounts = *b.ServiceAccounts
	}
	return in
}

// resourceOp は clients:manage を確かめ、fn を1つのトランザクションで実行する。フィーチャーが動いていなければ
// 404 resource_indicators_disabled。
func (s adminServer) resourceOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermClientsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.resources == nil {
		return failed(http.StatusNotFound, "resource_indicators_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_resource"), e.Msg)}, nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListOAuthResources(ctx context.Context, _ adminapi.ListOAuthResourcesRequestObject) (adminapi.ListOAuthResourcesResponseObject, error) {
	out := adminapi.OAuthResources{Resources: []adminapi.OAuthResource{}}
	o, err := s.resourceOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		xs, err := tx.OAuthResources().List(ctx, s.a.realm.ID)
		for _, x := range xs {
			out.Resources = append(out.Resources, oauthResourceOut(x))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListOAuthResources200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListOAuthResources401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListOAuthResources403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListOAuthResources404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateOAuthResource(ctx context.Context, req adminapi.CreateOAuthResourceRequestObject) (adminapi.CreateOAuthResourceResponseObject, error) {
	var out adminapi.OAuthResource
	o, err := s.resourceOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_resource", "body is required")
		}
		x, err := s.a.resources.Create(ctx, tx, s.a.realm.ID, oauthResourceIn(req.Body), p.Actor, requestID(ctx))
		out = oauthResourceOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateOAuthResource201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateOAuthResource400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateOAuthResource401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateOAuthResource403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateOAuthResource404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateOAuthResource409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetOAuthResource(ctx context.Context, req adminapi.GetOAuthResourceRequestObject) (adminapi.GetOAuthResourceResponseObject, error) {
	var out adminapi.OAuthResource
	o, err := s.resourceOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		x, err := tx.OAuthResources().Get(ctx, s.a.realm.ID, req.Id)
		out = oauthResourceOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetOAuthResource200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetOAuthResource401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetOAuthResource403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetOAuthResource404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateOAuthResource(ctx context.Context, req adminapi.UpdateOAuthResourceRequestObject) (adminapi.UpdateOAuthResourceResponseObject, error) {
	var out adminapi.OAuthResource
	o, err := s.resourceOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_resource", "body is required")
		}
		x, err := tx.OAuthResources().Get(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		x, err = s.a.resources.Update(ctx, tx, x, oauthResourceIn(req.Body), p.Actor, requestID(ctx))
		out = oauthResourceOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateOAuthResource200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateOAuthResource400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateOAuthResource401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateOAuthResource403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateOAuthResource404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateOAuthResource409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteOAuthResource(ctx context.Context, req adminapi.DeleteOAuthResourceRequestObject) (adminapi.DeleteOAuthResourceResponseObject, error) {
	o, err := s.resourceOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		x, err := tx.OAuthResources().Get(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.resources.Delete(ctx, tx, x, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteOAuthResource204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteOAuthResource401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteOAuthResource403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteOAuthResource404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
