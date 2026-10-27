package app

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 連携先（OIDC のクライアント）と署名鍵の管理 API（design.md 5.5、9.3、ADR 0026）。

func clientOut(c port.Client, secret string) (adminapi.Client, error) {
	out := adminapi.Client{ClientId: c.PublicID, Name: c.Name, TrustLevel: adminapi.ClientTrustLevel(c.TrustLevel),
		RedirectUris: c.RedirectURIs, PostLogoutRedirectUris: c.PostLogoutRedirectURIs, TokenEndpointAuthMethod: c.AuthMethod,
		IdTokenSignedResponseAlg: c.IDTokenAlg, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	if out.RedirectUris == nil {
		out.RedirectUris = []string{}
	}
	if out.PostLogoutRedirectUris == nil {
		out.PostLogoutRedirectUris = []string{}
	}
	if c.BackchannelLogoutURI != "" {
		out.BackchannelLogoutUri = &c.BackchannelLogoutURI
	}
	if len(c.JWKS) > 0 {
		var m map[string]any
		if err := json.Unmarshal(c.JWKS, &m); err != nil {
			return adminapi.Client{}, err
		}
		out.Jwks = &m
	}
	if secret != "" {
		out.ClientSecret = &secret
	}
	return out, nil
}

func clientIn(b adminapi.ClientInput) (provider.ClientInput, error) {
	in := provider.ClientInput{Name: b.Name, RedirectURIs: b.RedirectUris, AuthMethod: string(b.TokenEndpointAuthMethod)}
	if b.PostLogoutRedirectUris != nil {
		in.PostLogoutRedirectURIs = *b.PostLogoutRedirectUris
	}
	if b.IdTokenSignedResponseAlg != nil {
		in.IDTokenAlg = string(*b.IdTokenSignedResponseAlg)
	}
	if b.BackchannelLogoutUri != nil {
		in.BackchannelLogoutURI = *b.BackchannelLogoutUri
	}
	if b.Jwks != nil {
		raw, err := json.Marshal(*b.Jwks)
		if err != nil {
			return provider.ClientInput{}, err
		}
		in.JWKS = raw
	}
	return in, nil
}

// clientOp は clients:manage を確かめ、fn を1つのトランザクションで実行する。成功なら status は 200。
func (s adminServer) clientOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermClientsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListClients(ctx context.Context, _ adminapi.ListClientsRequestObject) (adminapi.ListClientsResponseObject, error) {
	out := adminapi.Clients{Clients: []adminapi.Client{}}
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		cs, err := tx.Clients().List(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, c := range cs {
			v, err := clientOut(c, "")
			if err != nil {
				return err
			}
			out.Clients = append(out.Clients, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListClients200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListClients401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListClients403JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateClient(ctx context.Context, req adminapi.CreateClientRequestObject) (adminapi.CreateClientResponseObject, error) {
	var out adminapi.Client
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return provider.ErrInvalidClient
		}
		in, err := clientIn(*req.Body)
		if err != nil {
			return provider.ErrInvalidClient
		}
		c, secret, err := s.a.clients.Create(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = clientOut(c, secret)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateClient201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateClient400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateClient401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateClient403JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetClient(ctx context.Context, req adminapi.GetClientRequestObject) (adminapi.GetClientResponseObject, error) {
	var out adminapi.Client
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		out, err = clientOut(c, "")
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetClient200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetClient401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetClient403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetClient404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateClient(ctx context.Context, req adminapi.UpdateClientRequestObject) (adminapi.UpdateClientResponseObject, error) {
	var out adminapi.Client
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return provider.ErrInvalidClient
		}
		in, err := clientIn(*req.Body)
		if err != nil {
			return provider.ErrInvalidClient
		}
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		c, secret, err := s.a.clients.Update(ctx, tx, c, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = clientOut(c, secret)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateClient200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateClient400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateClient401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateClient403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateClient404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RotateClientSecret(ctx context.Context, req adminapi.RotateClientSecretRequestObject) (adminapi.RotateClientSecretResponseObject, error) {
	var secret string
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		secret, err = s.a.clients.RotateSecret(ctx, tx, c, p.Actor, requestID(ctx))
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.RotateClientSecret200JSONResponse{ClientSecret: secret}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.RotateClientSecret401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.RotateClientSecret403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.RotateClientSecret404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.RotateClientSecret409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteClient(ctx context.Context, req adminapi.DeleteClientRequestObject) (adminapi.DeleteClientResponseObject, error) {
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.clients.Delete(ctx, tx, c, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteClient204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteClient401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteClient403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteClient404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RotateSigningKey(ctx context.Context, req adminapi.RotateSigningKeyRequestObject) (adminapi.RotateSigningKeyResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermSigningKeysRotate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.RotateSigningKey401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.RotateSigningKey403JSONResponse(d.Body), nil
	case req.Body == nil || (req.Body.Alg != adminapi.RotateSigningKeyJSONBodyAlgES256 && req.Body.Alg != adminapi.RotateSigningKeyJSONBodyAlgMLDSA65):
		return adminapi.RotateSigningKey400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var k port.SigningKey
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if k, err = s.a.keys.Rotate(ctx, tx, s.a.realm.ID, string(req.Body.Alg)); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "signing_key.rotated", Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
			Actor: p.Actor, RequestID: requestID(ctx), Details: map[string]any{"kid": k.ID, "alg": k.Alg}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return adminapi.RotateSigningKey200JSONResponse{Kid: k.ID, Alg: k.Alg}, nil
}
