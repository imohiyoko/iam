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

// Quota（design.md 11.14、ADR 0070）。

func publicShortage(err error) *publicapi.QuotaShortage {
	qe, ok := errors.AsType[*org.QuotaError](err)
	if !ok {
		return nil
	}
	return &publicapi.QuotaShortage{From: qe.From, Until: qe.Until, Limit: qe.Limit, Count: qe.Count, Shortage: qe.Shortage()}
}

func adminShortage(err error) *adminapi.QuotaShortage {
	p := publicShortage(err)
	if p == nil {
		return nil
	}
	return &adminapi.QuotaShortage{From: p.From, Until: p.Until, Limit: p.Limit, Count: p.Count, Shortage: p.Shortage}
}

// conflictOf は 409 の本文（Quota の不足なら quota を付ける）。
func conflictOf(err error, code string) publicapi.ConflictJSONResponse {
	return publicapi.ConflictJSONResponse{Error: code, Quota: publicShortage(err)}
}

func quotaGrantOut(g port.QuotaGrant) adminapi.QuotaGrant {
	out := adminapi.QuotaGrant{Id: g.PublicID, QuotaKey: adminapi.QuotaGrantQuotaKey(g.QuotaKey), Kind: adminapi.QuotaGrantKind(g.Kind),
		Quantity: g.Quantity, StartsAt: g.StartsAt, EndsAt: g.EndsAt, Source: adminapi.QuotaGrantSource(g.Source), CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt}
	if g.ExternalRef != "" {
		out.ExternalRef = &g.ExternalRef
	}
	return out
}

func quotaGrantIn(b *adminapi.QuotaGrantInput) org.QuotaGrantInput {
	in := org.QuotaGrantInput{Kind: port.QuotaGrantKind(b.Kind), Quantity: b.Quantity, StartsAt: b.StartsAt, EndsAt: b.EndsAt}
	if b.ExternalRef != nil {
		in.ExternalRef = *b.ExternalRef
	}
	return in
}

// quotaOff はフィーチャー org か quota が動いていなければ 404 を返す。
func (s adminServer) quotaOff() (outcome, bool) {
	if o, off := s.orgsOff(true); off {
		return o, true
	}
	if !s.a.orgs.Quotas {
		return failed(http.StatusNotFound, "quota_disabled"), true
	}
	return outcome{}, false
}

func (s adminServer) GetOrgQuota(ctx context.Context, req adminapi.GetOrgQuotaRequestObject) (adminapi.GetOrgQuotaResponseObject, error) {
	var out adminapi.OrgQuota
	o, err := func() (outcome, error) {
		_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
		if o, ok, err := outcomeOf(d, err); !ok {
			return o, err
		}
		if o, off := s.quotaOff(); off {
			return o, nil
		}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			og, _, err := s.adminOrg(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			v, err := s.a.orgs.Quota(ctx, tx, og)
			if err != nil {
				return err
			}
			out = adminapi.OrgQuota{QuotaKey: org.QuotaMembers, Limit: v.Limit, Count: v.Count, Grants: []adminapi.QuotaGrant{}}
			for _, g := range v.Grants {
				out.Grants = append(out.Grants, quotaGrantOut(g))
			}
			return nil
		})
		if o, ok, err := outcomeOf(nil, err); !ok {
			return o, err
		}
		return outcome{status: http.StatusOK}, nil
	}()
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetOrgQuota200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetOrgQuota401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetOrgQuota403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetOrgQuota404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.GetOrgQuota409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// quotaGrant は付与の変更の共通の手順（権限・フィーチャー・Org と付与の解決）。fn の結果を応答にする。
func (s adminServer) quotaGrant(ctx context.Context, orgID, grantID string, fn func(ctx context.Context, tx port.Tx, o port.Org, g port.QuotaGrant, p adminPrincipal) (int, error)) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermOrgsUpdate)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.quotaOff(); off {
		return o, nil
	}
	status := 0
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		og, _, err := s.adminOrg(ctx, tx, orgID)
		if err != nil {
			return err
		}
		var g port.QuotaGrant
		if grantID != "" {
			if g, err = tx.QuotaGrants().GetByPublicID(ctx, s.a.realm.ID, grantID); err == nil && g.OrgID != og.ID {
				err = errs.New(errs.KindNotFound, "quota grant")
			}
			if err != nil {
				return err
			}
		}
		status, err = fn(ctx, tx, og, g, p)
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: status}, nil
}

func (s adminServer) CreateOrgQuotaGrant(ctx context.Context, req adminapi.CreateOrgQuotaGrantRequestObject) (adminapi.CreateOrgQuotaGrantResponseObject, error) {
	var out adminapi.QuotaGrant
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if req.Body != nil {
		o, err = s.quotaGrant(ctx, req.Id, "", func(ctx context.Context, tx port.Tx, og port.Org, _ port.QuotaGrant, p adminPrincipal) (int, error) {
			g, created, err := s.a.orgs.PutQuotaGrant(ctx, tx, og, quotaGrantIn(req.Body), p.Actor, requestID(ctx))
			out = quotaGrantOut(g)
			if created {
				return http.StatusCreated, err
			}
			return http.StatusOK, err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateOrgQuotaGrant200JSONResponse(out), nil
	case o.status == http.StatusCreated:
		return adminapi.CreateOrgQuotaGrant201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateOrgQuotaGrant400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateOrgQuotaGrant401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateOrgQuotaGrant403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateOrgQuotaGrant404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateOrgQuotaGrant409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateOrgQuotaGrant(ctx context.Context, req adminapi.UpdateOrgQuotaGrantRequestObject) (adminapi.UpdateOrgQuotaGrantResponseObject, error) {
	var out adminapi.QuotaGrant
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if req.Body != nil {
		o, err = s.quotaGrant(ctx, req.Id, req.GrantId, func(ctx context.Context, tx port.Tx, og port.Org, g port.QuotaGrant, p adminPrincipal) (int, error) {
			g, err := s.a.orgs.UpdateQuotaGrant(ctx, tx, og, g, quotaGrantIn(req.Body), p.Actor, requestID(ctx))
			out = quotaGrantOut(g)
			return http.StatusOK, err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateOrgQuotaGrant200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateOrgQuotaGrant400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateOrgQuotaGrant401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateOrgQuotaGrant403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateOrgQuotaGrant404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateOrgQuotaGrant409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteOrgQuotaGrant(ctx context.Context, req adminapi.DeleteOrgQuotaGrantRequestObject) (adminapi.DeleteOrgQuotaGrantResponseObject, error) {
	o, err := s.quotaGrant(ctx, req.Id, req.GrantId, func(ctx context.Context, tx port.Tx, og port.Org, g port.QuotaGrant, p adminPrincipal) (int, error) {
		return http.StatusNoContent, s.a.orgs.DeleteQuotaGrant(ctx, tx, og, g, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusNoContent:
		return adminapi.DeleteOrgQuotaGrant204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteOrgQuotaGrant401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteOrgQuotaGrant403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteOrgQuotaGrant404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.DeleteOrgQuotaGrant409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
