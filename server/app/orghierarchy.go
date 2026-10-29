package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 階層（design.md 11.4、ADR 0078）。運営者が管理 API で親を設定する。

// hierarchyOff はフィーチャー org_hierarchy が動いていなければ 404 hierarchy_disabled を返す。
func (s adminServer) hierarchyOff() (outcome, bool) {
	if s.a.orgs == nil || !s.a.orgs.Hierarchy {
		return failed(http.StatusNotFound, "hierarchy_disabled"), true
	}
	return outcome{}, false
}

func (s adminServer) SetOrgParent(ctx context.Context, req adminapi.SetOrgParentRequestObject) (adminapi.SetOrgParentResponseObject, error) {
	var out adminapi.Org
	o, err := func() (outcome, error) {
		if req.Body == nil {
			return failed(http.StatusBadRequest, "invalid_request"), nil
		}
		p, d, err := s.a.authorize(ctx, role.PermOrgsUpdate)
		if o, ok, err := outcomeOf(d, err); !ok {
			return o, err
		}
		if o, off := s.hierarchyOff(); off {
			return o, nil
		}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			cur, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			var parent *port.Org
			if req.Body.ParentId != nil && *req.Body.ParentId != "" {
				po, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *req.Body.ParentId)
				if errors.Is(err, errs.NotFound) {
					return errs.WithCode(errs.KindInvalid, "parent_not_found", "parent org not found")
				}
				if err != nil {
					return err
				}
				parent = &po
			}
			if cur, err = s.a.orgs.SetParent(ctx, tx, cur, parent, p.Actor, requestID(ctx)); err != nil {
				return err
			}
			out, err = s.orgOut(ctx, tx, cur)
			return err
		})
		if o, ok, err := outcomeOf(nil, err); !ok {
			return o, err
		}
		// 判定の材料（祖先から効く付与）が変わる。
		s.a.authz.Invalidate(s.a.realm.ID)
		return outcome{status: http.StatusOK}, nil
	}()
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SetOrgParent200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SetOrgParent400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SetOrgParent401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SetOrgParent403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SetOrgParent404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.SetOrgParent409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListOrgChildren(ctx context.Context, req adminapi.ListOrgChildrenRequestObject) (adminapi.ListOrgChildrenResponseObject, error) {
	out := adminapi.ListOrgChildren200JSONResponse{Orgs: []adminapi.Org{}}
	o, err := func() (outcome, error) {
		_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
		if o, ok, err := outcomeOf(d, err); !ok {
			return o, err
		}
		if o, off := s.hierarchyOff(); off {
			return o, nil
		}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			cur, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			cs, err := tx.Orgs().ListChildren(ctx, s.a.realm.ID, cur.ID)
			if err != nil {
				return err
			}
			for _, c := range cs {
				v := orgView(c, "")
				v.ParentId = &cur.PublicID
				out.Orgs = append(out.Orgs, v)
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
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListOrgChildren401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListOrgChildren403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListOrgChildren404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
