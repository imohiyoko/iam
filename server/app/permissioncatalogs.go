package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/imohiyoko/iam/authz/permcatalog"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 連携先の権限のカタログの管理 API（ADR 0121）。

func permissionCatalogOut(c port.PermissionCatalog) adminapi.PermissionCatalog {
	out := adminapi.PermissionCatalog{Prefix: c.Prefix, DisplayName: c.DisplayName, Permissions: make([]adminapi.PermissionDef, 0, len(c.Permissions)),
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	for _, p := range c.Permissions {
		d := adminapi.PermissionDef{Name: p.Name}
		if p.Description != "" {
			d.Description = &p.Description
		}
		out.Permissions = append(out.Permissions, d)
	}
	return out
}

func permissionDefsIn(in []adminapi.PermissionDef) []port.PermissionDef {
	out := make([]port.PermissionDef, 0, len(in))
	for _, p := range in {
		d := port.PermissionDef{Name: p.Name}
		if p.Description != nil {
			d.Description = *p.Description
		}
		out = append(out, d)
	}
	return out
}

func permissionNames(c port.PermissionCatalog) []string {
	out := make([]string, 0, len(c.Permissions))
	for _, p := range c.Permissions {
		out = append(out, p.Name)
	}
	return out
}

// catalogRefs は、カタログ prefix の権限のうち next（nil なら消したあと）に無くなるものを使う独自のロール（realm 共通と、
// 削除していない Org のもの）の公開 ID を返す。
func catalogRefs(ctx context.Context, tx port.Tx, realmID, prefix string, next *port.PermissionCatalog) ([]string, error) {
	var out []string
	add := func(rs []port.Role) {
		for _, r := range rs {
			if len(permcatalog.Uses(r.Permissions, prefix, next)) > 0 {
				out = append(out, r.PublicID)
			}
		}
	}
	rs, err := tx.Roles().ListByOrg(ctx, realmID, "")
	if err != nil {
		return nil, err
	}
	add(rs)
	after := ""
	for {
		os, err := tx.Orgs().List(ctx, realmID, after, orgsPage)
		if err != nil {
			return nil, err
		}
		for _, o := range os {
			if o.DeletedAt != nil {
				continue
			}
			rs, err := tx.Roles().ListByOrg(ctx, realmID, o.ID)
			if err != nil {
				return nil, err
			}
			add(rs)
		}
		if len(os) < orgsPage {
			return out, nil
		}
		after = os[len(os)-1].ID
	}
}

func catalogInUse(refs []string) error {
	return errs.WithCode(errs.KindConflict, permcatalog.CodeCatalogInUse, fmt.Sprintf("permissions are used by roles %s", strings.Join(refs, ", ")))
}

// catalogOp は permission_catalogs:manage を確かめ、fn を1つのトランザクションで実行する。
func (s adminServer) catalogOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermPermissionCatalogsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	switch {
	case errors.Is(err, errs.Invalid) && errors.As(err, &e):
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, permcatalog.CodeInvalidCatalog), e.Msg)}, nil
	case errors.Is(err, errs.Conflict) && errors.As(err, &e) && e.Code == permcatalog.CodeCatalogInUse:
		return outcome{status: http.StatusConflict, body: adminError(e.Code, e.Msg)}, nil
	case errors.Is(err, errs.Conflict):
		return failed(http.StatusConflict, "catalog_exists"), nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	// カタログは独自のロールの確かめに効く（判定には効かない）ので、判定のキャッシュは捨てなくてよい。
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) recordCatalog(ctx context.Context, tx port.Tx, p adminPrincipal, typ string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor,
		RequestID: requestID(ctx), Details: details})
	return err
}

func (s adminServer) ListPermissionCatalogs(ctx context.Context, _ adminapi.ListPermissionCatalogsRequestObject) (adminapi.ListPermissionCatalogsResponseObject, error) {
	out := adminapi.PermissionCatalogs{Catalogs: []adminapi.PermissionCatalog{}}
	o, err := s.catalogOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		cs, err := tx.PermissionCatalogs().List(ctx, s.a.realm.ID)
		for _, c := range cs {
			out.Catalogs = append(out.Catalogs, permissionCatalogOut(c))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListPermissionCatalogs200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListPermissionCatalogs401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListPermissionCatalogs403JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreatePermissionCatalog(ctx context.Context, req adminapi.CreatePermissionCatalogRequestObject) (adminapi.CreatePermissionCatalogResponseObject, error) {
	var out adminapi.PermissionCatalog
	o, err := s.catalogOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, permcatalog.CodeInvalidCatalog, "body is required")
		}
		now := s.a.deps.Clock.Now()
		c, err := permcatalog.Normalize(port.PermissionCatalog{RealmID: s.a.realm.ID, Prefix: req.Body.Prefix, DisplayName: req.Body.DisplayName,
			Permissions: permissionDefsIn(req.Body.Permissions), CreatedAt: now, UpdatedAt: now})
		if err != nil {
			return err
		}
		if err := tx.PermissionCatalogs().Create(ctx, c); err != nil {
			return err
		}
		out = permissionCatalogOut(c)
		return s.recordCatalog(ctx, tx, p, "permission_catalog.created", map[string]any{"prefix": c.Prefix, "display_name": c.DisplayName,
			"permissions": permissionNames(c)})
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreatePermissionCatalog201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreatePermissionCatalog400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreatePermissionCatalog401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreatePermissionCatalog403JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreatePermissionCatalog409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetPermissionCatalog(ctx context.Context, req adminapi.GetPermissionCatalogRequestObject) (adminapi.GetPermissionCatalogResponseObject, error) {
	var out adminapi.PermissionCatalog
	o, err := s.catalogOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		c, err := tx.PermissionCatalogs().Get(ctx, s.a.realm.ID, req.Prefix)
		out = permissionCatalogOut(c)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetPermissionCatalog200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetPermissionCatalog401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetPermissionCatalog403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetPermissionCatalog404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdatePermissionCatalog(ctx context.Context, req adminapi.UpdatePermissionCatalogRequestObject) (adminapi.UpdatePermissionCatalogResponseObject, error) {
	var out adminapi.PermissionCatalog
	o, err := s.catalogOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, permcatalog.CodeInvalidCatalog, "body is required")
		}
		prev, err := tx.PermissionCatalogs().Get(ctx, s.a.realm.ID, req.Prefix)
		if err != nil {
			return err
		}
		c := prev
		c.DisplayName, c.Permissions, c.UpdatedAt = req.Body.DisplayName, permissionDefsIn(req.Body.Permissions), s.a.deps.Clock.Now()
		if c, err = permcatalog.Normalize(c); err != nil {
			return err
		}
		refs, err := catalogRefs(ctx, tx, s.a.realm.ID, c.Prefix, &c)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			return catalogInUse(refs)
		}
		if err := tx.PermissionCatalogs().Update(ctx, c); err != nil {
			return err
		}
		out = permissionCatalogOut(c)
		return s.recordCatalog(ctx, tx, p, "permission_catalog.updated", map[string]any{"prefix": c.Prefix, "display_name": c.DisplayName,
			"permissions": permissionNames(c), "previous_permissions": permissionNames(prev)})
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdatePermissionCatalog200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdatePermissionCatalog400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdatePermissionCatalog401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdatePermissionCatalog403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdatePermissionCatalog404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdatePermissionCatalog409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeletePermissionCatalog(ctx context.Context, req adminapi.DeletePermissionCatalogRequestObject) (adminapi.DeletePermissionCatalogResponseObject, error) {
	o, err := s.catalogOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		c, err := tx.PermissionCatalogs().Get(ctx, s.a.realm.ID, req.Prefix)
		if err != nil {
			return err
		}
		refs, err := catalogRefs(ctx, tx, s.a.realm.ID, c.Prefix, nil)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			return catalogInUse(refs)
		}
		if err := tx.PermissionCatalogs().Delete(ctx, s.a.realm.ID, c.Prefix); err != nil {
			return err
		}
		return s.recordCatalog(ctx, tx, p, "permission_catalog.deleted", map[string]any{"prefix": c.Prefix})
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeletePermissionCatalog204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeletePermissionCatalog401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeletePermissionCatalog403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeletePermissionCatalog404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.DeletePermissionCatalog409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
