package app

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// 操作の名前空間ごとの設定（要件と段階の境界。ADR 0084）。

// requirementsOut は要件を API の形にする。
func requirementsOut(rs check.Requirements) map[string]map[string]any {
	out := make(map[string]map[string]any, len(rs))
	for _, k := range slices.Sorted(maps.Keys(rs)) {
		b, _ := json.Marshal(rs[k])
		if c := conditionOut(b); c != nil {
			out[k] = *c
		}
	}
	return out
}

// requirementsIn は API の要件を読む。外れていれば errs.KindInvalid（コード invalid_condition）。
func requirementsIn(in *map[string]map[string]any) (check.Requirements, error) {
	if in == nil {
		return nil, nil
	}
	out := make(check.Requirements, len(*in))
	for k, v := range *in {
		c, err := conditionIn(&v)
		if err != nil {
			return nil, err
		}
		out[k] = *c
	}
	return out, nil
}

func namespaceOut(name string, ns check.Namespace, row *port.ActionNamespace) adminapi.ActionNamespace {
	out := adminapi.ActionNamespace{Name: name, Requirements: requirementsOut(ns.Requirements), Bands: map[string]adminapi.RiskBand{}}
	for t, b := range ns.Bands {
		out.Bands[t] = adminapi.RiskBand{Medium: b.Medium, High: b.High}
	}
	if row != nil {
		out.UpdatedAt = &row.UpdatedAt
	}
	return out
}

// namespaceAt は保存した名前空間の設定を読む。無ければ空の設定と nil。
func namespaceAt(ctx context.Context, tx port.Tx, realmID, name string) (check.Namespace, *port.ActionNamespace, error) {
	row, err := tx.ActionNamespaces().Get(ctx, realmID, name)
	if errors.Is(err, errs.NotFound) {
		return check.Namespace{}, nil, nil
	}
	if err != nil {
		return check.Namespace{}, nil, err
	}
	ns, err := check.ParseNamespace(row.Settings)
	return ns, &row, err
}

// authorizeNamespace は名前空間 name の設定を変える権限（requirements:manage。その名前空間に限った付与も効く）を確かめる。
func (s adminServer) authorizeNamespace(ctx context.Context, name string) (adminPrincipal, outcome, bool, error) {
	p, d, err := s.a.authorizeOn(ctx, role.PermRequirementsManage, check.Resource{Type: check.ResourceActionNamespace, ID: name}, false)
	if o, ok, err := outcomeOf(d, err); !ok {
		return p, o, false, err
	}
	if !check.ValidNamespace(name) {
		return p, failed(http.StatusBadRequest, "invalid_namespace"), false, nil
	}
	return p, outcome{}, true, nil
}

func (s adminServer) GetActionNamespace(ctx context.Context, req adminapi.GetActionNamespaceRequestObject) (adminapi.GetActionNamespaceResponseObject, error) {
	_, o, ok, err := s.authorizeNamespace(ctx, req.Name)
	var out adminapi.ActionNamespace
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ns, row, err := namespaceAt(ctx, tx, s.a.realm.ID, req.Name)
			out = namespaceOut(req.Name, ns, row)
			return err
		})
		o = outcome{status: http.StatusOK}
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetActionNamespace200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.GetActionNamespace400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetActionNamespace401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.GetActionNamespace403JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// errRequirementLockout は、変えた後の設定で呼び出し側が名前空間の設定を変えられなくなる（自分を締め出す）ときのエラー。
var errRequirementLockout = errs.WithCode(errs.KindConflict, "requirement_lockout", "the new settings would deny requirements:manage to the caller")

func (s adminServer) PutActionNamespace(ctx context.Context, req adminapi.PutActionNamespaceRequestObject) (adminapi.PutActionNamespaceResponseObject, error) {
	p, o, ok, err := s.authorizeNamespace(ctx, req.Name)
	var out adminapi.ActionNamespace
	if ok && req.Body == nil {
		ok, o = false, failed(http.StatusBadRequest, "invalid_request")
	}
	if ok {
		o, err = s.putNamespace(ctx, p, req.Name, *req.Body, &out)
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.PutActionNamespace200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.PutActionNamespace400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.PutActionNamespace401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.PutActionNamespace403JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.PutActionNamespace409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) putNamespace(ctx context.Context, p adminPrincipal, name string, in adminapi.ActionNamespaceInput, out *adminapi.ActionNamespace) (outcome, error) {
	rs, err := requirementsIn(in.Requirements)
	if err != nil {
		o, _, err := outcomeOf(nil, err)
		return o, err
	}
	next := check.Namespace{Requirements: rs}
	if in.Bands != nil {
		next.Bands = make(map[string]risk.Band, len(*in.Bands))
		for t, b := range *in.Bands {
			next.Bands[t] = risk.Band{Medium: b.Medium, High: b.High}
		}
	}
	now := s.a.deps.Clock.Now()
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		rows, err := tx.RiskTypes().List(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		if err := next.Validate(name, risk.CatalogOf(rows)); err != nil {
			return err
		}
		prev, row, err := namespaceAt(ctx, tx, s.a.realm.ID, name)
		if err != nil {
			return err
		}
		before, err := json.Marshal(prev)
		if err != nil {
			return err
		}
		after, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if row == nil || string(before) != string(after) {
			saved := port.ActionNamespace{RealmID: s.a.realm.ID, Name: name, Settings: after, CreatedAt: now, UpdatedAt: now}
			if err := tx.ActionNamespaces().Put(ctx, saved); err != nil {
				return err
			}
			row = &saved
			// 変えた後の設定で、呼び出し側がこの名前空間の設定を変え続けられるか（要件で自分を締め出さない）。
			d, err := s.a.authz.DecideTx(ctx, tx, s.a.realm.ID, check.Request{Principal: check.Principal{Type: p.Type, ID: p.ID},
				Action: role.PermRequirementsManage, Resource: check.Resource{Type: check.ResourceActionNamespace, ID: name}, Context: p.Context})
			if err != nil {
				return err
			}
			if !d.Allow {
				return errRequirementLockout
			}
			details := map[string]any{"namespace": name, "settings": json.RawMessage(after)}
			if len(before) > 0 && string(before) != "{}" {
				details["previous"] = json.RawMessage(before)
			}
			if _, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
				Type: "authz.requirement_updated", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
				Details: details,
			}); err != nil {
				return err
			}
		}
		*out = namespaceOut(name, next, row)
		return nil
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	s.a.authz.Invalidate(s.a.realm.ID)
	return outcome{status: http.StatusOK}, nil
}
