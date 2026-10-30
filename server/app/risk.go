package app

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// リスク（ADR 0084）。realm のリスクの種類の一覧と、評価器によるセッションの点数の更新。

func riskTypeOut(name string, st risk.Setting, row *port.RiskType) adminapi.RiskType {
	out := adminapi.RiskType{Name: name, Enabled: st.Enabled, Builtin: st.Builtin, Band: adminapi.RiskBand{Medium: st.Band.Medium, High: st.Band.High}}
	if row != nil {
		out.UpdatedAt = &row.UpdatedAt
	}
	return out
}

// riskTypes は realm の一覧（名前の順）。
func riskTypes(ctx context.Context, tx port.Tx, realmID string) ([]adminapi.RiskType, error) {
	rows, err := tx.RiskTypes().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	byName := map[string]*port.RiskType{}
	for i := range rows {
		byName[rows[i].Name] = &rows[i]
	}
	cat := risk.CatalogOf(rows)
	out := make([]adminapi.RiskType, 0, len(cat))
	for _, n := range cat.Names() {
		out = append(out, riskTypeOut(n, cat[n], byName[n]))
	}
	return out, nil
}

// riskTypeRefs は種類 name を見る条件の数：条件付きの付与、名前空間の設定（名前）、Org の要件（削除していない Org）。
type riskTypeRefs struct {
	bindings   int
	namespaces []string
	orgs       int
}

func (r riskTypeRefs) empty() bool { return r.bindings == 0 && len(r.namespaces) == 0 && r.orgs == 0 }

func (r riskTypeRefs) String() string {
	var parts []string
	if r.bindings > 0 {
		parts = append(parts, fmt.Sprintf("%d role bindings", r.bindings))
	}
	if len(r.namespaces) > 0 {
		parts = append(parts, "action namespaces "+strings.Join(r.namespaces, ", "))
	}
	if r.orgs > 0 {
		parts = append(parts, fmt.Sprintf("requirements of %d orgs", r.orgs))
	}
	return "risk type is referenced by " + strings.Join(parts, "; ")
}

// orgsPage は Org の要件を探すときの1回に読む Org の数。
const orgsPage = 500

func findRiskTypeRefs(ctx context.Context, tx port.Tx, realmID, name string) (riskTypeRefs, error) {
	var out riskTypeRefs
	bs, err := tx.RoleBindings().ListConditional(ctx, realmID)
	if err != nil {
		return out, err
	}
	for _, b := range bs {
		// 読めない条件は判定で付与を効かせない（fail-closed）ので、止めても変わらない。
		if c, err := check.ParseCondition(b.Condition); err == nil && c != nil && slices.Contains(c.RiskTypes(), name) {
			out.bindings++
		}
	}
	nss, err := tx.ActionNamespaces().List(ctx, realmID)
	if err != nil {
		return out, err
	}
	for _, row := range nss {
		ns, err := check.ParseNamespace(row.Settings)
		if err != nil {
			return out, err
		}
		if slices.Contains(ns.RiskTypes(), name) {
			out.namespaces = append(out.namespaces, row.Name)
		}
	}
	after := ""
	for {
		os, err := tx.Orgs().List(ctx, realmID, after, orgsPage)
		if err != nil {
			return out, err
		}
		for _, o := range os {
			if o.DeletedAt != nil {
				continue
			}
			rs, err := check.OrgRequirements(o.Settings)
			if err != nil {
				return out, err
			}
			if slices.Contains(rs.RiskTypes(), name) {
				out.orgs++
			}
		}
		if len(os) < orgsPage {
			return out, nil
		}
		after = os[len(os)-1].ID
	}
}

func (s adminServer) ListRiskTypes(ctx context.Context, _ adminapi.ListRiskTypesRequestObject) (adminapi.ListRiskTypesResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermRiskTypesManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListRiskTypes401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.ListRiskTypes403JSONResponse(d.Body), nil
	}
	var out []adminapi.RiskType
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		out, err = riskTypes(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return adminapi.ListRiskTypes200JSONResponse{RiskTypes: out}, nil
}

func (s adminServer) PutRiskType(ctx context.Context, req adminapi.PutRiskTypeRequestObject) (adminapi.PutRiskTypeResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermRiskTypesManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.PutRiskType401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.PutRiskType403JSONResponse(d.Body), nil
	}
	bad := func(code, msg string) adminapi.PutRiskTypeResponseObject {
		return adminapi.PutRiskType400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(code, msg))}
	}
	if req.Body == nil {
		return bad("invalid_request", ""), nil
	}
	if !risk.ValidName(req.Name) {
		return bad("invalid_risk_type", "name must be ip, device, account or <namespace>.<name> ([a-z0-9_]{1,32} each)"), nil
	}
	var band *risk.Band
	if b := req.Body.Band; b != nil {
		band = &risk.Band{Medium: b.Medium, High: b.High}
		if !band.Valid() {
			return bad("invalid_band", "band must satisfy 1 <= medium < high <= 100"), nil
		}
	}
	now := s.a.deps.Clock.Now()
	var out adminapi.RiskType
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		rows, err := tx.RiskTypes().List(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		prev, had := risk.CatalogOf(rows)[req.Name]
		next := risk.Setting{Enabled: req.Body.Enabled, Band: risk.DefaultBand, Builtin: prev.Builtin}
		if had {
			next.Band = prev.Band
		}
		if band != nil {
			next.Band = *band
		}
		var saved *port.RiskType
		for i := range rows {
			if rows[i].Name == req.Name {
				saved = &rows[i]
			}
		}
		// 見ている条件が残っていれば止められない（ずっと満たさない条件を残さない）。
		if prev.Enabled && !next.Enabled {
			refs, err := findRiskTypeRefs(ctx, tx, s.a.realm.ID, req.Name)
			if err != nil {
				return err
			}
			if !refs.empty() {
				return errs.WithCode(errs.KindConflict, "risk_type_in_use", refs.String())
			}
		}
		if !had || prev != next {
			row := port.RiskType{RealmID: s.a.realm.ID, Name: req.Name, Enabled: next.Enabled, BandMedium: next.Band.Medium, BandHigh: next.Band.High,
				CreatedAt: now, UpdatedAt: now}
			if err := tx.RiskTypes().Put(ctx, row); err != nil {
				return err
			}
			saved = &row
			details := map[string]any{"name": req.Name, "enabled": next.Enabled, "band": next.Band}
			if had {
				details["previous"] = map[string]any{"enabled": prev.Enabled, "band": prev.Band}
			}
			if _, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
				Type: "realm.risk_types_changed", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
				Details: details,
			}); err != nil {
				return err
			}
		}
		out = riskTypeOut(req.Name, next, saved)
		return nil
	})
	if code, ok := stateCode(err); ok {
		return adminapi.PutRiskType409JSONResponse(adminError(code, errMessage(err))), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.PutRiskType200JSONResponse(out), nil
}

// riskWriter は評価器（risk:write を持つサービスアカウントの API キー）かを確かめる。人の運営者やアクセストークンは
// risk:write を持っても拒む。
func (s adminServer) riskWriter(ctx context.Context) (adminPrincipal, outcome, bool, error) {
	p, d, err := s.a.authorize(ctx, role.PermRiskWrite)
	if o, ok, err := outcomeOf(d, err); !ok {
		return p, o, false, err
	}
	if p.Type != port.PrincipalServiceAccount || p.AccessToken {
		return p, failed(http.StatusForbidden, errs.CodePermissionDenied), false, nil
	}
	return p, outcome{}, true, nil
}

// setRisk は評価器による点数の更新を1つのトランザクションで行い、更新したセッションのキャッシュを捨てる。
func (s adminServer) setRisk(ctx context.Context, body *adminapi.RiskUpdate, fn func(ctx context.Context, tx port.Tx, p adminPrincipal, c session.RiskChanges) ([]string, error)) (int, outcome, error) {
	if body == nil {
		return 0, failed(http.StatusBadRequest, "invalid_request"), nil
	}
	p, o, ok, err := s.riskWriter(ctx)
	if !ok {
		return 0, o, err
	}
	var ids []string
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ids, err = fn(ctx, tx, p, session.RiskChanges(body.Risk))
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return 0, o, err
	}
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, ids)
	return len(ids), outcome{status: http.StatusOK}, nil
}

func (s adminServer) SetSessionRisk(ctx context.Context, req adminapi.SetSessionRiskRequestObject) (adminapi.SetSessionRiskResponseObject, error) {
	n, o, err := s.setRisk(ctx, req.Body, func(ctx context.Context, tx port.Tx, p adminPrincipal, c session.RiskChanges) ([]string, error) {
		ses, err := tx.Sessions().Get(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return nil, err
		}
		// 評価器は自分のセッションを更新できない。
		if ses.PrincipalType == p.Type && ses.PrincipalID == p.ID {
			return nil, errs.New(errs.KindPermissionDenied, "cannot update own session")
		}
		return s.a.sessions.SetRisk(ctx, tx, s.a.realm.ID, req.Id, c, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SetSessionRisk200JSONResponse{Sessions: n}, nil
	case o.status == http.StatusBadRequest:
		return adminapi.SetSessionRisk400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SetSessionRisk401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SetSessionRisk403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SetSessionRisk404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) SetUserRisk(ctx context.Context, req adminapi.SetUserRiskRequestObject) (adminapi.SetUserRiskResponseObject, error) {
	n, o, err := s.setRisk(ctx, req.Body, func(ctx context.Context, tx port.Tx, p adminPrincipal, c session.RiskChanges) ([]string, error) {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return nil, err
		}
		return s.a.sessions.SetUserRisk(ctx, tx, s.a.realm.ID, u.ID, c, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SetUserRisk200JSONResponse{Sessions: n}, nil
	case o.status == http.StatusBadRequest:
		return adminapi.SetUserRisk400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SetUserRisk401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SetUserRisk403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SetUserRisk404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
