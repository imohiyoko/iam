package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// Org の段のセキュリティ設定（design.md 2.8、5.4、10章、ADR 0062）。

func seconds(d *time.Duration) *int64 {
	if d == nil {
		return nil
	}
	v := int64(d.Seconds())
	return &v
}

func duration(v *int64) *time.Duration {
	if v == nil {
		return nil
	}
	d := time.Duration(*v) * time.Second
	return &d
}

func actionsOut[T ~string](m map[string]warning.Action) map[string]T {
	out := make(map[string]T, len(m))
	for k, v := range m {
		out[k] = T(v)
	}
	return out
}

func actionsIn[T ~string](m *map[string]T) map[string]warning.Action {
	if m == nil || len(*m) == 0 {
		return nil
	}
	out := make(map[string]warning.Action, len(*m))
	for k, v := range *m {
		out[k] = warning.Action(v)
	}
	return out
}

func policyOut(p *org.LoginPolicy) *publicapi.OrgLoginPolicy {
	if p == nil {
		return nil
	}
	out := publicapi.OrgLoginPolicy{RequirePasskey: &p.RequirePasskey}
	if p.RequireSSO {
		out.RequireSso = &p.RequireSSO
	}
	if len(p.MembershipEmailDomains) > 0 {
		out.MembershipEmailDomains = &p.MembershipEmailDomains
	}
	if len(p.IPAllowlist) > 0 {
		out.IpAllowlist = &p.IPAllowlist
	}
	return &out
}

func policyIn(p *publicapi.OrgLoginPolicy) *org.LoginPolicy {
	if p == nil {
		return nil
	}
	var out org.LoginPolicy
	if p.RequirePasskey != nil {
		out.RequirePasskey = *p.RequirePasskey
	}
	if p.RequireSso != nil {
		out.RequireSSO = *p.RequireSso
	}
	if p.MembershipEmailDomains != nil {
		out.MembershipEmailDomains = *p.MembershipEmailDomains
	}
	if p.IpAllowlist != nil {
		out.IPAllowlist = *p.IpAllowlist
	}
	return &out
}

func settingsIn(abs, idle, auth *int64) (org.Settings, error) {
	for _, v := range []*int64{abs, idle, auth} {
		// 秒の上限は time.Duration のあふれを防ぐため（ホスト先の範囲の検査は CheckSettings）。
		if v != nil && (*v <= 0 || *v > int64(100*365*24*time.Hour/time.Second)) {
			return org.Settings{}, errs.WithCode(errs.KindInvalid, org.CodeSettingInvalid, "out of range")
		}
	}
	return org.Settings{AbsoluteLifetime: duration(abs), IdleTimeout: duration(idle), MaxAuthAge: duration(auth)}, nil
}

// orgRequirementsIn は Org の要件を realm のリスクの種類の一覧で確かめ、保存の形にする（ADR 0084）。
func orgRequirementsIn(ctx context.Context, tx port.Tx, realmID string, rs check.Requirements) (map[string]json.RawMessage, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	rows, err := tx.RiskTypes().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	if err := rs.Validate("", risk.CatalogOf(rows).Enabled); err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(rs))
	for k, c := range rs {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		out[k] = b
	}
	return out, nil
}

// orgRequirementsOut は保存した Org の要件を API の形にする。無ければ nil。
func orgRequirementsOut(rs map[string]json.RawMessage) *map[string]map[string]any {
	if len(rs) == 0 {
		return nil
	}
	out := make(map[string]map[string]any, len(rs))
	for k, raw := range rs {
		if c := conditionOut(raw); c != nil {
			out[k] = *c
		}
	}
	return &out
}

// settingsView は publicapi の形の設定（adminapi も同じ形なので変換して使う）。
func (a *App) settingsView(o port.Org) (publicapi.OrgSettingsView, error) {
	st, err := org.SettingsOf(o)
	if err != nil {
		return publicapi.OrgSettingsView{}, err
	}
	e, err := a.orgs.Effective(o)
	if err != nil {
		return publicapi.OrgSettingsView{}, err
	}
	var v publicapi.OrgSettingsView
	v.Settings = publicapi.OrgSettings{AbsoluteLifetimeSeconds: seconds(st.AbsoluteLifetime), IdleTimeoutSeconds: seconds(st.IdleTimeout),
		MaxAuthAgeSeconds: seconds(st.MaxAuthAge), LoginPolicy: policyOut(st.LoginPolicy), Requirements: orgRequirementsOut(st.Requirements)}
	if len(st.Warnings) > 0 {
		w := actionsOut[publicapi.OrgSettingsWarnings](st.Warnings)
		v.Settings.Warnings = &w
	}
	v.Effective.AbsoluteLifetimeSeconds = int64(e.AbsoluteLifetime.Seconds())
	v.Effective.IdleTimeoutSeconds = int64(e.IdleTimeout.Seconds())
	v.Effective.MaxAuthAgeSeconds = int64(e.MaxAuthAge.Seconds())
	v.Effective.Warnings = actionsOut[publicapi.OrgSettingsViewEffectiveWarnings](e.Warnings)
	return v, nil
}

func adminSettingsView(v publicapi.OrgSettingsView) adminapi.OrgSettingsView {
	var out adminapi.OrgSettingsView
	out.Settings = adminapi.OrgSettings{AbsoluteLifetimeSeconds: v.Settings.AbsoluteLifetimeSeconds, IdleTimeoutSeconds: v.Settings.IdleTimeoutSeconds,
		MaxAuthAgeSeconds: v.Settings.MaxAuthAgeSeconds, Requirements: v.Settings.Requirements}
	if p := v.Settings.LoginPolicy; p != nil {
		out.Settings.LoginPolicy = &adminapi.OrgLoginPolicy{RequirePasskey: p.RequirePasskey, MembershipEmailDomains: p.MembershipEmailDomains, IpAllowlist: p.IpAllowlist,
			RequireSso: p.RequireSso}
	}
	if v.Settings.Warnings != nil {
		w := make(map[string]adminapi.OrgSettingsWarnings, len(*v.Settings.Warnings))
		for k, a := range *v.Settings.Warnings {
			w[k] = adminapi.OrgSettingsWarnings(a)
		}
		out.Settings.Warnings = &w
	}
	out.Effective.AbsoluteLifetimeSeconds = v.Effective.AbsoluteLifetimeSeconds
	out.Effective.IdleTimeoutSeconds = v.Effective.IdleTimeoutSeconds
	out.Effective.MaxAuthAgeSeconds = v.Effective.MaxAuthAgeSeconds
	out.Effective.Warnings = make(map[string]adminapi.OrgSettingsViewEffectiveWarnings, len(v.Effective.Warnings))
	for k, a := range v.Effective.Warnings {
		out.Effective.Warnings[k] = adminapi.OrgSettingsViewEffectiveWarnings(a)
	}
	return out
}

func (s publicServer) GetMyOrgSettings(ctx context.Context, req publicapi.GetMyOrgSettingsRequestObject) (publicapi.GetMyOrgSettingsResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.GetMyOrgSettings401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.GetMyOrgSettings404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var out publicapi.OrgSettingsView
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		out, err = s.a.settingsView(o)
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.GetMyOrgSettings404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.GetMyOrgSettings403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.GetMyOrgSettings200JSONResponse(out), nil
}

func (s publicServer) PutMyOrgSettings(ctx context.Context, req publicapi.PutMyOrgSettingsRequestObject) (publicapi.PutMyOrgSettingsResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.PutMyOrgSettings401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.PutMyOrgSettings404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case req.Body == nil:
		return publicapi.PutMyOrgSettings400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	b := req.Body
	st, err := settingsIn(b.AbsoluteLifetimeSeconds, b.IdleTimeoutSeconds, b.MaxAuthAgeSeconds)
	if err != nil {
		return publicapi.PutMyOrgSettings400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	}
	st.Warnings = actionsIn(b.Warnings)
	st.LoginPolicy = policyIn(b.LoginPolicy)
	rs, err := requirementsIn(b.Requirements)
	if err != nil {
		return publicapi.PutMyOrgSettings400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	}
	var out publicapi.OrgSettingsView
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err != nil {
			return err
		}
		if st.Requirements, err = orgRequirementsIn(ctx, tx, s.a.realm.ID, rs); err != nil {
			return err
		}
		if o, err = s.a.orgs.UpdateSettings(ctx, tx, o, st, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		// 変えた後の要件で、自分がこの Org の設定を変え続けられるか（要件で自分を締め出さない）。
		if len(st.Requirements) > 0 {
			ok, err := s.a.authz.CheckTx(ctx, tx, s.a.realm.ID, check.Request{Principal: check.Principal{Type: port.PrincipalUser, ID: au.PrincipalID},
				Action: role.PermOrgSettings, OrgID: o.ID, Context: sessionContext(au.Validated)})
			if err != nil {
				return err
			}
			if !ok {
				return errRequirementLockout
			}
		}
		out, err = s.a.settingsView(o)
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.PutMyOrgSettings409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.PutMyOrgSettings404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.PutMyOrgSettings403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.PutMyOrgSettings400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	// 既存のセッションには検証のキャッシュの期限（validity_max_delay）の内に効く（5.4）。要件はこのインスタンスではすぐに効く。
	s.a.authz.Invalidate(s.a.realm.ID)
	return publicapi.PutMyOrgSettings200JSONResponse(out), nil
}

func (s adminServer) GetOrgSettings(ctx context.Context, req adminapi.GetOrgSettingsRequestObject) (adminapi.GetOrgSettingsResponseObject, error) {
	var out publicapi.OrgSettingsView
	o, err := s.getOrgSettings(ctx, req.Id, &out)
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetOrgSettings200JSONResponse(adminSettingsView(out)), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetOrgSettings401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetOrgSettings403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetOrgSettings404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) getOrgSettings(ctx context.Context, publicID string, out *publicapi.OrgSettingsView) (outcome, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.orgsOff(true); off {
		return o, nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cur, _, err := s.adminOrg(ctx, tx, publicID)
		if err != nil {
			return err
		}
		*out, err = s.a.settingsView(cur)
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) PutOrgSettings(ctx context.Context, req adminapi.PutOrgSettingsRequestObject) (adminapi.PutOrgSettingsResponseObject, error) {
	var out publicapi.OrgSettingsView
	o, err := s.putOrgSettings(ctx, req, &out)
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.PutOrgSettings200JSONResponse(adminSettingsView(out)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.PutOrgSettings400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.PutOrgSettings401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.PutOrgSettings403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.PutOrgSettings404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.PutOrgSettings409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) putOrgSettings(ctx context.Context, req adminapi.PutOrgSettingsRequestObject, out *publicapi.OrgSettingsView) (outcome, error) {
	if req.Body == nil {
		return failed(http.StatusBadRequest, "invalid_request"), nil
	}
	p, d, err := s.a.authorize(ctx, role.PermOrgsUpdate)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.orgsOff(true); off {
		return o, nil
	}
	b := req.Body
	st, err := settingsIn(b.AbsoluteLifetimeSeconds, b.IdleTimeoutSeconds, b.MaxAuthAgeSeconds)
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	st.Warnings = actionsIn(b.Warnings)
	if p := b.LoginPolicy; p != nil {
		st.LoginPolicy = policyIn(&publicapi.OrgLoginPolicy{RequirePasskey: p.RequirePasskey, MembershipEmailDomains: p.MembershipEmailDomains, IpAllowlist: p.IpAllowlist,
			RequireSso: p.RequireSso})
	}
	rs, err := requirementsIn(b.Requirements)
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cur, _, err := s.adminOrg(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		if st.Requirements, err = orgRequirementsIn(ctx, tx, s.a.realm.ID, rs); err != nil {
			return err
		}
		if cur, err = s.a.orgs.UpdateSettings(ctx, tx, cur, st, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		*out, err = s.a.settingsView(cur)
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	s.a.authz.Invalidate(s.a.realm.ID)
	return outcome{status: http.StatusOK}, nil
}
