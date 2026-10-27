package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// realm の管理 API（複数 realm。design.md 11.1、ADR 0083）。既定の realm の管理 API だけが受け付ける。

// maxRealmHosts は realm に付けられるホスト名の数。
const maxRealmHosts = 10

// realmsOff は realm を管理できなければ 404 を返す。
func (s adminServer) realmsOff() (outcome, bool) {
	switch {
	case !s.a.plan.IsActive(feature.MultiRealm):
		return failed(http.StatusNotFound, "multi_realm_disabled"), true
	case s.a.root != s.a:
		return failed(http.StatusNotFound, "realm_management_unavailable"), true
	}
	return outcome{}, false
}

// manageRealms は権限 realms:manage と、realm を管理できることを確かめる。
func (s adminServer) manageRealms(ctx context.Context) (adminPrincipal, outcome, bool, error) {
	p, d, err := s.a.authorize(ctx, role.PermRealmsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return p, o, false, err
	}
	if o, off := s.realmsOff(); off {
		return p, o, false, nil
	}
	return p, outcome{}, true, nil
}

func (s adminServer) realmView(r port.Realm) (adminapi.Realm, error) {
	isDefault := r.ID == s.a.realm.ID
	rs := s.a.settings
	if !isDefault {
		var err error
		if rs, err = parseRealmSettings(s.a.cfg.Realm, r.Settings); err != nil {
			return adminapi.Realm{}, err
		}
	}
	v := adminapi.Realm{Id: r.ID, Slug: r.Slug, Hosts: r.Hosts, Default: isDefault, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if v.Hosts == nil {
		v.Hosts = []string{}
	}
	if iss := endpointFor(s.a.cfg, r, isDefault).issuer; iss != "" {
		v.Issuer = &iss
	}
	v.Settings.Timezone, v.Settings.VerifiedVia, v.Settings.OrgCreation = rs.Timezone, rs.VerifiedVia, rs.OrgCreation
	v.Settings.OrgDeletionGraceSeconds, v.Settings.UserDeletionGraceSeconds = rs.OrgDeletionGraceSeconds, rs.UserDeletionGraceSeconds
	v.Settings.EmailStorage = rs.EmailStorage
	v.Settings.QuotaCount.Invited, v.Settings.QuotaCount.Future, v.Settings.QuotaCount.Suspended = rs.QuotaCount.Invited, rs.QuotaCount.Future, rs.QuotaCount.Suspended
	if v.Settings.VerifiedVia == nil {
		v.Settings.VerifiedVia = []string{}
	}
	return v, nil
}

// applySettings は API の設定を rs に重ねる（渡した項目だけ）。
func applySettings(rs realmSettings, in *adminapi.RealmSettings) realmSettings {
	if in == nil {
		return rs
	}
	if in.Timezone != nil {
		rs.Timezone = *in.Timezone
	}
	if in.VerifiedVia != nil {
		rs.VerifiedVia = make([]string, 0, len(*in.VerifiedVia))
		for _, v := range *in.VerifiedVia {
			rs.VerifiedVia = append(rs.VerifiedVia, string(v))
		}
	}
	if in.OrgCreation != nil {
		rs.OrgCreation = string(*in.OrgCreation)
	}
	if in.OrgDeletionGraceSeconds != nil {
		rs.OrgDeletionGraceSeconds = *in.OrgDeletionGraceSeconds
	}
	if in.UserDeletionGraceSeconds != nil {
		rs.UserDeletionGraceSeconds = *in.UserDeletionGraceSeconds
	}
	if in.EmailStorage != nil {
		rs.EmailStorage = string(*in.EmailStorage)
	}
	if q := in.QuotaCount; q != nil {
		if q.Invited != nil {
			rs.QuotaCount.Invited = *q.Invited
		}
		if q.Future != nil {
			rs.QuotaCount.Future = *q.Future
		}
		if q.Suspended != nil {
			rs.QuotaCount.Suspended = *q.Suspended
		}
	}
	return rs
}

// checkHosts はホスト名を確かめ、小文字にして返す。
func checkHosts(in *[]string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	if len(*in) > maxRealmHosts {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_hosts", "too many hosts")
	}
	var out []string
	for _, h := range *in {
		h = normalizeHost(h)
		if !validHost(h) {
			return nil, errs.WithCode(errs.KindInvalid, "invalid_hosts", "invalid host")
		}
		if slices.Contains(out, h) {
			return nil, errs.WithCode(errs.KindInvalid, "invalid_hosts", "repeated host")
		}
		out = append(out, h)
	}
	return out, nil
}

// realmTaken は slug かホスト名の重複を 409 realm_taken にする。
func realmTaken(err error) error {
	if errors.Is(err, errs.Conflict) {
		return errs.WithCode(errs.KindFailedPrecondition, "realm_taken", "realm slug or host taken")
	}
	return err
}

func (s adminServer) ListRealms(ctx context.Context, _ adminapi.ListRealmsRequestObject) (adminapi.ListRealmsResponseObject, error) {
	_, o, ok, err := s.manageRealms(ctx)
	out := adminapi.ListRealms200JSONResponse{Realms: []adminapi.Realm{}}
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			rs, err := tx.Realms().List(ctx)
			for _, r := range rs {
				v, err := s.realmView(r)
				if err != nil {
					return err
				}
				out.Realms = append(out.Realms, v)
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
		return adminapi.ListRealms401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListRealms403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListRealms404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateRealm(ctx context.Context, req adminapi.CreateRealmRequestObject) (adminapi.CreateRealmResponseObject, error) {
	p, o, ok, err := s.manageRealms(ctx)
	var out adminapi.Realm
	if ok {
		err = s.createRealm(ctx, p, req.Body, &out)
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.CreateRealm201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateRealm400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateRealm401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateRealm403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateRealm404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateRealm409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) createRealm(ctx context.Context, p adminPrincipal, body *adminapi.RealmInput, out *adminapi.Realm) error {
	if body == nil || !realmSlugRE.MatchString(body.Slug) {
		return errs.WithCode(errs.KindInvalid, "invalid_slug", "invalid realm slug")
	}
	hosts, err := checkHosts(body.Hosts)
	if err != nil {
		return err
	}
	rs := applySettings(defaultRealmSettings(s.a.cfg.Realm), body.Settings)
	if err := rs.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	now := s.a.deps.Clock.Now()
	r := port.Realm{ID: id.NewExternal(id.Realm), Slug: body.Slug, Settings: raw, Hosts: hosts, CreatedAt: now, UpdatedAt: now}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Realms().Create(ctx, r); err != nil {
			return realmTaken(err)
		}
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "realm.created", Result: audit.ResultSuccess, RealmID: r.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"slug": r.Slug, "hosts": hosts, "created_from_realm_id": s.a.realm.ID},
		})
		return err
	})
	if err != nil {
		return err
	}
	s.realmChanged(ctx)
	*out, err = s.realmView(r)
	return err
}

// realmChanged はこのインスタンスの realm の表をすぐに読み直す（他のインスタンスは refresh の間隔の内に反映する）。
func (s adminServer) realmChanged(ctx context.Context) {
	if err := s.a.loadRealms(ctx); err != nil {
		s.a.deps.Logger.WarnContext(ctx, "realm: reload failed", "error", err)
	}
}

func (s adminServer) GetRealm(ctx context.Context, req adminapi.GetRealmRequestObject) (adminapi.GetRealmResponseObject, error) {
	_, o, ok, err := s.manageRealms(ctx)
	var out adminapi.Realm
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			r, err := tx.Realms().Get(ctx, req.RealmId)
			if err != nil {
				return err
			}
			out, err = s.realmView(r)
			return err
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.GetRealm200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetRealm401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetRealm403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetRealm404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateRealm(ctx context.Context, req adminapi.UpdateRealmRequestObject) (adminapi.UpdateRealmResponseObject, error) {
	p, o, ok, err := s.manageRealms(ctx)
	var out adminapi.Realm
	if ok {
		err = s.updateRealm(ctx, p, req.RealmId, req.Body, &out)
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.UpdateRealm200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateRealm400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateRealm401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateRealm403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateRealm404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateRealm409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) updateRealm(ctx context.Context, p adminPrincipal, realmID string, body *adminapi.RealmUpdate, out *adminapi.Realm) error {
	if body == nil {
		return errs.WithCode(errs.KindInvalid, "invalid_request", "missing body")
	}
	if realmID == s.a.realm.ID {
		return errs.WithCode(errs.KindFailedPrecondition, "default_realm", "the default realm is configured in the config file")
	}
	hosts, err := checkHosts(body.Hosts)
	if err != nil {
		return err
	}
	var r port.Realm
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if r, err = tx.Realms().Get(ctx, realmID); err != nil {
			return err
		}
		rs, err := parseRealmSettings(s.a.cfg.Realm, r.Settings)
		if err != nil {
			return err
		}
		rs = applySettings(rs, body.Settings)
		if err := rs.validate(); err != nil {
			return err
		}
		if r.Settings, err = json.Marshal(rs); err != nil {
			return err
		}
		if body.Hosts != nil {
			r.Hosts = hosts
		}
		r.UpdatedAt = s.a.deps.Clock.Now()
		if err := tx.Realms().Update(ctx, r); err != nil {
			return realmTaken(err)
		}
		_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "realm.updated", Result: audit.ResultSuccess, RealmID: r.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"hosts": r.Hosts, "updated_from_realm_id": s.a.realm.ID},
		})
		return err
	})
	if err != nil {
		return err
	}
	s.realmChanged(ctx)
	*out, err = s.realmView(r)
	return err
}

func (s adminServer) CreateRealmOperator(ctx context.Context, req adminapi.CreateRealmOperatorRequestObject) (adminapi.CreateRealmOperatorResponseObject, error) {
	p, o, ok, err := s.manageRealms(ctx)
	var out adminapi.CreateRealmOperator201JSONResponse
	if ok {
		err = s.createRealmOperator(ctx, p, req.RealmId, req.Body, &out)
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return out, nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateRealmOperator400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateRealmOperator401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateRealmOperator403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateRealmOperator404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) createRealmOperator(ctx context.Context, p adminPrincipal, realmID string, body *adminapi.CreateRealmOperatorJSONRequestBody, out *adminapi.CreateRealmOperator201JSONResponse) error {
	if body == nil {
		return errs.WithCode(errs.KindInvalid, "invalid_request", "missing body")
	}
	ra, ok := s.a.forRealm(realmID)
	if !ok {
		return errs.New(errs.KindNotFound, "realm %s", realmID)
	}
	roleName, ttl := role.RealmOwner, 15*time.Minute
	if body.Role != nil {
		roleName = *body.Role
	}
	if body.TtlSeconds != nil {
		ttl = time.Duration(*body.TtlSeconds) * time.Second
	}
	op, err := ra.createOperator(ctx, body.Email, roleName, ttl, p.Actor, requestID(ctx))
	if err != nil {
		return err
	}
	out.UserId, out.Created, out.LoginToken = op.UserID, op.Created, op.LinkToken
	if ra.issuer != "" {
		out.LoginUrl = ra.issuer + "/login/link#token=" + op.LinkToken
	}
	return nil
}
