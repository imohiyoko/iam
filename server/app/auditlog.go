package app

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの照会（ADR 0100）。運営者は管理 API で realm のイベントを、Org の管理者は公開 API で自分の Org のイベントを読む。
// 読んだこと自体も audit.read として監査ログに残す（大量の読み取りの検知に使う）。

const (
	defaultAuditPage = 50
	maxAuditParamLen = 200
	// EventAuditRead は監査ログを読んだこと。EventAuditVerified はチェーンを検証したこと。
	EventAuditRead     = "audit.read"
	EventAuditVerified = "audit.verified"
)

// auditParams は照会の条件（管理 API と公開 API で共通）。
type auditParams struct {
	limit                     *int
	after                     *string
	since, until              *time.Time
	typ, typePrefix, result   *string
	actorType, actorID, orgID *string
	target                    *string
}

// auditQuery は条件を確かめて照会を作る。誤りは 400 のコード（invalid_request・invalid_cursor）。
func auditQuery(realmID string, p auditParams) (port.AuditQuery, string) {
	q := port.AuditQuery{RealmID: realmID, Limit: defaultAuditPage}
	if p.limit != nil {
		if *p.limit < 1 || *p.limit > eventlog.MaxPage {
			return q, "invalid_request"
		}
		q.Limit = *p.limit
	}
	before, err := eventlog.ParseCursor(deref(p.after))
	if err != nil {
		return q, "invalid_cursor"
	}
	q.BeforeSeq = before
	for _, s := range []*string{p.typ, p.typePrefix, p.actorType, p.actorID, p.orgID, p.target} {
		if s != nil && len(*s) > maxAuditParamLen {
			return q, "invalid_request"
		}
	}
	q.Since, q.Until = deref(p.since), deref(p.until)
	if !q.Since.IsZero() && !q.Until.IsZero() && !q.Since.Before(q.Until) {
		return q, "invalid_request"
	}
	switch r := audit.Result(deref(p.result)); r {
	case "", audit.ResultSuccess, audit.ResultFailure:
		q.Result = r
	default:
		return q, "invalid_request"
	}
	q.Type, q.TypePrefix, q.ActorType, q.ActorID, q.OrgID, q.Ref = deref(p.typ), deref(p.typePrefix), deref(p.actorType), deref(p.actorID),
		deref(p.orgID), deref(p.target)
	return q, ""
}

// filterDetails は監査ログに残す照会の条件（空の項目は残さない）。
func filterDetails(q port.AuditQuery) map[string]any {
	d := map[string]any{}
	for k, v := range map[string]string{"type": q.Type, "type_prefix": q.TypePrefix, "result": string(q.Result), "actor_type": q.ActorType,
		"actor_id": q.ActorID, "org_id": q.OrgID, "target_id": q.Ref} {
		if v != "" {
			d[k] = v
		}
	}
	if !q.Since.IsZero() {
		d["since"] = q.Since.UTC().Format(time.RFC3339Nano)
	}
	if !q.Until.IsZero() {
		d["until"] = q.Until.UTC().Format(time.RFC3339Nano)
	}
	if q.BeforeSeq > 0 {
		d["before_seq"] = q.BeforeSeq
	}
	return d
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func auditEventOut(en eventlog.Entry) adminapi.AuditEvent {
	e := en.Event
	out := adminapi.AuditEvent{Id: e.ID, Seq: en.Seq, Hash: hex.EncodeToString(en.Hash), Time: e.Time, Type: e.Type, Result: string(e.Result),
		Actor: adminapi.AuditActor{Type: e.Actor.Type, Id: strPtr(e.Actor.ID)}, OrgId: strPtr(e.OrgID), SessionId: strPtr(e.SessionID),
		Ip: strPtr(e.IP), UserAgent: strPtr(e.UserAgent), RequestId: strPtr(e.RequestID)}
	if len(e.Details) > 0 {
		out.Details = &e.Details
	}
	return out
}

// withClientData は全文を復号して out に入れる（読めなければ client_unreadable）。読めた件数を返す。
func (a *App) withClientData(ctx context.Context, tx port.Tx, en eventlog.Entry, out *adminapi.AuditEvent) (bool, error) {
	ip, ua, err := a.clientSealer.Open(ctx, tx, en.Event)
	if errors.Is(err, eventlog.ErrClientUnreadable) {
		out.ClientUnreadable = new(true)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	out.Client = &struct {
		Ip        *string `json:"ip,omitempty"`
		UserAgent *string `json:"user_agent,omitempty"`
	}{Ip: strPtr(ip), UserAgent: strPtr(ua)}
	return true, nil
}

// recordAuditRead は照会したことを監査ログに残す。
func (a *App) recordAuditRead(ctx context.Context, tx port.Tx, actor audit.Actor, orgID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{Type: EventAuditRead, Result: audit.ResultSuccess, RealmID: a.realm.ID, OrgID: orgID,
		Actor: actor, RequestID: requestID(ctx), Details: details})
	return err
}

// authorizeAudit は audit:read と、全文を読むなら audit:read_client_data を確かめる。
func (s adminServer) authorizeAudit(ctx context.Context, clientData bool) (adminPrincipal, *denial, error) {
	p, d, err := s.a.authorize(ctx, role.PermAuditRead)
	if d != nil || err != nil || !clientData {
		return p, d, err
	}
	return s.a.authorize(ctx, role.PermAuditReadClientData)
}

func (s adminServer) ListAuditEvents(ctx context.Context, req adminapi.ListAuditEventsRequestObject) (adminapi.ListAuditEventsResponseObject, error) {
	pr := req.Params
	clientData := deref(pr.IncludeClientData)
	p, d, err := s.authorizeAudit(ctx, clientData)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListAuditEvents401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.ListAuditEvents403JSONResponse(d.Body), nil
	}
	q, code := auditQuery(s.a.realm.ID, auditParams{limit: pr.Limit, after: pr.After, since: pr.Since, until: pr.Until, typ: pr.Type,
		typePrefix: pr.TypePrefix, result: (*string)(pr.Result), actorType: pr.ActorType, actorID: pr.ActorId, orgID: pr.OrgId, target: pr.TargetId})
	if code != "" {
		return adminapi.ListAuditEvents400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(code, ""))}, nil
	}
	out := adminapi.ListAuditEvents200JSONResponse{Events: []adminapi.AuditEvent{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		entries, next, err := eventlog.Query(ctx, tx, q)
		if err != nil {
			return err
		}
		opened := 0
		for _, en := range entries {
			v := auditEventOut(en)
			if clientData {
				ok, err := s.a.withClientData(ctx, tx, en, &v)
				if err != nil {
					return err
				}
				if ok {
					opened++
				}
			}
			out.Events = append(out.Events, v)
		}
		if next > 0 {
			out.NextCursor = new(eventlog.Cursor(next))
		}
		return s.a.recordAuditRead(ctx, tx, p.Actor, "", map[string]any{"scope": "realm", "count": len(entries), "client_data": clientData,
			"client_data_opened": opened, "filter": filterDetails(q)})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s adminServer) GetAuditEvent(ctx context.Context, req adminapi.GetAuditEventRequestObject) (adminapi.GetAuditEventResponseObject, error) {
	clientData := deref(req.Params.IncludeClientData)
	p, d, err := s.authorizeAudit(ctx, clientData)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.GetAuditEvent401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.GetAuditEvent403JSONResponse(d.Body), nil
	}
	var out adminapi.AuditEvent
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		en, err := eventlog.Get(ctx, tx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		out = auditEventOut(en)
		opened := 0
		if clientData {
			ok, err := s.a.withClientData(ctx, tx, en, &out)
			if err != nil {
				return err
			}
			if ok {
				opened = 1
			}
		}
		return s.a.recordAuditRead(ctx, tx, p.Actor, "", map[string]any{"scope": "realm", "event_id": en.Event.ID, "count": 1,
			"client_data": clientData, "client_data_opened": opened})
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.GetAuditEvent404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	return adminapi.GetAuditEvent200JSONResponse(out), nil
}

func (s adminServer) VerifyAuditChain(ctx context.Context, req adminapi.VerifyAuditChainRequestObject) (adminapi.VerifyAuditChainResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermAuditRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.VerifyAuditChain401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.VerifyAuditChain403JSONResponse(d.Body), nil
	case s.a.root != s.a:
		// チェーンは全 realm で1本なので、既定の realm の運営者だけが確かめる（ほかの realm の件数を見せない）。
		return adminapi.VerifyAuditChain404JSONResponse(adminError("not_found", "")), nil
	}
	var from, to int64
	if b := req.Body; b != nil {
		from, to = deref(b.FromSeq), deref(b.ToSeq)
	}
	if from < 0 || to < 0 || (to > 0 && from > to) {
		return adminapi.VerifyAuditChain400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	res, err := eventlog.VerifyRange(ctx, s.a.deps.Storage, from, to)
	switch {
	case errors.Is(err, eventlog.ErrRangeTooLarge):
		return adminapi.VerifyAuditChain400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("range_too_large", ""))}, nil
	case errors.Is(err, eventlog.ErrTruncatedDuringVerify):
		return adminapi.VerifyAuditChain409JSONResponse(adminError("truncated_during_verification", "")), nil
	case err != nil:
		return nil, err
	}
	out := adminapi.AuditChainVerification{Valid: res.Broken == nil, FromSeq: res.FromSeq, ToSeq: res.ToSeq, HeadSeq: res.HeadSeq,
		Anchored: res.Anchored, PrevHash: hex.EncodeToString(res.PrevHash)}
	if res.LastHash != nil {
		out.LastHash = new(hex.EncodeToString(res.LastHash))
	}
	if cp := res.Checkpoint; cp != nil {
		out.Checkpoint = &struct {
			At   time.Time `json:"at"`
			Hash string    `json:"hash"`
			Seq  int64     `json:"seq"`
		}{At: cp.At, Hash: hex.EncodeToString(cp.Hash), Seq: cp.Seq}
	}
	details := map[string]any{"from_seq": res.FromSeq, "to_seq": res.ToSeq, "anchored": res.Anchored, "valid": out.Valid}
	result := audit.ResultSuccess
	if b := res.Broken; b != nil {
		out.Broken = &struct {
			Reason adminapi.AuditChainVerificationBrokenReason `json:"reason"`
			Seq    int64                                       `json:"seq"`
		}{Reason: adminapi.AuditChainVerificationBrokenReason(b.Reason), Seq: b.Seq}
		details["broken_seq"], details["reason"], result = b.Seq, b.Reason, audit.ResultFailure
		s.a.deps.Logger.Error("audit chain verification failed", "seq", b.Seq, "reason", b.Reason)
	}
	if err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: EventAuditVerified, Result: result, RealmID: s.a.realm.ID, Actor: p.Actor,
			RequestID: requestID(ctx), Details: details})
		return err
	}); err != nil {
		return nil, err
	}
	return adminapi.VerifyAuditChain200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// Org の監査ログ（公開 API。フィーチャー org_audit_log）

// orgAuditOn はフィーチャー org と org_audit_log が動いているか。
func (s publicServer) orgAuditOn() bool {
	return s.a.orgs != nil && s.a.plan.IsActive(feature.OrgAuditLog)
}

// orgActorVisible は、主体の ID を Org に見せてよいか（この Org のメンバー（終了したものを含む）か、この Org のサービスアカウント）。
// 運営者やほかの Org の主体の ID は見せない（ADR 0022、0036）。
type orgActorVisible struct {
	tx    port.Tx
	realm string
	org   port.Org
	seen  map[audit.Actor]bool
}

func (v *orgActorVisible) ok(ctx context.Context, a audit.Actor) (bool, error) {
	if a.ID == "" {
		return false, nil
	}
	if r, ok := v.seen[a]; ok {
		return r, nil
	}
	r := false
	switch a.Type {
	case "user":
		u, err := v.tx.Users().GetByPublicID(ctx, v.realm, a.ID)
		if err == nil {
			_, err = v.tx.Memberships().GetByUserOrg(ctx, v.realm, u.ID, v.org.ID)
		}
		if err != nil && !errors.Is(err, errs.NotFound) {
			return false, err
		}
		r = err == nil
	case "service_account":
		sa, err := v.tx.ServiceAccounts().Get(ctx, v.realm, a.ID)
		if err != nil && !errors.Is(err, errs.NotFound) {
			return false, err
		}
		r = err == nil && sa.OrgID == v.org.ID
	}
	v.seen[a] = r
	return r, nil
}

func (s publicServer) ListOrgAuditEvents(ctx context.Context, req publicapi.ListOrgAuditEventsRequestObject) (publicapi.ListOrgAuditEventsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListOrgAuditEvents401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.orgAuditOn() {
		return publicapi.ListOrgAuditEvents404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	pr := req.Params
	q, code := auditQuery(s.a.realm.ID, auditParams{limit: pr.Limit, after: pr.After, since: pr.Since, until: pr.Until, typ: pr.Type,
		typePrefix: pr.TypePrefix, result: (*string)(pr.Result), actorID: pr.ActorId, target: pr.TargetId})
	if code != "" {
		return publicapi.ListOrgAuditEvents400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: code}}, nil
	}
	out := publicapi.ListOrgAuditEvents200JSONResponse{Events: []publicapi.OrgAuditEvent{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgAuditRead)
		if err != nil {
			return err
		}
		// Org の範囲はここで決める（呼び出し側の条件では変えられない）。
		q.OrgID = o.PublicID
		entries, next, err := eventlog.Query(ctx, tx, q)
		if err != nil {
			return err
		}
		vis := &orgActorVisible{tx: tx, realm: s.a.realm.ID, org: o, seen: map[audit.Actor]bool{}}
		for _, en := range entries {
			e := en.Event
			if e.OrgID != o.PublicID {
				continue // Query が確かめ直しているが、念のため
			}
			v := publicapi.OrgAuditEvent{Id: e.ID, Time: e.Time, Type: e.Type, Result: string(e.Result), RequestId: strPtr(e.RequestID)}
			v.Actor.Type = e.Actor.Type
			show, err := vis.ok(ctx, e.Actor)
			if err != nil {
				return err
			}
			if show {
				v.Actor.Id = &e.Actor.ID
			}
			if len(e.Details) > 0 {
				v.Details = &e.Details
			}
			out.Events = append(out.Events, v)
		}
		if next > 0 {
			out.NextCursor = new(eventlog.Cursor(next))
		}
		return s.a.recordAuditRead(ctx, tx, au.Actor(), o.PublicID, map[string]any{"scope": "org", "count": len(entries), "filter": filterDetails(q)})
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgAuditEvents404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgAuditEvents403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}
