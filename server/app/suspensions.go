package app

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 停止と有効期間（design.md 4.7、4.8、ADR 0053、0058）。

// suspensionPerm は種別を停止・解除する権限。realm で足した種別は realm:owner（suspensions:*）だけ。
func suspensionPerm(category string) string {
	if slices.Contains(account.BuiltinCategories, category) {
		return role.SuspensionPerm(category)
	}
	return role.PermSuspensionsAny
}

// subject は停止・有効期間の対象と、ユーザーか Membership なら本人。
type subject struct {
	target       account.Target
	userID       string // 本人の内部 ID（セッションの検証結果を消す）
	userPublicID string
}

// resolveFunc はトランザクションの中で対象を引く。止められない対象（個人 Org など）ならエラーを返す。
type resolveFunc func(ctx context.Context, tx port.Tx) (subject, error)

func (s adminServer) userSubject(publicID string) resolveFunc {
	return func(ctx context.Context, tx port.Tx) (subject, error) {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID)
		return subject{target: account.UserTarget(u), userID: u.ID, userPublicID: u.PublicID}, err
	}
}

func (s adminServer) orgSubject(publicID string) resolveFunc {
	return func(ctx context.Context, tx port.Tx) (subject, error) {
		o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, publicID)
		if err != nil {
			return subject{}, err
		}
		return subject{target: org.OrgTarget(o)}, org.Suspendable(o)
	}
}

func (s adminServer) membershipSubject(publicID string) resolveFunc {
	return func(ctx context.Context, tx port.Tx) (subject, error) {
		m, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, publicID)
		if err != nil {
			return subject{}, err
		}
		return s.membershipOf(ctx, tx, m)
	}
}

func (s adminServer) membershipOf(ctx context.Context, tx port.Tx, m port.Membership) (subject, error) {
	o, err := tx.Orgs().Get(ctx, s.a.realm.ID, m.OrgID)
	if err != nil {
		return subject{}, err
	}
	u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
	if err != nil {
		return subject{}, err
	}
	return subject{target: org.MembershipTarget(m), userID: u.ID, userPublicID: u.PublicID}, org.Suspendable(o)
}

// subjectOf は停止の対象を引く。
func (s adminServer) subjectOf(ctx context.Context, tx port.Tx, sp port.Suspension) (subject, error) {
	switch sp.TargetType {
	case port.SuspensionTargetUser:
		u, err := tx.Users().Get(ctx, s.a.realm.ID, sp.TargetID)
		return subject{target: account.UserTarget(u), userID: u.ID, userPublicID: u.PublicID}, err
	case port.SuspensionTargetOrg:
		o, err := tx.Orgs().Get(ctx, s.a.realm.ID, sp.TargetID)
		return subject{target: org.OrgTarget(o)}, err
	case port.SuspensionTargetServiceAccount:
		sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, sp.TargetID)
		return subject{target: serviceaccount.Target(sa)}, err
	case port.SuspensionTargetMembership:
		m, err := tx.Memberships().Get(ctx, s.a.realm.ID, sp.TargetID)
		if err != nil {
			return subject{}, err
		}
		sub, err := s.membershipOf(ctx, tx, m)
		if errors.Is(err, org.ErrPersonalOrg) {
			err = nil
		}
		return sub, err
	}
	return subject{}, errs.New(errs.KindNotFound, "suspension")
}

func (s adminServer) suspensionView(sp port.Suspension, sub subject) adminapi.Suspension {
	now := s.a.deps.Clock.Now()
	end := sp.EndsAt
	if sp.LiftedAt != nil && (end == nil || sp.LiftedAt.Before(*end)) {
		end = sp.LiftedAt
	}
	v := adminapi.Suspension{Id: sp.PublicID, TargetType: adminapi.SuspensionTargetType(sp.TargetType), TargetId: sub.target.PublicID,
		Category: sp.Category, Reason: sp.Reason, StartsAt: sp.StartsAt, EndsAt: sp.EndsAt, CreatedAt: sp.CreatedAt, LiftedAt: sp.LiftedAt,
		Active: !sp.StartsAt.After(now) && (end == nil || end.After(now))}
	if sub.userPublicID != "" {
		v.UserId = &sub.userPublicID
	}
	if sp.ExternalRef != "" {
		v.ExternalRef = &sp.ExternalRef
	}
	if sp.CreatedBy != "" {
		v.CreatedBy = &sp.CreatedBy
	}
	if sp.LiftedBy != "" {
		v.LiftedBy = &sp.LiftedBy
	}
	return v
}

// outcome は管理 API の応答の状態と、エラーの本文。
type outcome struct {
	status int
	body   adminapi.Error
}

func failed(status int, code string) outcome {
	return outcome{status: status, body: adminError(code, "")}
}

// outcomeOf は認可の拒否とエラーを応答の状態にする。ok は成功（status は呼び出し側が決める）。
func outcomeOf(d *denial, err error) (outcome, bool, error) {
	if d != nil {
		return outcome{status: d.Status, body: d.Body}, false, nil
	}
	if code, ok := stateCode(err); ok {
		o := failed(http.StatusConflict, code)
		o.body.Quota = adminShortage(err)
		return o, false, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return failed(http.StatusNotFound, "not_found"), false, nil
	case errors.Is(err, errs.Invalid):
		return failed(http.StatusBadRequest, errCode(err)), false, nil
	case errors.Is(err, errs.PermissionDenied):
		return failed(http.StatusForbidden, errCodeOr(err, errs.CodePermissionDenied)), false, nil
	case errors.Is(err, errOutranked):
		return failed(http.StatusForbidden, errs.CodePermissionDenied), false, nil
	case err != nil:
		return outcome{}, false, err
	}
	return outcome{}, true, nil
}

// orgsOff はフィーチャー org が動いていなければ 404 org_disabled を返す。
func (s adminServer) orgsOff(needOrg bool) (outcome, bool) {
	if needOrg && s.a.orgs == nil {
		return failed(http.StatusNotFound, "org_disabled"), true
	}
	return outcome{}, false
}

// outranksUser は、対象がユーザーなら、呼び出し側が対象のロールの権限をすべて持つかを確かめる（上位のロールの運営者を
// 下位の運営者が止めない。ADR 0053）。Membership・Org・サービスアカウントは見ない。
func (s adminServer) outranksUser(ctx context.Context, tx port.Tx, p adminPrincipal, sub subject) error {
	if sub.target.Type != port.SuspensionTargetUser {
		return nil
	}
	return s.a.outranks(ctx, tx, p, sub.userID)
}

// suspend は運営者による停止（4.7）。成功なら 201（同じ external_ref の停止があれば 200）。
func (s adminServer) suspend(ctx context.Context, body *adminapi.SuspendRequest, needOrg bool, resolve resolveFunc) (adminapi.Suspension, outcome, error) {
	if body == nil {
		return adminapi.Suspension{}, failed(http.StatusBadRequest, "invalid_request"), nil
	}
	p, d, err := s.a.authorize(ctx, suspensionPerm(body.Category))
	if o, ok, err := outcomeOf(d, err); !ok {
		return adminapi.Suspension{}, o, err
	}
	if o, off := s.orgsOff(needOrg); off {
		return adminapi.Suspension{}, o, nil
	}
	in := account.Suspend{Category: body.Category, Reason: body.Reason, StartsAt: body.StartsAt, EndsAt: body.EndsAt}
	if body.ExternalRef != nil {
		in.ExternalRef = *body.ExternalRef
	}
	var sub subject
	var out adminapi.Suspension
	var created bool
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if sub, err = resolve(ctx, tx); err != nil {
			return err
		}
		if err := s.outranksUser(ctx, tx, p, sub); err != nil {
			return err
		}
		var sp port.Suspension
		if sp, created, err = s.a.accounts.Suspend(ctx, tx, s.a.realm.ID, sub.target, in, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		// 今から効くユーザーの停止は、ログインの系列を終える（Back-Channel Logout。予約は始まりの時刻に scheduler で）。
		if created && sp.TargetType == port.SuspensionTargetUser && !sp.StartsAt.After(s.a.deps.Clock.Now()) {
			if err := s.a.sessions.EndUserTx(ctx, tx, s.a.realm.ID, sp.TargetID, session.ReasonSuspended, requestID(ctx)); err != nil {
				return err
			}
		}
		out = s.suspensionView(sp, sub)
		return nil
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return adminapi.Suspension{}, o, err
	}
	if !created {
		return out, outcome{status: http.StatusOK}, nil
	}
	if sub.userID != "" {
		s.a.sessions.Forget(ctx, s.a.realm.ID, sub.userID)
	}
	return out, outcome{status: http.StatusCreated}, nil
}

// listSuspensions は対象の停止の一覧（解除・終了したものも含む）。
func (s adminServer) listSuspensions(ctx context.Context, needOrg bool, resolve resolveFunc) (adminapi.Suspensions, outcome, error) {
	_, d, err := s.a.authorize(ctx, role.PermSuspensionsRead)
	if o, ok, err := outcomeOf(d, err); !ok {
		return adminapi.Suspensions{}, o, err
	}
	if o, off := s.orgsOff(needOrg); off {
		return adminapi.Suspensions{}, o, nil
	}
	out := adminapi.Suspensions{Suspensions: []adminapi.Suspension{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		sub, err := resolve(ctx, tx)
		if err != nil && !errors.Is(err, org.ErrPersonalOrg) {
			return err
		}
		ss, err := tx.Suspensions().ListByTarget(ctx, s.a.realm.ID, sub.target.Type, sub.target.ID)
		for _, sp := range ss {
			out.Suspensions = append(out.Suspensions, s.suspensionView(sp, sub))
		}
		return err
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return adminapi.Suspensions{}, o, err
	}
	return out, outcome{status: http.StatusOK}, nil
}

func (s adminServer) SuspendUser(ctx context.Context, req adminapi.SuspendUserRequestObject) (adminapi.SuspendUserResponseObject, error) {
	out, o, err := s.suspend(ctx, req.Body, false, s.userSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SuspendUser200JSONResponse(out), nil
	case o.status == http.StatusCreated:
		return adminapi.SuspendUser201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SuspendUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SuspendUser401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SuspendUser403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SuspendUser404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.SuspendUser409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) SuspendOrg(ctx context.Context, req adminapi.SuspendOrgRequestObject) (adminapi.SuspendOrgResponseObject, error) {
	out, o, err := s.suspend(ctx, req.Body, true, s.orgSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SuspendOrg200JSONResponse(out), nil
	case o.status == http.StatusCreated:
		return adminapi.SuspendOrg201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SuspendOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SuspendOrg401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SuspendOrg403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SuspendOrg404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.SuspendOrg409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) SuspendMembership(ctx context.Context, req adminapi.SuspendMembershipRequestObject) (adminapi.SuspendMembershipResponseObject, error) {
	out, o, err := s.suspend(ctx, req.Body, true, s.membershipSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SuspendMembership200JSONResponse(out), nil
	case o.status == http.StatusCreated:
		return adminapi.SuspendMembership201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SuspendMembership400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SuspendMembership401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SuspendMembership403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SuspendMembership404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.SuspendMembership409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListUserSuspensions(ctx context.Context, req adminapi.ListUserSuspensionsRequestObject) (adminapi.ListUserSuspensionsResponseObject, error) {
	out, o, err := s.listSuspensions(ctx, false, s.userSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListUserSuspensions200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListUserSuspensions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListUserSuspensions403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListUserSuspensions404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListOrgSuspensions(ctx context.Context, req adminapi.ListOrgSuspensionsRequestObject) (adminapi.ListOrgSuspensionsResponseObject, error) {
	out, o, err := s.listSuspensions(ctx, true, s.orgSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListOrgSuspensions200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListOrgSuspensions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListOrgSuspensions403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListOrgSuspensions404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListMembershipSuspensions(ctx context.Context, req adminapi.ListMembershipSuspensionsRequestObject) (adminapi.ListMembershipSuspensionsResponseObject, error) {
	out, o, err := s.listSuspensions(ctx, true, s.membershipSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListMembershipSuspensions200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListMembershipSuspensions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListMembershipSuspensions403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListMembershipSuspensions404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// errUnexpected は応答の型に無い状態（実装の誤り）。
func errUnexpected(o outcome) error {
	return errs.New(errs.KindInternal, "unexpected admin outcome %d (%s)", o.status, o.body.Error)
}

func (s adminServer) LiftSuspension(ctx context.Context, req adminapi.LiftSuspensionRequestObject) (adminapi.LiftSuspensionResponseObject, error) {
	// 種別が分かるまでは一覧の権限で確かめ、権限の無い人に停止の有無を見せない。
	p, d, err := s.a.authorize(ctx, role.PermSuspensionsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.LiftSuspension401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.LiftSuspension403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.LiftSuspension400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var sp port.Suspension
	var sub subject
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if sp, err = tx.Suspensions().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		sub, err = s.subjectOf(ctx, tx, sp)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.LiftSuspension404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	if _, d, err = s.a.authorize(ctx, suspensionPerm(sp.Category)); err != nil {
		return nil, err
	} else if d != nil {
		return adminapi.LiftSuspension403JSONResponse(d.Body), nil
	}
	// 本人は自分の停止（ユーザーと Membership）を解除できない（4.7）。
	if p.Type == port.PrincipalUser && sub.userID != "" && p.ID == sub.userID {
		return adminapi.LiftSuspension403JSONResponse(adminError(errs.CodePermissionDenied, "cannot lift own suspension")), nil
	}
	var out adminapi.Suspension
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Suspensions().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if err := s.outranksUser(ctx, tx, p, sub); err != nil {
			return err
		}
		if cur, err = s.a.accounts.LiftSuspension(ctx, tx, s.a.realm.ID, cur, req.Body.Reason, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out = s.suspensionView(cur, sub)
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.LiftSuspension404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errOutranked):
		return adminapi.LiftSuspension403JSONResponse(adminError(errs.CodePermissionDenied, "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.LiftSuspension400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	if sub.userID != "" {
		s.a.sessions.Forget(ctx, s.a.realm.ID, sub.userID)
	}
	return adminapi.LiftSuspension200JSONResponse(out), nil
}

func (s adminServer) UpdateUser(ctx context.Context, req adminapi.UpdateUserRequestObject) (adminapi.UpdateUserResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersUpdate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.UpdateUser401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.UpdateUser403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.UpdateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var u port.User
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		if err := s.a.outranks(ctx, tx, p, u.ID); err != nil {
			return err
		}
		if u, err = s.a.accounts.SetValidity(ctx, tx, s.a.realm.ID, u, req.Body.ValidFrom, req.Body.ValidUntil, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		if !inValidity(u, s.a.deps.Clock.Now()) {
			return s.a.sessions.EndUserTx(ctx, tx, s.a.realm.ID, u.ID, session.ReasonValidity, requestID(ctx))
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.UpdateUser404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errOutranked):
		return adminapi.UpdateUser403JSONResponse(adminError(errs.CodePermissionDenied, "")), nil
	case errors.Is(err, account.ErrLastRealmOwner):
		return adminapi.UpdateUser409JSONResponse(adminError(errCode(err), "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.UpdateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Forget(ctx, s.a.realm.ID, u.ID)
	return adminapi.UpdateUser200JSONResponse(adminUser(u)), nil
}
