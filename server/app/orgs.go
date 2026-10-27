package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org と Membership（design.md 4.4、4.11、11.13、ADR 0055）。フィーチャー org が動いていなければ 404。

func myOrg(j org.Joined, activeOrgID string) publicapi.MyOrg {
	v := publicapi.MyOrg{Id: j.Org.PublicID, Kind: publicapi.MyOrgKind(j.Org.Kind), Role: publicapi.MyOrgRole(j.Membership.Role),
		MembershipId: j.Membership.PublicID, Active: j.Org.ID == activeOrgID}
	if j.Org.Name != "" {
		v.Name = &j.Org.Name
	}
	st := publicapi.MyOrgStatus(j.Membership.Status)
	v.Status = &st
	if j.Membership.ManagementRequestedAt != nil {
		v.ManagementRequested = new(true)
	}
	return v
}

func (s publicServer) ListMyOrgs(ctx context.Context, _ publicapi.ListMyOrgsRequestObject) (publicapi.ListMyOrgsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyOrgs401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.ListMyOrgs404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	}
	out := publicapi.ListMyOrgs200JSONResponse{Orgs: []publicapi.MyOrg{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		js, err := s.a.orgs.ListForUser(ctx, tx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		now := s.a.deps.Clock.Now()
		for _, j := range js {
			v := myOrg(j, au.ActiveOrgID)
			if org.IsManaged(u, j.Org) {
				v.Managed = new(true)
			}
			if j.Membership.Status == port.MembershipActive {
				_, err := org.Check(ctx, tx, j.Org, j.Membership, now)
				if d, ok := errors.AsType[errs.Denial](err); ok {
					reasons := d.Reasons()
					v.Unavailable = &reasons
				} else if err != nil {
					return err
				}
			}
			out.Orgs = append(out.Orgs, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s publicServer) CreateMyOrg(ctx context.Context, req publicapi.CreateMyOrgRequestObject) (publicapi.CreateMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CreateMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.CreateMyOrg404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	}
	if req.Body == nil {
		return publicapi.CreateMyOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var j org.Joined
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		j.Org, j.Membership, err = s.a.orgs.Create(ctx, tx, u, req.Body.Name, false, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, errs.Invalid):
		return publicapi.CreateMyOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.CreateMyOrg403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CreateMyOrg201JSONResponse(myOrg(j, au.ActiveOrgID)), nil
}

// ---------------------------------------------------------------------------

func orgView(o port.Org, ownerPublicID string) adminapi.Org {
	v := adminapi.Org{Id: o.PublicID, Kind: adminapi.OrgKind(o.Kind), CreatedAt: o.CreatedAt, ValidFrom: o.ValidFrom, ValidUntil: o.ValidUntil,
		DeletionScheduledAt: o.DeletionScheduledAt, DeletedAt: o.DeletedAt}
	if o.Name != "" {
		v.Name = &o.Name
	}
	if ownerPublicID != "" {
		v.PersonalOwnerId = &ownerPublicID
	}
	return v
}

// adminOrg は公開 ID の Org と、個人 Org の持ち主の公開 ID を返す。
func (s adminServer) adminOrg(ctx context.Context, tx port.Tx, publicID string) (port.Org, adminapi.Org, error) {
	o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, publicID)
	if err != nil {
		return port.Org{}, adminapi.Org{}, err
	}
	v, err := s.orgOut(ctx, tx, o)
	return o, v, err
}

// orgOut は Org の表示（個人 Org の持ち主と親の公開 ID を引く）。
func (s adminServer) orgOut(ctx context.Context, tx port.Tx, o port.Org) (adminapi.Org, error) {
	var owner string
	if o.Kind == port.OrgPersonal {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, o.PersonalOwnerID)
		if err != nil {
			return adminapi.Org{}, err
		}
		owner = u.PublicID
	}
	v := orgView(o, owner)
	if o.ParentID != "" {
		p, err := tx.Orgs().Get(ctx, s.a.realm.ID, o.ParentID)
		if err != nil {
			return adminapi.Org{}, err
		}
		v.ParentId = &p.PublicID
	}
	return v, nil
}

func (s adminServer) CreateOrg(ctx context.Context, req adminapi.CreateOrgRequestObject) (adminapi.CreateOrgResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermOrgsCreate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateOrg401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateOrg403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.CreateOrg404JSONResponse(adminError("org_disabled", "")), nil
	}
	if req.Body == nil {
		return adminapi.CreateOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var out adminapi.Org
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Body.OwnerId)
		if err != nil {
			return err
		}
		o, _, err := s.a.orgs.Create(ctx, tx, u, req.Body.Name, true, p.Actor, requestID(ctx))
		out = orgView(o, "")
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.CreateOrg404JSONResponse(adminError("not_found", "owner")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.CreateOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	return adminapi.CreateOrg201JSONResponse(out), nil
}

func (s adminServer) GetOrg(ctx context.Context, req adminapi.GetOrgRequestObject) (adminapi.GetOrgResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.GetOrg401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.GetOrg403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.GetOrg404JSONResponse(adminError("org_disabled", "")), nil
	}
	var out adminapi.Org
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		_, out, err = s.adminOrg(ctx, tx, req.Id)
		return err
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.GetOrg404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	return adminapi.GetOrg200JSONResponse(out), nil
}

func (s adminServer) ListOrgMemberships(ctx context.Context, req adminapi.ListOrgMembershipsRequestObject) (adminapi.ListOrgMembershipsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListOrgMemberships401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.ListOrgMemberships403JSONResponse(d.Body), nil
	}
	if s.a.orgs == nil {
		return adminapi.ListOrgMemberships404JSONResponse(adminError("org_disabled", "")), nil
	}
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 200 {
		return adminapi.ListOrgMemberships400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", "limit must be within [1, 200]"))}, nil
	}
	out := adminapi.ListOrgMemberships200JSONResponse{Memberships: []adminapi.Membership{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.adminOrg(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		// 1件多く取り、続きがあるかを知る。
		ms, err := tx.Memberships().ListByOrg(ctx, s.a.realm.ID, o.ID, deref(req.Params.After), limit+1)
		if err != nil {
			return err
		}
		if len(ms) > limit {
			ms = ms[:limit]
			next := ms[limit-1].PublicID
			out.NextCursor = &next
		}
		for _, m := range ms {
			u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
			if err != nil {
				return err
			}
			out.Memberships = append(out.Memberships, membershipView(m, u.PublicID, o.PublicID))
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.ListOrgMemberships404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func membershipView(m port.Membership, userPublicID, orgPublicID string) adminapi.Membership {
	v := adminapi.Membership{Id: m.PublicID, UserId: userPublicID, OrgId: orgPublicID, Status: adminapi.MembershipStatus(m.Status),
		Role: adminapi.MembershipRole(m.Role), ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil, CreatedAt: m.CreatedAt}
	if m.EndedReason != "" {
		v.EndedReason = &m.EndedReason
	}
	return v
}

// updateValidity は運営者による Org・Membership の有効期間の変更の共通部分（4.8）。
func (s adminServer) updateValidity(ctx context.Context, body *adminapi.Validity, change func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	if body == nil {
		return failed(http.StatusBadRequest, "invalid_request"), nil
	}
	p, d, err := s.a.authorize(ctx, role.PermOrgsUpdate)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.orgsOff(true); off {
		return o, nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return change(ctx, tx, p) })
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) UpdateOrg(ctx context.Context, req adminapi.UpdateOrgRequestObject) (adminapi.UpdateOrgResponseObject, error) {
	var out adminapi.Org
	o, err := s.updateValidity(ctx, req.Body, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		cur, _, err := s.adminOrg(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		if cur, err = s.a.orgs.SetOrgValidity(ctx, tx, cur, req.Body.ValidFrom, req.Body.ValidUntil, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out, err = s.orgOut(ctx, tx, cur)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateOrg200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateOrg400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateOrg401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateOrg403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateOrg404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateOrg409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateMembership(ctx context.Context, req adminapi.UpdateMembershipRequestObject) (adminapi.UpdateMembershipResponseObject, error) {
	var out adminapi.Membership
	var userID string
	o, err := s.updateValidity(ctx, req.Body, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		m, err := tx.Memberships().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		og, err := tx.Orgs().Get(ctx, s.a.realm.ID, m.OrgID)
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
		if err != nil {
			return err
		}
		if m, err = s.a.orgs.SetMembershipValidity(ctx, tx, og, m, req.Body.ValidFrom, req.Body.ValidUntil, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		userID, out = u.ID, membershipView(m, u.PublicID, og.PublicID)
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		s.a.sessions.Forget(ctx, s.a.realm.ID, userID)
		return adminapi.UpdateMembership200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateMembership400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateMembership401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateMembership403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateMembership404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateMembership409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// ---------------------------------------------------------------------------
// 招待とメンバー（4.4）。Org の中の操作は、その Org の使える Membership と、authz の判定（org_role と Org の範囲の付与）で決める。

// errOrgPermission は org_role に権限が無いこと。
var errOrgPermission = errs.WithCode(errs.KindPermissionDenied, errs.CodePermissionDenied, "org permission denied")

// orgUnavailable は Org か Membership が停止中か有効期間の外であること（4.7、4.8）。理由を返す（4.9）。
type orgUnavailable struct{ errs.Denial }

func (orgUnavailable) Is(target error) bool { return target == errs.PermissionDenied }

// orgDenied は Org の操作の拒否の応答。停止などは理由を返す。
func orgDenied(err error) publicapi.DeniedJSONResponse {
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return denied(d)
	}
	return publicapi.DeniedJSONResponse{Error: errCode(err)}
}

// orgMember は本人の、公開 ID の Org と active な Membership を返す。perm が空でなければ、その権限が要る。
// 所属していない Org は無いものとして扱う（errs.NotFound）。Org か Membership が使えなければ orgUnavailable。
func (s publicServer) orgMember(ctx context.Context, tx port.Tx, au auth, orgPublicID, perm string) (port.Org, port.Membership, error) {
	o, m, err := s.membership(ctx, tx, au, orgPublicID)
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	if _, err := org.Check(ctx, tx, o, m, s.a.deps.Clock.Now()); err != nil {
		if d, ok := errors.AsType[errs.Denial](err); ok {
			err = orgUnavailable{d}
		}
		return port.Org{}, port.Membership{}, err
	}
	if perm != "" {
		// org_role の組み込みのロールと、Org の範囲の付与（Group を含む）から判定する（ADR 0064）。
		ok, err := s.a.authz.CheckTx(ctx, tx, s.a.realm.ID, check.Request{Principal: check.Principal{Type: port.PrincipalUser, ID: au.PrincipalID},
			Action: perm, OrgID: o.ID})
		if err != nil {
			return port.Org{}, port.Membership{}, err
		}
		if !ok {
			return port.Org{}, port.Membership{}, errOrgPermission
		}
	}
	return o, m, nil
}

// membership は本人の、公開 ID の Org と active な Membership を返す。使えるか（停止・有効期間）は見ない。
func (s publicServer) membership(ctx context.Context, tx port.Tx, au auth, orgPublicID string) (port.Org, port.Membership, error) {
	o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, orgPublicID)
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	m, err := tx.Memberships().GetByUserOrg(ctx, s.a.realm.ID, au.PrincipalID, o.ID)
	if err == nil && m.Status != port.MembershipActive {
		err = errs.New(errs.KindNotFound, "membership")
	}
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	return o, m, nil
}

func orgInvitation(inv port.Invitation, email string, now time.Time) publicapi.OrgInvitation {
	st := publicapi.OrgInvitationStatus(inv.Status)
	if inv.Status == port.InvitationPending && !now.Before(inv.ExpiresAt) {
		st = "expired"
	}
	v := publicapi.OrgInvitation{Id: inv.PublicID, Role: publicapi.OrgInvitationRole(inv.Role), Status: st, ExpiresAt: inv.ExpiresAt, CreatedAt: inv.CreatedAt}
	if inv.Managed {
		v.Managed = new(true)
	}
	if email != "" && inv.Status == port.InvitationPending && now.Before(inv.ExpiresAt) {
		v.Email = &email
	}
	return v
}

func myOrgWithEmail(ctx context.Context, tx port.Tx, j org.Joined, activeOrgID string) (publicapi.MyOrg, error) {
	v := myOrg(j, activeOrgID)
	if j.Membership.EmailID != "" {
		e, err := org.BoundEmail(ctx, tx, j.Membership)
		if err != nil {
			return v, err
		}
		v.EmailId = &e.PublicID
	}
	return v, nil
}

func (s publicServer) ListOrgMembers(ctx context.Context, req publicapi.ListOrgMembersRequestObject) (publicapi.ListOrgMembersResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListOrgMembers401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.ListOrgMembers404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > 200 {
		return publicapi.ListOrgMembers400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	out := publicapi.ListOrgMembers200JSONResponse{Members: []publicapi.OrgMember{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgRemove)
		if err != nil {
			return err
		}
		ms, err := tx.Memberships().ListByOrg(ctx, s.a.realm.ID, o.ID, deref(req.Params.After), limit+1)
		if err != nil {
			return err
		}
		if len(ms) > limit {
			ms = ms[:limit]
			next := ms[limit-1].PublicID
			out.NextCursor = &next
		}
		for _, m := range ms {
			if m.Status == port.MembershipEnded {
				continue
			}
			v, err := s.orgMemberView(ctx, tx, m)
			if err != nil {
				return err
			}
			out.Members = append(out.Members, v)
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgMembers404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgMembers403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

// orgMemberView は Org の管理者に見せるメンバー。見せるメールは結び付けたものだけ（4.4）。
func (s publicServer) orgMemberView(ctx context.Context, tx port.Tx, m port.Membership) (publicapi.OrgMember, error) {
	u, err := tx.Users().Get(ctx, s.a.realm.ID, m.UserID)
	if err != nil {
		return publicapi.OrgMember{}, err
	}
	v := publicapi.OrgMember{MembershipId: m.PublicID, UserId: u.PublicID, Role: publicapi.OrgMemberRole(m.Role), Status: publicapi.OrgMemberStatus(m.Status),
		ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil}
	if u.ManagedOrgID != "" && u.ManagedOrgID == m.OrgID {
		v.Managed = new(true)
	}
	if m.ManagementRequestedAt != nil {
		v.ManagementRequested = new(true)
	}
	e, err := org.BoundEmail(ctx, tx, m)
	// 結び付けたメールが無いか、アドレスを保存しない構成（index_only。9.6）なら出さない。
	if errors.Is(err, errs.NotFound) || (err == nil && len(e.Ciphertext) == 0) {
		return v, nil
	}
	if err != nil {
		return publicapi.OrgMember{}, err
	}
	addr, err := s.a.accounts.EmailAddress(ctx, tx, e)
	if err != nil {
		return publicapi.OrgMember{}, err
	}
	if addr != "" {
		v.Email = &addr
	}
	return v, nil
}

func (s publicServer) ListOrgInvitations(ctx context.Context, req publicapi.ListOrgInvitationsRequestObject) (publicapi.ListOrgInvitationsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListOrgInvitations401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.ListOrgInvitations404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	now := s.a.deps.Clock.Now()
	out := publicapi.ListOrgInvitations200JSONResponse{Invitations: []publicapi.OrgInvitation{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgInvite)
		if err != nil {
			return err
		}
		invs, err := tx.Invitations().ListByOrg(ctx, s.a.realm.ID, o.ID)
		if err != nil {
			return err
		}
		for _, inv := range invs {
			email, err := s.a.orgs.InvitationEmail(ctx, tx, inv)
			if err != nil {
				return err
			}
			out.Invitations = append(out.Invitations, orgInvitation(inv, email, now))
		}
		return nil
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.ListOrgInvitations404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListOrgInvitations403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func (s publicServer) InviteToOrg(ctx context.Context, req publicapi.InviteToOrgRequestObject) (publicapi.InviteToOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.InviteToOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.InviteToOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.InviteToOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var out publicapi.OrgInvitation
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, m, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgInvite)
		if err != nil {
			return err
		}
		r := port.OrgRole(req.Body.Role)
		// owner として招けるのは owner だけ（下位の役割が上位の役割を作れないように）。
		if r == port.OrgOwner && m.Role != port.OrgOwner {
			return errOrgPermission
		}
		inv, err := s.a.orgs.Invite(ctx, tx, o, org.Invite{Email: req.Body.Email, Role: r, ValidFrom: req.Body.ValidFrom, ValidUntil: req.Body.ValidUntil,
			Managed: deref(req.Body.Managed)},
			au.Actor(), requestID(ctx))
		out = orgInvitation(inv.Invitation, inv.Email, s.a.deps.Clock.Now())
		return err
	})
	if c, ok := stateCode(err); ok {
		return publicapi.InviteToOrg409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.InviteToOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.InviteToOrg403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.InviteToOrg400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.InviteToOrg201JSONResponse(out), nil
}

func (s publicServer) RevokeOrgInvitation(ctx context.Context, req publicapi.RevokeOrgInvitationRequestObject) (publicapi.RevokeOrgInvitationResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RevokeOrgInvitation401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.RevokeOrgInvitation404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgInvite)
		if err != nil {
			return err
		}
		return s.a.orgs.Revoke(ctx, tx, o, req.InvitationId, au.Actor(), requestID(ctx))
	})
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.RevokeOrgInvitation404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: errCodeOr(err, "not_found")}}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.RevokeOrgInvitation403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.RevokeOrgInvitation204Response{}, nil
}

func (s publicServer) BindMyOrgEmail(ctx context.Context, req publicapi.BindMyOrgEmailRequestObject) (publicapi.BindMyOrgEmailResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.BindMyOrgEmail401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.BindMyOrgEmail404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var emailID string
	if req.Body != nil {
		emailID = deref(req.Body.EmailId)
	}
	var out publicapi.MyOrg
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		j, err := s.a.orgs.BindEmail(ctx, tx, u, req.Id, emailID, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = myOrgWithEmail(ctx, tx, j, au.ActiveOrgID)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.BindMyOrgEmail404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.BindMyOrgEmail409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.BindMyOrgEmail200JSONResponse(out), nil
}

func (s publicServer) AcceptInvitation(ctx context.Context, req publicapi.AcceptInvitationRequestObject) (publicapi.AcceptInvitationResponseObject, error) {
	if s.a.orgs == nil {
		return publicapi.AcceptInvitation404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.AcceptInvitation400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	au, signedIn := authFrom(ctx)
	c := s.a.clientOf(ctx)
	var replace string
	if tok, viaCookie := s.a.sessionToken(httpFrom(ctx).r); viaCookie {
		replace = tok
	}
	var out publicapi.AcceptInvitation200JSONResponse
	var issued *session.Issued
	var userPublicID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var u *port.User
		if signedIn {
			x, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
			if err != nil {
				return err
			}
			u = &x
		}
		acc, err := s.a.orgs.Accept(ctx, tx, s.a.realm.ID, req.Body.Token, u, c.RequestID)
		if err != nil {
			return err
		}
		active := au.ActiveOrgID
		if acc.Created != nil {
			// 招待からの登録：招待された Org に入ったセッションを発行する。
			in := session.Issue{
				RealmID: s.a.realm.ID, UserID: acc.Created.User.ID, AuthMethods: []string{"otp"}, Credentials: []string{acc.Created.Email.ID},
				IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, ReplaceToken: replace, OrgID: acc.Joined.Org.ID,
			}
			is, err := s.a.sessions.Issue(ctx, tx, in)
			if _, ok := errors.AsType[*account.UnavailableError](err); ok {
				// 招待された Org のログインポリシー（passkey 必須など）を満たさなければ、参加は済ませて個人 Org に入る。
				in.OrgID = ""
				is, err = s.a.sessions.Issue(ctx, tx, in)
			}
			if err != nil {
				return err
			}
			issued, userPublicID, active = &is, acc.Created.User.PublicID, is.Session.ActiveOrgID
		}
		out.Org, err = myOrgWithEmail(ctx, tx, acc.Joined, active)
		return err
	})
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.AcceptInvitation403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.AcceptInvitation409JSONResponse{ConflictJSONResponse: conflictOf(err, code)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.AcceptInvitation404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: errCodeOr(err, "not_found")}}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.AcceptInvitation400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	if issued != nil {
		s.a.sessions.Committed(ctx, s.a.realm.ID, *issued)
		login := s.loginResult(ctx, *issued, userPublicID, true, req.Body.ReturnToken)
		out.Login = &login
	}
	return out, nil
}

func errCodeOr(err error, fallback string) string {
	if c := errCode(err); c != "" {
		return c
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Org の切り替え（4.4）

func (s publicServer) SwitchMyOrg(ctx context.Context, req publicapi.SwitchMyOrgRequestObject) (publicapi.SwitchMyOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.SwitchMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.SwitchMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var orgID string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		orgID = o.ID
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return publicapi.SwitchMyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	is, err := s.a.sessions.SwitchOrg(ctx, s.a.realm.ID, au.SessionID, orgID, s.a.clientOf(ctx).IP, requestID(ctx))
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.SwitchMyOrg403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, org.ErrNoAvailableOrg):
		return publicapi.SwitchMyOrg403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse{Error: errs.CodeNoAvailableOrg}}, nil
	case errors.Is(err, session.ErrReauthRequired):
		// 切り替え先の Org の寿命を超えている（5.4）。再認証のログインで、その Org を指定して入り直す。
		return publicapi.SwitchMyOrg401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: session.CodeReauthRequired}}, nil
	case errors.Is(err, errs.Unauthenticated), errors.Is(err, errs.NotFound):
		return publicapi.SwitchMyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case err != nil:
		return nil, err
	}
	// Bearer のセッションは古いトークンがすぐ使えなくなるため、新しいトークンを必ず返す。
	returnToken := !au.viaCookie
	if req.Body != nil && deref(req.Body.ReturnToken) {
		returnToken = true
	}
	return publicapi.SwitchMyOrg200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, &returnToken)), nil
}

func (s publicServer) SetMyPasskeyOrg(ctx context.Context, req publicapi.SetMyPasskeyOrgRequestObject) (publicapi.SetMyPasskeyOrgResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.SetMyPasskeyOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.orgs == nil {
		return publicapi.SetMyPasskeyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var orgPublicID string
	if req.Body != nil {
		orgPublicID = deref(req.Body.OrgId)
	}
	nf, _, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		p, err := tx.Passkeys().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err == nil && (p.UserID != au.PrincipalID || p.RevokedAt != nil) {
			err = errs.New(errs.KindNotFound, "passkey")
		}
		if err != nil {
			return err
		}
		var orgID string
		if orgPublicID != "" {
			// 停止中の Org も既定にできる（ログインでは使える Org だけを候補にする）。
			o, _, err := s.membership(ctx, tx, au, orgPublicID)
			if err != nil {
				return err
			}
			orgID = o.ID
		}
		return tx.Passkeys().SetPreferredOrg(ctx, s.a.realm.ID, p.ID, orgID)
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.SetMyPasskeyOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := publicapi.SetMyPasskeyOrg200JSONResponse{}
	if orgPublicID != "" {
		out.OrgId = &orgPublicID
	}
	return out, nil
}
