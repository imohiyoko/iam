package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/account"
	dirldap "github.com/imohiyoko/iam/authn/method/ldap"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 管理 API の一覧・取得・検索と、運営者によるメールの操作（ADR 0097）。
//
// 既存の管理 API の拡張なので、フィーチャーにしない。権限は運営者ロールに足した読み取りの権限（users:read など）で確かめる。
// 応答には公開 ID だけを出す（ADR 0045）。メールアドレスは pii:read を持つ呼び出し側が求めたときだけ復号し、監査ログに残す。
// 読み取りは、既存の参照（Org・停止・認証情報の一覧）と同じく監査ログに残さない。

// errSearchEmpty は検索の条件に合うものが無いと先に分かったこと（無い Org・connection・アドレス）。空の一覧を返す。
var errSearchEmpty = errors.New("search matches nothing")

// errConnectionOwned は Org 専用 SSO の connection を運営者が変えようとしたこと（Org の owner が扱う。ADR 0077）。
var errConnectionOwned = errs.WithCode(errs.KindFailedPrecondition, "org_connection", "the connection belongs to an org")

// pageLimit は一覧の件数（既定 100、1〜200）。範囲の外なら ok が偽。
func pageLimit(p *int) (int, bool) {
	n := 100
	if p != nil {
		n = *p
	}
	return n, n >= 1 && n <= 200
}

// ---------------------------------------------------------------------------
// ユーザー

// suspendedNow はユーザーが今停止中かを返す。
func (s adminServer) suspendedNow(ctx context.Context, tx port.Tx, u port.User) (bool, []port.Suspension, error) {
	ss, err := tx.Suspensions().ListByTarget(ctx, s.a.realm.ID, port.SuspensionTargetUser, u.ID)
	if err != nil {
		return false, nil, err
	}
	now := s.a.deps.Clock.Now()
	for _, sp := range ss {
		end := sp.EndsAt
		if sp.LiftedAt != nil && (end == nil || sp.LiftedAt.Before(*end)) {
			end = sp.LiftedAt
		}
		if !sp.StartsAt.After(now) && (end == nil || end.After(now)) {
			return true, ss, nil
		}
	}
	return false, ss, nil
}

// orgPublicID は Org の内部 ID を公開 ID にする。空か、消えた Org なら空。
func (s adminServer) orgPublicID(ctx context.Context, tx port.Tx, orgID string) (string, error) {
	if orgID == "" {
		return "", nil
	}
	o, err := tx.Orgs().Get(ctx, s.a.realm.ID, orgID)
	if errors.Is(err, errs.NotFound) {
		return "", nil
	}
	return o.PublicID, err
}

func optString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func (s adminServer) userSummary(ctx context.Context, tx port.Tx, u port.User) (adminapi.AdminUserSummary, error) {
	suspended, _, err := s.suspendedNow(ctx, tx, u)
	if err != nil {
		return adminapi.AdminUserSummary{}, err
	}
	managed, err := s.orgPublicID(ctx, tx, u.ManagedOrgID)
	if err != nil {
		return adminapi.AdminUserSummary{}, err
	}
	v := adminapi.AdminUserSummary{Id: u.PublicID, Status: adminapi.AdminUserSummaryStatus(u.Status), Suspended: suspended, ValidFrom: u.ValidFrom,
		ValidUntil: u.ValidUntil, DeletionScheduledAt: u.DeletionScheduledAt, ManagedByOrgId: optString(managed), CreatedAt: u.CreatedAt}
	if u.LegalHold {
		v.LegalHold = &u.LegalHold
	}
	return v, nil
}

// userSearch は API の絞り込みを Storage の絞り込みにする。条件に合うものが無いと分かれば errSearchEmpty。
func (s adminServer) userSearch(ctx context.Context, tx port.Tx, q adminapi.ListUsersParams, limit int) (port.UserSearch, error) {
	f := port.UserSearch{Now: s.a.deps.Clock.Now(), After: deref(q.After), Limit: limit, CreatedFrom: q.CreatedFrom, CreatedBefore: q.CreatedBefore}
	if q.Email != nil {
		addr, err := account.NormalizeEmail(*q.Email)
		if err != nil {
			return f, err
		}
		// ブラインドインデックスで引く完全一致（9.5）。アドレスは復号しない。
		e, err := s.a.accounts.FindByEmail(ctx, tx, s.a.realm.ID, addr)
		if errors.Is(err, errs.NotFound) {
			return f, errSearchEmpty
		}
		if err != nil {
			return f, err
		}
		f.UserID = e.UserID
	}
	if q.Connection != nil {
		c, err := tx.Connections().GetBySlug(ctx, s.a.realm.ID, *q.Connection)
		if errors.Is(err, errs.NotFound) {
			return f, errSearchEmpty
		}
		if err != nil {
			return f, err
		}
		i, err := tx.Identities().GetBySubject(ctx, s.a.realm.ID, c.ID, *q.Subject)
		if errors.Is(err, errs.NotFound) || (err == nil && f.UserID != "" && f.UserID != i.UserID) {
			return f, errSearchEmpty
		}
		if err != nil {
			return f, err
		}
		f.UserID = i.UserID
	}
	if q.OrgId != nil {
		o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *q.OrgId)
		if errors.Is(err, errs.NotFound) {
			return f, errSearchEmpty
		}
		if err != nil {
			return f, err
		}
		f.OrgID = o.ID
	}
	if q.Status != nil {
		switch *q.Status {
		case "active":
			f.Status, f.Suspended = port.UserActive, port.TriNo
		case "suspended":
			f.Status, f.Suspended = port.UserActive, port.TriYes
		case "deleted":
			f.Status = port.UserDeleted
		case "merged":
			f.Status = port.UserMerged
		default:
			return f, errs.WithCode(errs.KindInvalid, "invalid_request", "unknown status")
		}
	}
	return f, nil
}

func (s adminServer) ListUsers(ctx context.Context, req adminapi.ListUsersRequestObject) (adminapi.ListUsersResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermUsersRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		q := req.Params
		limit, valid := pageLimit(q.Limit)
		switch {
		case !valid:
			o = failed(http.StatusBadRequest, "invalid_request")
			o.body.Message = ptrTo("limit must be within [1, 200]")
		case (q.Connection == nil) != (q.Subject == nil):
			o = failed(http.StatusBadRequest, "invalid_request")
			o.body.Message = ptrTo("connection and subject go together")
		default:
			out := adminapi.ListUsers200JSONResponse{Users: []adminapi.AdminUserSummary{}}
			err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				f, err := s.userSearch(ctx, tx, q, limit+1)
				if err != nil {
					return err
				}
				// 1件多く取り、続きがあるかを知る。
				us, err := tx.Users().Search(ctx, s.a.realm.ID, f)
				if err != nil {
					return err
				}
				if len(us) > limit {
					us = us[:limit]
					out.NextCursor = &us[limit-1].PublicID
				}
				for _, u := range us {
					v, err := s.userSummary(ctx, tx, u)
					if err != nil {
						return err
					}
					out.Users = append(out.Users, v)
				}
				return nil
			})
			if errors.Is(err, errSearchEmpty) {
				return out, nil
			}
			if o, ok, err = outcomeOf(nil, err); ok {
				return out, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusBadRequest:
		return adminapi.ListUsers400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusUnauthorized:
		return adminapi.ListUsers401JSONResponse(o.body), nil
	case http.StatusForbidden:
		return adminapi.ListUsers403JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func ptrTo[T any](v T) *T { return &v }

// emailOut はメールの表示。reveal ならアドレスを復号する（最小化モードでは持たない）。
func (s adminServer) emailOut(ctx context.Context, tx port.Tx, e port.UserEmail, reveal bool) (adminapi.AdminUserEmail, bool, error) {
	v := adminapi.AdminUserEmail{Id: e.PublicID, Primary: e.IsPrimary, Verified: e.VerifiedAt != nil, CreatedAt: e.CreatedAt}
	if e.VerifiedVia != "" {
		v.VerifiedVia = ptrTo(adminapi.AdminUserEmailVerifiedVia(e.VerifiedVia))
	}
	if !reveal || len(e.Ciphertext) == 0 {
		return v, false, nil
	}
	addr, err := s.a.accounts.EmailAddress(ctx, tx, e)
	if err != nil {
		return v, false, err
	}
	v.Email = &addr
	return v, true, nil
}

func (s adminServer) userDetail(ctx context.Context, tx port.Tx, u port.User, reveal bool) (adminapi.AdminUserDetail, bool, error) {
	var revealed bool
	suspended, ss, err := s.suspendedNow(ctx, tx, u)
	if err != nil {
		return adminapi.AdminUserDetail{}, false, err
	}
	managed, err := s.orgPublicID(ctx, tx, u.ManagedOrgID)
	if err != nil {
		return adminapi.AdminUserDetail{}, false, err
	}
	v := adminapi.AdminUserDetail{Id: u.PublicID, Status: adminapi.AdminUserDetailStatus(u.Status), Suspended: suspended, ValidFrom: u.ValidFrom,
		ValidUntil: u.ValidUntil, DeletionScheduledAt: u.DeletionScheduledAt, ManagedByOrgId: optString(managed), CreatedAt: u.CreatedAt,
		Emails: []adminapi.AdminUserEmail{}, Suspensions: []adminapi.Suspension{}}
	if u.LegalHold {
		v.LegalHold = &u.LegalHold
	}
	if u.MergedInto != "" {
		into, err := tx.Users().Get(ctx, s.a.realm.ID, u.MergedInto)
		if err != nil && !errors.Is(err, errs.NotFound) {
			return v, false, err
		}
		v.MergedInto = optString(into.PublicID)
	}
	m, err := s.a.accounts.ListMethods(ctx, tx, s.a.realm.ID, u.ID)
	if err != nil {
		return v, false, err
	}
	for _, e := range m.Emails {
		ev, ok, err := s.emailOut(ctx, tx, e, reveal)
		if err != nil {
			return v, false, err
		}
		revealed = revealed || ok
		v.Emails = append(v.Emails, ev)
	}
	if v.Credentials, err = s.credentialsOut(ctx, tx, m); err != nil {
		return v, false, err
	}
	codes, err := tx.RecoveryCodes().ListByUser(ctx, s.a.realm.ID, u.ID)
	if err != nil {
		return v, false, err
	}
	remaining := 0
	for _, c := range codes {
		if c.UsedAt == nil {
			remaining++
		}
	}
	v.RecoveryCodesRemaining = &remaining
	sub := subject{target: account.UserTarget(u), userID: u.ID, userPublicID: u.PublicID}
	for _, sp := range ss {
		v.Suspensions = append(v.Suspensions, s.suspensionView(sp, sub))
	}
	if s.a.orgs != nil {
		ms, err := s.membershipsOut(ctx, tx, u)
		if err != nil {
			return v, false, err
		}
		v.Memberships = &ms
	}
	return v, revealed, nil
}

func (s adminServer) membershipsOut(ctx context.Context, tx port.Tx, u port.User) ([]adminapi.Membership, error) {
	ms, err := tx.Memberships().ListByUser(ctx, s.a.realm.ID, u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]adminapi.Membership, 0, len(ms))
	for _, m := range ms {
		o, err := s.orgPublicID(ctx, tx, m.OrgID)
		if err != nil {
			return nil, err
		}
		out = append(out, membershipView(m, u.PublicID, o))
	}
	return out, nil
}

func (s adminServer) GetUser(ctx context.Context, req adminapi.GetUserRequestObject) (adminapi.GetUserResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersRead)
	o, ok, err := outcomeOf(d, err)
	reveal := deref(req.Params.IncludePii)
	if ok && reveal {
		// アドレスの復号は独立した権限（4.11、ADR 0023）。
		_, d, err = s.a.authorize(ctx, role.PermPIIRead)
		o, ok, err = outcomeOf(d, err)
	}
	if ok {
		var out adminapi.AdminUserDetail
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			var revealed bool
			if out, revealed, err = s.userDetail(ctx, tx, u, reveal); err != nil || !revealed {
				return err
			}
			_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "user.pii_read", Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
				Actor: p.Actor, RequestID: requestID(ctx), Details: map[string]any{"user_id": u.PublicID, "fields": []string{"email"}}})
			return err
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.GetUser200JSONResponse(out), nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.GetUser401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.GetUser403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.GetUser404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) ListUserMemberships(ctx context.Context, req adminapi.ListUserMembershipsRequestObject) (adminapi.ListUserMembershipsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermUsersRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		var off bool
		if o, off = s.orgsOff(true); !off {
			var out []adminapi.Membership
			err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
				if err != nil {
					return err
				}
				out, err = s.membershipsOut(ctx, tx, u)
				return err
			})
			if o, ok, err = outcomeOf(nil, err); ok {
				return adminapi.ListUserMemberships200JSONResponse{Memberships: out}, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.ListUserMemberships401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListUserMemberships403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListUserMemberships404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// セッション

func (s adminServer) ListUserSessions(ctx context.Context, req adminapi.ListUserSessionsRequestObject) (adminapi.ListUserSessionsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermSessionsRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		out := []adminapi.AdminSession{}
		var u port.User
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) (err error) {
			u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			return err
		})
		var list []port.Session
		if err == nil {
			// 有効なものだけ（本人の一覧と同じ判定）。
			list, err = s.a.sessions.List(ctx, s.a.realm.ID, u.ID)
		}
		if err == nil {
			err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				for _, x := range list {
					v := adminapi.AdminSession{Id: x.ID, AuthenticatedAt: x.AuthenticatedAt, CreatedAt: x.CreatedAt, LastSeenAt: x.LastSeenAt,
						ExpiresAt: x.ExpiresAt, AuthMethods: append([]string{}, x.AuthMethods...), Restriction: optString(string(x.Restriction))}
					oid, err := s.orgPublicID(ctx, tx, x.ActiveOrgID)
					if err != nil {
						return err
					}
					v.ActiveOrgId = optString(oid)
					out = append(out, v)
				}
				return nil
			})
		}
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.ListUserSessions200JSONResponse{Sessions: out}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.ListUserSessions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListUserSessions403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListUserSessions404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// RevokeAllUserSessions は全セッションの失効。認証情報は残す（credentials:revoke-all との違い）。セッションの失効はなりすましに
// ならないので、個別の失効（sessions/{id}:revoke）と同じく outranks の判定はしない。
func (s adminServer) RevokeAllUserSessions(ctx context.Context, req adminapi.RevokeAllUserSessionsRequestObject) (adminapi.RevokeAllUserSessionsResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermSessionsRevoke)
	o, ok, err := outcomeOf(d, err)
	if ok {
		var revoked []string
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			revoked, err = s.revokeUserSessions(ctx, tx, u.ID, p)
			return err
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, revoked)
			return adminapi.RevokeAllUserSessions200JSONResponse{Sessions: len(revoked)}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.RevokeAllUserSessions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.RevokeAllUserSessions403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.RevokeAllUserSessions404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// 付与と所属の逆引き

// principalByPublicID は逆引きの主体（ユーザーは公開 ID、サービスアカウントは ID）の内部 ID を返す。
func (s adminServer) principalByPublicID(ctx context.Context, tx port.Tx, t port.PrincipalType, publicID string) (string, error) {
	if t == port.PrincipalUser {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID)
		return u.ID, err
	}
	sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, publicID)
	return sa.ID, err
}

// effectiveBindings は主体に効く付与（直接の付与と Group の付与）を返す。判定と同じ材料（ListEffective）を使う。
func (s adminServer) effectiveBindings(ctx context.Context, t port.PrincipalType, publicID string) ([]adminapi.EffectiveRoleBinding, outcome, error) {
	_, d, err := s.a.authorize(ctx, role.PermRolesRead)
	if o, ok, err := outcomeOf(d, err); !ok {
		return nil, o, err
	}
	out := []adminapi.EffectiveRoleBinding{}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		pid, err := s.principalByPublicID(ctx, tx, t, publicID)
		if err != nil {
			return err
		}
		bs, err := tx.RoleBindings().ListEffective(ctx, s.a.realm.ID, t, pid, s.a.authz.NestedGroups)
		if err != nil {
			return err
		}
		for _, b := range bs {
			name, err := manage.DisplayRole(ctx, tx, b.RealmID, b.Role)
			if err != nil && !errors.Is(err, errs.NotFound) {
				return err
			}
			principal, err := principalPublicID(ctx, tx, b.RealmID, b.PrincipalType, b.PrincipalID)
			if err != nil {
				return err
			}
			orgID, err := s.orgPublicID(ctx, tx, b.OrgID)
			if err != nil {
				return err
			}
			v := adminapi.EffectiveRoleBinding{Id: b.PublicID, Role: name, PrincipalType: string(b.PrincipalType), PrincipalId: principal,
				OrgId: optString(orgID), ResourceType: optString(b.ResourceType), ResourceId: optString(b.ResourceID),
				Condition: conditionOut(b.Condition), CreatedAt: b.CreatedAt}
			if b.PrincipalType == port.PrincipalGroup {
				v.ViaGroupId = optString(principal)
			}
			out = append(out, v)
		}
		return nil
	})
	o, _, err := outcomeOf(nil, err)
	if err == nil && o.status == 0 {
		o.status = http.StatusOK
	}
	return out, o, err
}

// principalGroups は主体が所属する Group（realm と Org の範囲）を名前の順に返す。ネストなら、含む Group も返す（direct が偽）。
func (s adminServer) principalGroups(ctx context.Context, t port.PrincipalType, publicID string) ([]adminapi.PrincipalGroup, outcome, error) {
	_, d, err := s.a.authorize(ctx, role.PermGroupsRead)
	if o, ok, err := outcomeOf(d, err); !ok {
		return nil, o, err
	}
	out := []adminapi.PrincipalGroup{}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		pid, err := s.principalByPublicID(ctx, tx, t, publicID)
		if err != nil {
			return err
		}
		gs, err := tx.Groups().ListByMember(ctx, s.a.realm.ID, t, pid)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		add := func(g port.Group, direct bool) error {
			seen[g.ID] = true
			orgID, err := s.orgPublicID(ctx, tx, g.OrgID)
			if err != nil {
				return err
			}
			out = append(out, adminapi.PrincipalGroup{Id: g.PublicID, Name: g.Name, OrgId: optString(orgID), Direct: direct, CreatedAt: g.CreatedAt})
			return nil
		}
		for _, g := range gs {
			if !seen[g.ID] {
				if err := add(g, true); err != nil {
					return err
				}
			}
		}
		if s.a.authz.NestedGroups {
			for _, g := range gs {
				ls, err := tx.Groups().Ancestors(ctx, s.a.realm.ID, g.ID)
				if err != nil {
					return err
				}
				for _, l := range ls {
					if seen[l.GroupID] {
						continue
					}
					a, err := tx.Groups().Get(ctx, s.a.realm.ID, l.GroupID)
					if errors.Is(err, errs.NotFound) {
						continue
					}
					if err != nil {
						return err
					}
					if err := add(a, false); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	slices.SortStableFunc(out, func(x, y adminapi.PrincipalGroup) int { return strings.Compare(x.Name, y.Name) })
	o, _, err := outcomeOf(nil, err)
	if err == nil && o.status == 0 {
		o.status = http.StatusOK
	}
	return out, o, err
}

func (s adminServer) ListUserRoleBindings(ctx context.Context, req adminapi.ListUserRoleBindingsRequestObject) (adminapi.ListUserRoleBindingsResponseObject, error) {
	out, o, err := s.effectiveBindings(ctx, port.PrincipalUser, req.Id)
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.ListUserRoleBindings200JSONResponse{Bindings: out}, nil
	case http.StatusUnauthorized:
		return adminapi.ListUserRoleBindings401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListUserRoleBindings403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListUserRoleBindings404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) ListServiceAccountRoleBindings(ctx context.Context, req adminapi.ListServiceAccountRoleBindingsRequestObject) (adminapi.ListServiceAccountRoleBindingsResponseObject, error) {
	out, o, err := s.effectiveBindings(ctx, port.PrincipalServiceAccount, req.Id)
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.ListServiceAccountRoleBindings200JSONResponse{Bindings: out}, nil
	case http.StatusUnauthorized:
		return adminapi.ListServiceAccountRoleBindings401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListServiceAccountRoleBindings403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListServiceAccountRoleBindings404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) ListUserGroups(ctx context.Context, req adminapi.ListUserGroupsRequestObject) (adminapi.ListUserGroupsResponseObject, error) {
	out, o, err := s.principalGroups(ctx, port.PrincipalUser, req.Id)
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.ListUserGroups200JSONResponse{Groups: out}, nil
	case http.StatusUnauthorized:
		return adminapi.ListUserGroups401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListUserGroups403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListUserGroups404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) ListServiceAccountGroups(ctx context.Context, req adminapi.ListServiceAccountGroupsRequestObject) (adminapi.ListServiceAccountGroupsResponseObject, error) {
	out, o, err := s.principalGroups(ctx, port.PrincipalServiceAccount, req.Id)
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.ListServiceAccountGroups200JSONResponse{Groups: out}, nil
	case http.StatusUnauthorized:
		return adminapi.ListServiceAccountGroups401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListServiceAccountGroups403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListServiceAccountGroups404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// Org

func (s adminServer) ListOrgs(ctx context.Context, req adminapi.ListOrgsRequestObject) (adminapi.ListOrgsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermOrgsRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		q := req.Params
		limit, valid := pageLimit(q.Limit)
		var off bool
		o, off = s.orgsOff(true)
		knownStatus := q.Status == nil || slices.Contains([]string{"active", "suspended", "deleted"}, string(*q.Status))
		switch {
		case off:
		case !knownStatus:
			o = failed(http.StatusBadRequest, "invalid_request")
			o.body.Message = ptrTo("unknown status")
		case !valid || len(deref(q.NamePrefix)) > 400:
			o = failed(http.StatusBadRequest, "invalid_request")
			o.body.Message = ptrTo("limit must be within [1, 200] and name_prefix at most 400 bytes")
		default:
			out := adminapi.ListOrgs200JSONResponse{Orgs: []adminapi.Org{}}
			f := port.OrgSearch{Now: s.a.deps.Clock.Now(), After: deref(q.After), NamePrefix: deref(q.NamePrefix), Limit: limit + 1}
			if q.Kind != nil {
				f.Kind = port.OrgKind(*q.Kind)
			}
			if q.Status != nil {
				switch *q.Status {
				case "active":
					f.Deleted, f.Suspended = port.TriNo, port.TriNo
				case "suspended":
					f.Deleted, f.Suspended = port.TriNo, port.TriYes
				case "deleted":
					f.Deleted = port.TriYes
				}
			}
			err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				if q.ParentId != nil {
					p, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *q.ParentId)
					if errors.Is(err, errs.NotFound) {
						return errSearchEmpty
					}
					if err != nil {
						return err
					}
					f.ParentID = p.ID
				}
				os, err := tx.Orgs().Search(ctx, s.a.realm.ID, f)
				if err != nil {
					return err
				}
				if len(os) > limit {
					os = os[:limit]
					out.NextCursor = &os[limit-1].PublicID
				}
				for _, o := range os {
					v, err := s.orgOut(ctx, tx, o)
					if err != nil {
						return err
					}
					out.Orgs = append(out.Orgs, v)
				}
				return nil
			})
			if errors.Is(err, errSearchEmpty) {
				return out, nil
			}
			if o, ok, err = outcomeOf(nil, err); ok {
				return out, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusBadRequest:
		return adminapi.ListOrgs400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusUnauthorized:
		return adminapi.ListOrgs401JSONResponse(o.body), nil
	case http.StatusForbidden:
		return adminapi.ListOrgs403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.ListOrgs404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// IdP 接続

func (s adminServer) connectionOut(ctx context.Context, tx port.Tx, c port.Connection) (adminapi.AdminConnection, error) {
	v := adminapi.AdminConnection{Id: c.ID, Slug: c.Slug, Type: c.Type, Scopes: []string{}, RedirectUris: []string{}, CreatedAt: c.CreatedAt}
	if c.Type == oauth.Type {
		in, err := oauth.Info(c)
		if err != nil {
			return v, err
		}
		v.Issuer, v.AuthorizationEndpoint, v.TokenEndpoint = optString(in.Issuer), optString(in.AuthURL), optString(in.TokenURL)
		v.ClientId = in.ClientID
		v.Scopes = append(v.Scopes, in.Scopes...)
		v.RedirectUris = append(v.RedirectUris, in.RedirectURIs...)
	}
	if c.Type == dirldap.Type {
		in, err := dirldap.InfoOf(c)
		if err != nil {
			return v, err
		}
		v.Ldap = adminLDAPInfo(in)
	}
	owner, err := s.orgPublicID(ctx, tx, c.OwnerOrgID)
	if err != nil {
		return v, err
	}
	v.OwnerOrgId = optString(owner)
	v.ActiveIdentities, err = tx.Identities().CountActiveByConnection(ctx, s.a.realm.ID, c.ID)
	return v, err
}

func (s adminServer) ListConnections(ctx context.Context, _ adminapi.ListConnectionsRequestObject) (adminapi.ListConnectionsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermConnectionsRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		out := []adminapi.AdminConnection{}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			cs, err := tx.Connections().List(ctx, s.a.realm.ID)
			if err != nil {
				return err
			}
			for _, c := range cs {
				v, err := s.connectionOut(ctx, tx, c)
				if err != nil {
					return err
				}
				out = append(out, v)
			}
			return nil
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.ListConnections200JSONResponse{Connections: out}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.ListConnections401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListConnections403JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) GetConnection(ctx context.Context, req adminapi.GetConnectionRequestObject) (adminapi.GetConnectionResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermConnectionsRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		var out adminapi.AdminConnection
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			c, err := tx.Connections().Get(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			out, err = s.connectionOut(ctx, tx, c)
			return err
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.GetConnection200JSONResponse(out), nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.GetConnection401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.GetConnection403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.GetConnection404JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// realmConnection は運営者が変えられる（realm 共通の）connection を返す。Org 専用 SSO の connection は errConnectionOwned。
func (s adminServer) realmConnection(ctx context.Context, tx port.Tx, id string) (port.Connection, error) {
	c, err := tx.Connections().Get(ctx, s.a.realm.ID, id)
	if err == nil && c.OwnerOrgID != "" {
		err = errConnectionOwned
	}
	return c, err
}

func (s adminServer) UpdateConnection(ctx context.Context, req adminapi.UpdateConnectionRequestObject) (adminapi.UpdateConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	o, ok, err := outcomeOf(d, err)
	if ok && req.Body == nil {
		o, ok = failed(http.StatusBadRequest, "invalid_request"), false
	}
	if ok {
		var out adminapi.AdminConnection
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			c, err := s.realmConnection(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			b := req.Body
			c, changed, err := s.a.oauth.UpdateConnection(ctx, c, b.ClientId, b.ClientSecret, b.RedirectUris)
			if err != nil {
				return err
			}
			if err := tx.Connections().UpdateConfig(ctx, s.a.realm.ID, c.ID, c.Config); err != nil {
				return err
			}
			if len(changed) > 0 {
				// 値は残さない（クライアントシークレットを含みうるため、変えた項目の名前だけ）。
				if _, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "connection.updated", Result: audit.ResultSuccess,
					RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
					Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "fields": changed}}); err != nil {
					return err
				}
			}
			out, err = s.connectionOut(ctx, tx, c)
			return err
		})
		if errors.Is(err, errs.Invalid) {
			var e *errs.Error
			errors.As(err, &e)
			o, ok, err = failed(http.StatusBadRequest, "invalid_connection"), false, nil
			o.body.Message = optString(e.Msg)
		} else if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.UpdateConnection200JSONResponse(out), nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusBadRequest:
		return adminapi.UpdateConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusUnauthorized:
		return adminapi.UpdateConnection401JSONResponse(o.body), nil
	case http.StatusForbidden:
		return adminapi.UpdateConnection403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.UpdateConnection404JSONResponse(o.body), nil
	case http.StatusConflict:
		return adminapi.UpdateConnection409JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) DeleteConnection(ctx context.Context, req adminapi.DeleteConnectionRequestObject) (adminapi.DeleteConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	o, ok, err := outcomeOf(d, err)
	if ok {
		revoke := req.Body != nil && deref(req.Body.RevokeIdentities)
		var revoked, inUse int
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			c, err := s.realmConnection(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			if inUse, err = tx.Identities().CountActiveByConnection(ctx, s.a.realm.ID, c.ID); err != nil {
				return err
			}
			if inUse > 0 && !revoke {
				// 使っている外部 ID があれば、既定では消さない（ログインの手段を黙って奪わない）。
				return errs.WithCode(errs.KindFailedPrecondition, "connection_in_use", "connection has active identities")
			}
			if revoked, err = tx.Identities().RevokeByConnection(ctx, s.a.realm.ID, c.ID, s.a.deps.Clock.Now(), org.RevokeConnectionDeleted); err != nil {
				return err
			}
			// ディレクトリの同期の Group の対応も外す（Group は残る。ADR 0102）。
			if _, err := tx.DirectoryGroups().DeleteByConnection(ctx, s.a.realm.ID, c.ID); err != nil {
				return err
			}
			if err := tx.Connections().Delete(ctx, s.a.realm.ID, c.ID); err != nil {
				return err
			}
			_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "connection.deleted", Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
				Actor: p.Actor, RequestID: requestID(ctx), Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "identities_revoked": revoked}})
			return err
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.DeleteConnection200JSONResponse{IdentitiesRevoked: revoked}, nil
		}
		if o.body.Error == "connection_in_use" {
			o.body.Message = ptrTo(fmt.Sprintf("%d active identities; pass revoke_identities to revoke them", inUse))
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.DeleteConnection401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.DeleteConnection403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.DeleteConnection404JSONResponse(o.body), nil
	case http.StatusConflict:
		return adminapi.DeleteConnection409JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// 署名鍵

func (s adminServer) ListSigningKeys(ctx context.Context, _ adminapi.ListSigningKeysRequestObject) (adminapi.ListSigningKeysResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermSigningKeysRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		out := []adminapi.AdminSigningKey{}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ks, err := tx.SigningKeys().List(ctx, s.a.realm.ID)
			if err != nil {
				return err
			}
			now := s.a.deps.Clock.Now()
			for _, k := range ks {
				// 秘密鍵は封をしたものでも出さない。公開鍵は JWKS で配る。
				v := adminapi.AdminSigningKey{Kid: k.ID, Alg: k.Alg, State: "active", CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt}
				if k.RetiredAt != nil {
					until := k.RetiredAt.Add(s.a.keys.RetiredKeyTTL)
					v.State, v.PublishedUntil = "retired", &until
					if !now.Before(until) {
						v.State = "expired"
					}
				}
				out = append(out, v)
			}
			return nil
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.ListSigningKeys200JSONResponse{Keys: out}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.ListSigningKeys401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.ListSigningKeys403JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

// ---------------------------------------------------------------------------
// 運営者によるメールの操作

// emailChange は運営者によるメールの操作の共通部分。対象を上回ることを確かめてから change を呼ぶ（メールは復旧とログインの
// 経路なので、なりすましと同じ outranks の判定。ADR 0052）。
func (s adminServer) emailChange(ctx context.Context, publicID string, change func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersEmails)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID)
		if err != nil {
			return err
		}
		if err := s.a.outranks(ctx, tx, p, u.ID); err != nil {
			return err
		}
		return change(ctx, tx, u, p)
	})
	if errors.Is(err, account.ErrViaNotAllowed) || errors.Is(err, account.ErrEmailInvalid) {
		// 要求の誤り（createUser と同じく 400）。
		return failed(http.StatusBadRequest, errCode(err)), nil
	}
	o, ok, err := outcomeOf(nil, err)
	if ok {
		o.status = http.StatusOK
	}
	return o, err
}

func (s adminServer) AddUserEmail(ctx context.Context, req adminapi.AddUserEmailRequestObject) (adminapi.AddUserEmailResponseObject, error) {
	var out adminapi.AdminUserEmail
	var o outcome
	var err error
	if req.Body == nil {
		o = failed(http.StatusBadRequest, "invalid_request")
	} else {
		o, err = s.emailChange(ctx, req.Id, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) error {
			e, err := s.a.accounts.AdminAddEmail(ctx, tx, u, req.Body.Email, p.Actor, requestID(ctx))
			if err != nil {
				return err
			}
			out, _, err = s.emailOut(ctx, tx, e, false)
			return err
		})
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.AddUserEmail201JSONResponse(out), nil
	case http.StatusBadRequest:
		return adminapi.AddUserEmail400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusUnauthorized:
		return adminapi.AddUserEmail401JSONResponse(o.body), nil
	case http.StatusForbidden:
		return adminapi.AddUserEmail403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.AddUserEmail404JSONResponse(o.body), nil
	case http.StatusConflict:
		return adminapi.AddUserEmail409JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) RemoveUserEmail(ctx context.Context, req adminapi.RemoveUserEmailRequestObject) (adminapi.RemoveUserEmailResponseObject, error) {
	o, err := s.emailChange(ctx, req.Id, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) error {
		return s.a.accounts.AdminRemoveEmail(ctx, tx, u, req.EmailId, p.Actor, requestID(ctx))
	})
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.RemoveUserEmail204Response{}, nil
	case http.StatusUnauthorized:
		return adminapi.RemoveUserEmail401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.RemoveUserEmail403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.RemoveUserEmail404JSONResponse(o.body), nil
	case http.StatusConflict:
		return adminapi.RemoveUserEmail409JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}

func (s adminServer) MakeUserEmailPrimary(ctx context.Context, req adminapi.MakeUserEmailPrimaryRequestObject) (adminapi.MakeUserEmailPrimaryResponseObject, error) {
	o, err := s.emailChange(ctx, req.Id, func(ctx context.Context, tx port.Tx, u port.User, p adminPrincipal) error {
		return s.a.accounts.AdminSetPrimaryEmail(ctx, tx, u, req.EmailId, p.Actor, requestID(ctx))
	})
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusOK:
		return adminapi.MakeUserEmailPrimary204Response{}, nil
	case http.StatusUnauthorized:
		return adminapi.MakeUserEmailPrimary401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.MakeUserEmailPrimary403JSONResponse(o.body), nil
	case http.StatusNotFound:
		return adminapi.MakeUserEmailPrimary404JSONResponse(o.body), nil
	case http.StatusConflict:
		return adminapi.MakeUserEmailPrimary409JSONResponse(o.body), nil
	}
	return nil, errStatus(o.status)
}
