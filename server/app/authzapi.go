package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ロール・付与・Group の管理の API（design.md 3.2、4.11、ADR 0064）。realm の範囲は管理 API、Org の範囲は公開 API の
// /v1/me/orgs/{id} の下に置き、中身は同じ処理を使う。応答の形は publicapi の型で作り、管理 API は型の変換で使う。
// 応答と監査ログには公開 ID だけを出す（ADR 0045）。

// authzCall は管理の操作の範囲と操作する主体。
type authzCall struct {
	sc manage.Scope
	ac manage.Actor
}

type authzFunc func(ctx context.Context, tx port.Tx, c authzCall) error

var (
	errInvalidPrincipal = manage.ErrInvalidPrincipal
	errRoleExists       = errs.WithCode(errs.KindConflict, "role_exists", "role name exists")
	errBindingExists    = errs.WithCode(errs.KindConflict, "binding_exists", "role binding exists")
	errGroupExists      = errs.WithCode(errs.KindConflict, "group_exists", "group name exists")
	errMemberExists     = errs.WithCode(errs.KindConflict, "member_exists", "already a member")
)

// conflictAs は Repository の重複（コードの無い errs.Conflict）を、応答のコードを持つ誤りにする。
func conflictAs(err, as error) error {
	if errors.Is(err, errs.Conflict) && errCode(err) == "" {
		return as
	}
	return err
}

// authzTx は fn を1つのトランザクションで実行する。成功しても失敗しても判定の材料のキャッシュを捨てる
// （コミットの前に捨てると、その間に古い材料を読んでキャッシュしうるため、コミットの後にもう一度捨てる）。
func (a *App) authzTx(ctx context.Context, fn func(ctx context.Context, tx port.Tx) error) error {
	err := a.deps.Storage.Tx(ctx, fn)
	a.authz.Invalidate(a.realm.ID)
	return err
}

// ---------------------------------------------------------------------------
// 主体の公開 ID と内部 ID

// resolvePrincipal は API の主体（種類と公開 ID）を範囲の主体にする。Group は同じ範囲のものだけ。
func resolvePrincipal(ctx context.Context, tx port.Tx, sc manage.Scope, typ, publicID string, allowGroup bool) (manage.Target, error) {
	switch {
	case typ == string(port.PrincipalUser):
		u, err := tx.Users().GetByPublicID(ctx, sc.RealmID, publicID)
		if errors.Is(err, errs.NotFound) || (err == nil && u.Status == port.UserDeleted) {
			return manage.Target{}, errInvalidPrincipal
		}
		if err != nil {
			return manage.Target{}, err
		}
		return manage.Target{Principal: check.Principal{Type: port.PrincipalUser, ID: u.ID}, PublicID: u.PublicID}, nil
	case typ == string(port.PrincipalServiceAccount):
		// サービスアカウントの ID は外部 ID（ADR 0045）。Org の範囲では、その Org に属するものだけ。
		sa, err := tx.ServiceAccounts().Get(ctx, sc.RealmID, publicID)
		if errors.Is(err, errs.NotFound) || (err == nil && (sa.DeletedAt != nil || sa.OrgID != sc.OrgID && sc.OrgID != "")) {
			return manage.Target{}, errInvalidPrincipal
		}
		if err != nil {
			return manage.Target{}, err
		}
		return manage.Target{Principal: check.Principal{Type: port.PrincipalServiceAccount, ID: sa.ID}, PublicID: sa.ID}, nil
	case typ == string(port.PrincipalGroup) && allowGroup:
		g, err := tx.Groups().GetByPublicID(ctx, sc.RealmID, publicID)
		if errors.Is(err, errs.NotFound) || (err == nil && g.OrgID != sc.OrgID) {
			return manage.Target{}, errInvalidPrincipal
		}
		if err != nil {
			return manage.Target{}, err
		}
		return manage.Target{Principal: check.Principal{Type: port.PrincipalGroup, ID: g.ID}, PublicID: g.PublicID}, nil
	}
	return manage.Target{}, errInvalidPrincipal
}

// principalPublicID は主体の内部 ID を公開 ID にする。消えた主体は空。
func principalPublicID(ctx context.Context, tx port.Tx, realmID string, t port.PrincipalType, internalID string) (string, error) {
	var pub string
	var err error
	switch t {
	case port.PrincipalUser:
		var u port.User
		u, err = tx.Users().Get(ctx, realmID, internalID)
		pub = u.PublicID
	case port.PrincipalGroup:
		var g port.Group
		g, err = tx.Groups().Get(ctx, realmID, internalID)
		pub = g.PublicID
	case port.PrincipalServiceAccount:
		// サービスアカウントの ID は外部 ID（ADR 0045）。
		return internalID, nil
	default:
		return "", nil
	}
	if errors.Is(err, errs.NotFound) {
		return "", nil
	}
	return pub, err
}

// ---------------------------------------------------------------------------
// ロール

func roleOut(r port.Role) publicapi.Role {
	return publicapi.Role{Id: r.PublicID, Name: r.Name, Permissions: append([]string{}, r.Permissions...), Assignable: true}
}

func (a *App) listRoles(ctx context.Context, tx port.Tx, c authzCall) ([]publicapi.Role, error) {
	out := []publicapi.Role{}
	for _, b := range role.Builtins() {
		switch {
		case b.Scope == role.ScopeSystem:
		case c.sc.OrgID == "" && b.Scope == role.ScopeRealm:
			out = append(out, publicapi.Role{Id: b.Name, Name: b.Name, Permissions: b.Permissions, Builtin: true, Assignable: true})
		case c.sc.OrgID != "" && b.Scope == role.ScopeOrg:
			out = append(out, publicapi.Role{Id: b.Name, Name: b.Name, Permissions: b.Permissions, Builtin: true})
		}
	}
	scopes := []string{""}
	if c.sc.OrgID != "" {
		scopes = append(scopes, c.sc.OrgID)
	}
	for _, o := range scopes {
		rs, err := tx.Roles().ListByOrg(ctx, c.sc.RealmID, o)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			out = append(out, roleOut(r))
		}
	}
	return out, nil
}

// scopedRole は範囲の独自のロールを公開 ID で返す。別の範囲のロールは無いものとして扱う。
func scopedRole(ctx context.Context, tx port.Tx, sc manage.Scope, publicID string) (port.Role, error) {
	r, err := tx.Roles().GetByPublicID(ctx, sc.RealmID, publicID)
	if err == nil && r.OrgID != sc.OrgID {
		err = errs.New(errs.KindNotFound, "role")
	}
	return r, err
}

func (a *App) createRole(ctx context.Context, tx port.Tx, c authzCall, in publicapi.RoleInput) (publicapi.Role, error) {
	r, err := a.manage.CreateRole(ctx, tx, c.sc, c.ac, in.Name, in.Permissions)
	if err != nil {
		return publicapi.Role{}, conflictAs(err, errRoleExists)
	}
	return roleOut(r), nil
}

func (a *App) updateRole(ctx context.Context, tx port.Tx, c authzCall, publicID string, in publicapi.RoleInput) (publicapi.Role, error) {
	r, err := scopedRole(ctx, tx, c.sc, publicID)
	if err != nil {
		return publicapi.Role{}, err
	}
	if r, err = a.manage.UpdateRole(ctx, tx, c.sc, c.ac, r, in.Name, in.Permissions); err != nil {
		return publicapi.Role{}, conflictAs(err, errRoleExists)
	}
	return roleOut(r), nil
}

func (a *App) deleteRole(ctx context.Context, tx port.Tx, c authzCall, publicID string) error {
	r, err := scopedRole(ctx, tx, c.sc, publicID)
	if err != nil {
		return err
	}
	return a.manage.DeleteRole(ctx, tx, c.sc, c.ac, r)
}

// ---------------------------------------------------------------------------
// 付与

func (a *App) bindingOut(ctx context.Context, tx port.Tx, b port.RoleBinding) (publicapi.RoleBinding, error) {
	name, err := manage.DisplayRole(ctx, tx, b.RealmID, b.Role)
	if errors.Is(err, errs.NotFound) {
		name, err = "", nil
	}
	if err != nil {
		return publicapi.RoleBinding{}, err
	}
	pid, err := principalPublicID(ctx, tx, b.RealmID, b.PrincipalType, b.PrincipalID)
	if err != nil {
		return publicapi.RoleBinding{}, err
	}
	out := publicapi.RoleBinding{Id: b.PublicID, Role: name, PrincipalType: string(b.PrincipalType), PrincipalId: pid, CreatedAt: b.CreatedAt,
		Condition: conditionOut(b.Condition)}
	if b.ResourceType != "" {
		out.ResourceType, out.ResourceId = &b.ResourceType, &b.ResourceID
	}
	return out, nil
}

func (a *App) listBindings(ctx context.Context, tx port.Tx, c authzCall) ([]publicapi.RoleBinding, error) {
	bs, err := tx.RoleBindings().ListByOrg(ctx, c.sc.RealmID, c.sc.OrgID)
	if err != nil {
		return nil, err
	}
	out := make([]publicapi.RoleBinding, 0, len(bs))
	for _, b := range bs {
		v, err := a.bindingOut(ctx, tx, b)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (a *App) createBinding(ctx context.Context, tx port.Tx, c authzCall, in publicapi.RoleBindingInput) (publicapi.RoleBinding, error) {
	t, err := resolvePrincipal(ctx, tx, c.sc, in.PrincipalType, in.PrincipalId, true)
	if err != nil {
		return publicapi.RoleBinding{}, err
	}
	var res check.Resource
	if in.ResourceType != nil {
		res.Type = *in.ResourceType
	}
	if in.ResourceId != nil {
		res.ID = *in.ResourceId
	}
	cond, err := conditionIn(in.Condition)
	if err != nil {
		return publicapi.RoleBinding{}, err
	}
	b, err := a.manage.Bind(ctx, tx, c.sc, c.ac, in.Role, t, res, cond)
	if err != nil {
		return publicapi.RoleBinding{}, conflictAs(err, errBindingExists)
	}
	return a.bindingOut(ctx, tx, b)
}

func (a *App) deleteBinding(ctx context.Context, tx port.Tx, c authzCall, publicID string) error {
	b, err := tx.RoleBindings().GetByPublicID(ctx, c.sc.RealmID, publicID)
	if err != nil {
		return err
	}
	pid, err := principalPublicID(ctx, tx, b.RealmID, b.PrincipalType, b.PrincipalID)
	if err != nil {
		return err
	}
	return a.manage.Unbind(ctx, tx, c.sc, c.ac, b, pid)
}

// ---------------------------------------------------------------------------
// Group

func groupOut(g port.Group) publicapi.Group {
	return publicapi.Group{Id: g.PublicID, Name: g.Name, CreatedAt: g.CreatedAt}
}

// scopedGroup は範囲の Group を公開 ID で返す。別の範囲の Group は無いものとして扱う。
func scopedGroup(ctx context.Context, tx port.Tx, sc manage.Scope, publicID string) (port.Group, error) {
	g, err := tx.Groups().GetByPublicID(ctx, sc.RealmID, publicID)
	if err == nil && g.OrgID != sc.OrgID {
		err = errs.New(errs.KindNotFound, "group")
	}
	return g, err
}

func (a *App) listGroups(ctx context.Context, tx port.Tx, c authzCall) ([]publicapi.Group, error) {
	gs, err := tx.Groups().ListByOrg(ctx, c.sc.RealmID, c.sc.OrgID)
	if err != nil {
		return nil, err
	}
	out := make([]publicapi.Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupOut(g))
	}
	return out, nil
}

// myGroups は本人がこの Org の範囲で所属する Group を名前の順に返す（ADR 0085）。ネストなら、所属する Group を含む Group も
// 返す（direct が false。その付与も本人に効くため）。
func (a *App) myGroups(ctx context.Context, tx port.Tx, realmID, userID, orgID string) ([]publicapi.MyGroup, error) {
	gs, err := tx.Groups().ListByMember(ctx, realmID, port.PrincipalUser, userID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []publicapi.MyGroup{}
	var direct []string
	for _, g := range gs {
		if g.OrgID != orgID || seen[g.ID] {
			continue
		}
		seen[g.ID] = true
		direct = append(direct, g.ID)
		out = append(out, publicapi.MyGroup{Id: g.PublicID, Name: g.Name, CreatedAt: g.CreatedAt, Direct: true})
	}
	if a.authz.NestedGroups {
		for _, id := range direct {
			ls, err := tx.Groups().Ancestors(ctx, realmID, id)
			if err != nil {
				return nil, err
			}
			for _, l := range ls {
				if seen[l.GroupID] {
					continue
				}
				seen[l.GroupID] = true
				g, err := tx.Groups().Get(ctx, realmID, l.GroupID)
				if errors.Is(err, errs.NotFound) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if g.OrgID == orgID {
					out = append(out, publicapi.MyGroup{Id: g.PublicID, Name: g.Name, CreatedAt: g.CreatedAt})
				}
			}
		}
	}
	slices.SortFunc(out, func(x, y publicapi.MyGroup) int { return strings.Compare(x.Name, y.Name) })
	return out, nil
}

// readGroups は Org の Group を読めることを確かめる（ADR 0085）。`org:groups` か `org:groups.read` が要る。groupPublicID が
// 空でなければ、その Group に限った `org:groups.read` の付与（resource_type が group）でもよい。
func (a *App) readGroups(ctx context.Context, tx port.Tx, c authzCall, groupPublicID string) error {
	r := check.Request{Principal: c.ac.Principal, Action: role.PermOrgGroups, OrgID: c.sc.OrgID, Context: c.ac.Context}
	ok, err := a.authz.CheckTx(ctx, tx, c.sc.RealmID, r)
	if err != nil || ok {
		return err
	}
	r.Action = role.PermOrgGroupsRead
	if groupPublicID != "" {
		r.Resource = check.Resource{Type: check.ResourceGroup, ID: groupPublicID}
	}
	if ok, err = a.authz.CheckTx(ctx, tx, c.sc.RealmID, r); err != nil || ok {
		return err
	}
	return errOrgPermission
}

func (a *App) createGroup(ctx context.Context, tx port.Tx, c authzCall, in publicapi.GroupInput) (publicapi.Group, error) {
	g, err := a.manage.CreateGroup(ctx, tx, c.sc, c.ac, in.Name)
	if err != nil {
		return publicapi.Group{}, conflictAs(err, errGroupExists)
	}
	return groupOut(g), nil
}

func (a *App) renameGroup(ctx context.Context, tx port.Tx, c authzCall, publicID string, in publicapi.GroupInput) (publicapi.Group, error) {
	g, err := scopedGroup(ctx, tx, c.sc, publicID)
	if err != nil {
		return publicapi.Group{}, err
	}
	if g, err = a.manage.RenameGroup(ctx, tx, c.sc, c.ac, g, in.Name); err != nil {
		return publicapi.Group{}, conflictAs(err, errGroupExists)
	}
	return groupOut(g), nil
}

func (a *App) deleteGroup(ctx context.Context, tx port.Tx, c authzCall, publicID string) error {
	g, err := scopedGroup(ctx, tx, c.sc, publicID)
	if err != nil {
		return err
	}
	return a.manage.DeleteGroup(ctx, tx, c.sc, c.ac, g)
}

func (a *App) listGroupMembers(ctx context.Context, tx port.Tx, c authzCall, publicID string) ([]publicapi.GroupMember, error) {
	g, err := scopedGroup(ctx, tx, c.sc, publicID)
	if err != nil {
		return nil, err
	}
	ms, err := tx.Groups().ListMembers(ctx, c.sc.RealmID, g.ID)
	if err != nil {
		return nil, err
	}
	out := make([]publicapi.GroupMember, 0, len(ms))
	for _, m := range ms {
		pid, err := principalPublicID(ctx, tx, c.sc.RealmID, m.MemberType, m.MemberID)
		if err != nil {
			return nil, err
		}
		out = append(out, publicapi.GroupMember{PrincipalType: string(m.MemberType), PrincipalId: pid, CreatedAt: m.CreatedAt})
	}
	return out, nil
}

func (a *App) addGroupMember(ctx context.Context, tx port.Tx, c authzCall, publicID string, in publicapi.GroupMemberInput) error {
	g, err := scopedGroup(ctx, tx, c.sc, publicID)
	if err != nil {
		return err
	}
	t, err := resolvePrincipal(ctx, tx, c.sc, in.PrincipalType, in.PrincipalId, a.manage.NestedGroups)
	if err != nil {
		return err
	}
	return conflictAs(a.manage.AddMember(ctx, tx, c.sc, c.ac, g, t), errMemberExists)
}

func (a *App) removeGroupMember(ctx context.Context, tx port.Tx, c authzCall, publicID string, in publicapi.GroupMemberInput) error {
	g, err := scopedGroup(ctx, tx, c.sc, publicID)
	if err != nil {
		return err
	}
	// Group のネストを無効にする途中でも、Group としての所属は外せる。
	t, err := resolvePrincipal(ctx, tx, c.sc, in.PrincipalType, in.PrincipalId, true)
	if errors.Is(err, errInvalidPrincipal) {
		return errs.New(errs.KindNotFound, "group member")
	}
	if err != nil {
		return err
	}
	return a.manage.RemoveMember(ctx, tx, c.sc, c.ac, g, t)
}

// ---------------------------------------------------------------------------
// 範囲と応答の状態

// orgAuthz は公開 API の、Org の範囲の管理の操作を実行する。本人がその Org の使える所属と perm を持つことを確かめる。
// 成功なら 200 を、そうでなければ応答の状態と本文を返す（err は想定外の誤りだけ）。
func (s publicServer) orgAuthz(ctx context.Context, orgPublicID, perm string, noBody bool, fn authzFunc) (int, publicapi.Error, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return http.StatusUnauthorized, publicapi.Error(unauthenticated()), nil
	case s.a.orgs == nil:
		return http.StatusNotFound, publicapi.Error(notFound()), nil
	case noBody:
		return http.StatusBadRequest, publicapi.Error{Error: "invalid_request"}, nil
	}
	err := s.a.authzTx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, orgPublicID, perm)
		if err != nil {
			return err
		}
		if o.Kind == port.OrgPersonal {
			return org.ErrPersonalOrg
		}
		return fn(ctx, tx, authzCall{
			sc: manage.Scope{RealmID: s.a.realm.ID, OrgID: o.ID, OrgPublicID: o.PublicID},
			ac: manage.Actor{Principal: check.Principal{Type: port.PrincipalUser, ID: au.PrincipalID}, Audit: au.Actor(), RequestID: requestID(ctx),
				Context: sessionContext(au.Validated)},
		})
	})
	if code, ok := stateCode(err); ok {
		return http.StatusConflict, publicapi.Error{Error: code}, nil
	}
	switch {
	case err == nil:
		return http.StatusOK, publicapi.Error{}, nil
	case errors.Is(err, errs.NotFound):
		return http.StatusNotFound, publicapi.Error(notFound()), nil
	case errors.Is(err, errs.PermissionDenied):
		return http.StatusForbidden, publicapi.Error(orgDenied(err)), nil
	case errors.Is(err, errs.Invalid):
		return http.StatusBadRequest, publicapi.Error{Error: errCodeOr(err, "invalid_request")}, nil
	}
	return 0, publicapi.Error{}, err
}

// adminAuthz は管理 API の、realm の範囲の管理の操作を実行する。成功なら status は 200。
func (s adminServer) adminAuthz(ctx context.Context, perm string, noBody bool, fn authzFunc) (outcome, error) {
	p, d, err := s.a.authorize(ctx, perm)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if noBody {
		return failed(http.StatusBadRequest, "invalid_request"), nil
	}
	err = s.a.authzTx(ctx, func(ctx context.Context, tx port.Tx) error {
		return fn(ctx, tx, authzCall{
			sc: manage.Scope{RealmID: s.a.realm.ID},
			ac: manage.Actor{Principal: check.Principal{Type: p.Type, ID: p.ID}, Audit: p.Actor, RequestID: requestID(ctx), Context: p.Context},
		})
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

// errStatus は応答の型に無い状態（実装の誤り）。
func errStatus(status int) error {
	return errs.New(errs.KindInternal, "unexpected status %d", status)
}
