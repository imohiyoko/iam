// Package manage はロール・ロールの付与・Group の管理を行う（design.md 3.2、4.11、ADR 0064）。
//
// 管理の操作には、範囲ごとの管理の権限（realm は roles:manage・groups:manage、Org は org:roles・org:groups）に加え、
// 渡す権限をすべて自分がその範囲で持っていることを求める（持っていない権限を人に渡して、権限を引き上げられないように）。
// 変更は監査ログに残し、判定の材料のキャッシュを捨てる。
package manage

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 上限。
const (
	MaxNameLength  = 64
	MaxPermissions = 100
)

var (
	// ErrNotHeld は、渡そうとする権限を自分が持っていないこと。
	ErrNotHeld = errs.WithCode(errs.KindPermissionDenied, errs.CodePermissionDenied, "permission not held")
	// ErrInvalidName はロール・Group の名前の形が正しくない（組み込みの名前空間を含む）。
	ErrInvalidName = errs.WithCode(errs.KindInvalid, "invalid_name", "invalid name")
	// ErrInvalidPermission は権限の形が正しくないか、範囲で使えない。
	ErrInvalidPermission = errs.WithCode(errs.KindInvalid, "invalid_permission", "invalid permission")
	// ErrUnknownRole は付与できるロールが無い（組み込みの Org・システムのロールと、別の範囲の独自のロールを含む）。
	ErrUnknownRole = errs.WithCode(errs.KindInvalid, "unknown_role", "unknown role")
	// ErrInvalidPrincipal は付与・所属の主体が範囲に合わない。
	ErrInvalidPrincipal = errs.WithCode(errs.KindInvalid, "invalid_principal", "invalid principal")
	// ErrNotMember は Org の範囲の付与・Group の所属に、その Org の使える所属が無いこと。
	ErrNotMember = errs.WithCode(errs.KindFailedPrecondition, "not_member", "principal is not a member of the org")
	// ErrLastOwner は最後の realm:owner の付与を消そうとしたこと。
	ErrLastOwner = errs.WithCode(errs.KindFailedPrecondition, "last_owner", "last realm owner")
)

// Service は管理の操作を行う。
type Service struct {
	Checker *check.Checker
	Clock   clock.Clock
}

// Scope は操作の範囲。OrgID が空なら realm。
type Scope struct {
	RealmID     string
	OrgID       string // 内部 ID
	OrgPublicID string // 監査ログ用
}

// Actor は操作する主体。
type Actor struct {
	Principal check.Principal
	Audit     audit.Actor
	RequestID string
}

// Target は付与・所属の主体（ユーザー・サービスアカウントは呼び出し側が authn で確かめて渡す）。
type Target struct {
	Principal check.Principal
	PublicID  string // 監査ログと応答用の公開 ID
}

func (s *Service) authorize(ctx context.Context, tx port.Tx, sc Scope, a Actor, realmPerm, orgPerm string, grants []string) error {
	perm := realmPerm
	if sc.OrgID != "" {
		perm = orgPerm
	}
	ok, err := s.Checker.CheckTx(ctx, tx, sc.RealmID, check.Request{Principal: a.Principal, Action: perm, OrgID: sc.OrgID})
	if err != nil {
		return err
	}
	if !ok {
		return errs.WithCode(errs.KindPermissionDenied, errs.CodePermissionDenied, "missing "+perm)
	}
	if len(grants) == 0 {
		return nil
	}
	held, err := s.Checker.Holds(ctx, tx, sc.RealmID, a.Principal, sc.OrgID, grants)
	if err != nil {
		return err
	}
	if !held {
		return ErrNotHeld
	}
	return nil
}

func (s *Service) record(ctx context.Context, tx port.Tx, sc Scope, a Actor, typ string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: sc.RealmID, OrgID: sc.OrgPublicID,
		Actor: a.Audit, RequestID: a.RequestID, Details: details})
	if err == nil {
		s.Checker.Invalidate(sc.RealmID)
	}
	return err
}

// NormalizeName は名前の前後の空白を除き、形を確かめる。組み込みの名前空間（realm:・org:・system:）は使えない。
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxNameLength || role.IsBuiltinName(name) ||
		strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrInvalidName
	}
	return name, nil
}

// NormalizePermissions は権限の形を確かめ、重複を除く（順は保つ）。Org の範囲では IAM 自身の realm の管理の権限は使えない。
func NormalizePermissions(perms []string, orgID string) ([]string, error) {
	if len(perms) > MaxPermissions {
		return nil, ErrInvalidPermission
	}
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if !role.ValidPermission(p) || (orgID != "" && role.RealmOnly(p)) {
			return nil, errs.WithCode(errs.KindInvalid, ErrInvalidPermission.(*errs.Error).Code, "invalid permission "+p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// ロール

// CreateRole は独自のロールを作る。
func (s *Service) CreateRole(ctx context.Context, tx port.Tx, sc Scope, a Actor, name string, perms []string) (port.Role, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return port.Role{}, err
	}
	if perms, err = NormalizePermissions(perms, sc.OrgID); err != nil {
		return port.Role{}, err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermRolesManage, role.PermOrgRoles, perms); err != nil {
		return port.Role{}, err
	}
	now := s.Clock.Now()
	r := port.Role{ID: id.New(id.Role), PublicID: id.NewExternal(id.Role), RealmID: sc.RealmID, OrgID: sc.OrgID, Name: name,
		Permissions: perms, CreatedAt: now, UpdatedAt: now}
	if err := tx.Roles().Create(ctx, r); err != nil {
		return port.Role{}, err
	}
	return r, s.record(ctx, tx, sc, a, "role.created", map[string]any{"role_id": r.PublicID, "name": r.Name, "permissions": r.Permissions})
}

// UpdateRole は独自のロールの名前と権限を置き換える。今の権限も新しい権限も、すべて持っていなければならない。
func (s *Service) UpdateRole(ctx context.Context, tx port.Tx, sc Scope, a Actor, r port.Role, name string, perms []string) (port.Role, error) {
	if r.OrgID != sc.OrgID {
		return port.Role{}, errs.New(errs.KindNotFound, "role")
	}
	name, err := NormalizeName(name)
	if err != nil {
		return port.Role{}, err
	}
	if perms, err = NormalizePermissions(perms, sc.OrgID); err != nil {
		return port.Role{}, err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermRolesManage, role.PermOrgRoles, append(slices.Clone(r.Permissions), perms...)); err != nil {
		return port.Role{}, err
	}
	before := r.Permissions
	r.Name, r.Permissions, r.UpdatedAt = name, perms, s.Clock.Now()
	if err := tx.Roles().Update(ctx, r); err != nil {
		return port.Role{}, err
	}
	return r, s.record(ctx, tx, sc, a, "role.updated", map[string]any{"role_id": r.PublicID, "name": r.Name, "permissions": r.Permissions,
		"previous_permissions": before})
}

// DeleteRole は独自のロールと、その付与を消す。
func (s *Service) DeleteRole(ctx context.Context, tx port.Tx, sc Scope, a Actor, r port.Role) error {
	if r.OrgID != sc.OrgID {
		return errs.New(errs.KindNotFound, "role")
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermRolesManage, role.PermOrgRoles, r.Permissions); err != nil {
		return err
	}
	bs, err := tx.RoleBindings().ListByRole(ctx, sc.RealmID, r.ID)
	if err != nil {
		return err
	}
	for _, b := range bs {
		if err := tx.RoleBindings().Delete(ctx, sc.RealmID, b.ID); err != nil {
			return err
		}
	}
	if err := tx.Roles().Delete(ctx, sc.RealmID, r.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, sc, a, "role.deleted", map[string]any{"role_id": r.PublicID, "name": r.Name, "bindings_removed": len(bs)})
}

// ResolvedRole は付与に使うロール。
type ResolvedRole struct {
	Key         string // 付与の role（組み込みは名前、独自は内部 ID）
	Name        string // 組み込みは名前、独自は公開 ID（応答・監査ログ用）
	Permissions []string
}

// ResolveRole は ref（組み込みのロールの名前か、独自のロールの公開 ID）を、範囲で付与できるロールにする。
// 組み込みの運営者ロールは realm の範囲だけ。Org とシステムの組み込みのロールは付与できない（Org のロールは org_role から効く）。
func ResolveRole(ctx context.Context, tx port.Tx, sc Scope, ref string) (ResolvedRole, error) {
	if b, ok := role.Lookup(ref); ok {
		if b.Scope != role.ScopeRealm || sc.OrgID != "" {
			return ResolvedRole{}, ErrUnknownRole
		}
		return ResolvedRole{Key: b.Name, Name: b.Name, Permissions: b.Permissions}, nil
	}
	r, err := tx.Roles().GetByPublicID(ctx, sc.RealmID, ref)
	if errors.Is(err, errs.NotFound) || (err == nil && r.OrgID != "" && r.OrgID != sc.OrgID) {
		return ResolvedRole{}, ErrUnknownRole
	}
	if err != nil {
		return ResolvedRole{}, err
	}
	return ResolvedRole{Key: r.ID, Name: r.PublicID, Permissions: r.Permissions}, nil
}

// DisplayRole は付与の role を応答・監査ログの形（組み込みは名前、独自は公開 ID）にする。
func DisplayRole(ctx context.Context, tx port.Tx, realmID, key string) (string, error) {
	if _, ok := role.Lookup(key); ok {
		return key, nil
	}
	r, err := tx.Roles().Get(ctx, realmID, key)
	if err != nil {
		return "", err
	}
	return r.PublicID, nil
}

// requireMember は Org の範囲で、ユーザーとサービスアカウントにその Org の使える所属を求める。
func (s *Service) requireMember(ctx context.Context, tx port.Tx, sc Scope, p check.Principal) error {
	if sc.OrgID == "" || p.Type == port.PrincipalGroup {
		return nil
	}
	if s.Checker.Members == nil {
		return ErrNotMember
	}
	_, ok, err := s.Checker.Members.OrgRole(ctx, tx, sc.RealmID, p, sc.OrgID, s.Clock.Now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotMember
	}
	return nil
}

// Bind はロールを付与する。res が空なら範囲全体。
func (s *Service) Bind(ctx context.Context, tx port.Tx, sc Scope, a Actor, ref string, t Target, res check.Resource) (port.RoleBinding, error) {
	r, err := ResolveRole(ctx, tx, sc, ref)
	if err != nil {
		return port.RoleBinding{}, err
	}
	if (res.Type == "") != (res.ID == "") || res.Type == check.ResourceOrg {
		return port.RoleBinding{}, errs.WithCode(errs.KindInvalid, "invalid_resource", "invalid resource")
	}
	if t.Principal.Type == port.PrincipalGroup {
		g, err := tx.Groups().Get(ctx, sc.RealmID, t.Principal.ID)
		if err != nil {
			return port.RoleBinding{}, err
		}
		if g.OrgID != "" && g.OrgID != sc.OrgID {
			return port.RoleBinding{}, ErrInvalidPrincipal
		}
	}
	if err := s.requireMember(ctx, tx, sc, t.Principal); err != nil {
		return port.RoleBinding{}, err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermRolesManage, role.PermOrgRoles, r.Permissions); err != nil {
		return port.RoleBinding{}, err
	}
	b := port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: sc.RealmID, Role: r.Key,
		PrincipalType: t.Principal.Type, PrincipalID: t.Principal.ID, OrgID: sc.OrgID, ResourceType: res.Type, ResourceID: res.ID,
		CreatedAt: s.Clock.Now()}
	if err := tx.RoleBindings().Create(ctx, b); err != nil {
		return port.RoleBinding{}, err
	}
	details := map[string]any{"binding_id": b.PublicID, "role": r.Name, "principal_type": string(t.Principal.Type), "principal_id": t.PublicID}
	if res.Type != "" {
		details["resource_type"], details["resource_id"] = res.Type, res.ID
	}
	return b, s.record(ctx, tx, sc, a, "role.granted", details)
}

// Unbind は付与を消す。消す付与のロールの権限をすべて持っていなければならない。最後の realm:owner は消せない。
func (s *Service) Unbind(ctx context.Context, tx port.Tx, sc Scope, a Actor, b port.RoleBinding, principalPublicID string) error {
	if b.OrgID != sc.OrgID {
		return errs.New(errs.KindNotFound, "role binding")
	}
	var perms []string
	if bi, ok := role.Lookup(b.Role); ok {
		perms = bi.Permissions
	} else if r, err := tx.Roles().Get(ctx, sc.RealmID, b.Role); err == nil {
		perms = r.Permissions
	} else if !errors.Is(err, errs.NotFound) {
		return err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermRolesManage, role.PermOrgRoles, perms); err != nil {
		return err
	}
	if b.Role == role.RealmOwner && b.ResourceType == "" {
		bs, err := tx.RoleBindings().ListByRole(ctx, sc.RealmID, role.RealmOwner)
		if err != nil {
			return err
		}
		n := 0
		for _, x := range bs {
			if x.OrgID == "" && x.ResourceType == "" && x.PrincipalType == port.PrincipalUser {
				n++
			}
		}
		if n <= 1 && b.PrincipalType == port.PrincipalUser {
			return ErrLastOwner
		}
	}
	if err := tx.RoleBindings().Delete(ctx, sc.RealmID, b.ID); err != nil {
		return err
	}
	name, err := DisplayRole(ctx, tx, sc.RealmID, b.Role)
	if errors.Is(err, errs.NotFound) {
		name, err = "", nil
	}
	if err != nil {
		return err
	}
	return s.record(ctx, tx, sc, a, "role.revoked", map[string]any{"binding_id": b.PublicID, "role": name,
		"principal_type": string(b.PrincipalType), "principal_id": principalPublicID})
}

// ---------------------------------------------------------------------------
// Group

// CreateGroup は Group を作る。
func (s *Service) CreateGroup(ctx context.Context, tx port.Tx, sc Scope, a Actor, name string) (port.Group, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return port.Group{}, err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermGroupsManage, role.PermOrgGroups, nil); err != nil {
		return port.Group{}, err
	}
	now := s.Clock.Now()
	g := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: sc.RealmID, OrgID: sc.OrgID, Name: name, CreatedAt: now, UpdatedAt: now}
	if err := tx.Groups().Create(ctx, g); err != nil {
		return port.Group{}, err
	}
	return g, s.record(ctx, tx, sc, a, "group.created", map[string]any{"group_id": g.PublicID, "name": g.Name})
}

// RenameGroup は Group の名前を変える。
func (s *Service) RenameGroup(ctx context.Context, tx port.Tx, sc Scope, a Actor, g port.Group, name string) (port.Group, error) {
	if g.OrgID != sc.OrgID {
		return port.Group{}, errs.New(errs.KindNotFound, "group")
	}
	name, err := NormalizeName(name)
	if err != nil {
		return port.Group{}, err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermGroupsManage, role.PermOrgGroups, nil); err != nil {
		return port.Group{}, err
	}
	g.Name, g.UpdatedAt = name, s.Clock.Now()
	if err := tx.Groups().Rename(ctx, sc.RealmID, g.ID, g.Name, g.UpdatedAt); err != nil {
		return port.Group{}, err
	}
	return g, s.record(ctx, tx, sc, a, "group.renamed", map[string]any{"group_id": g.PublicID, "name": g.Name})
}

// groupPermissions は Group に付与されたロールの権限（範囲全体のもの）。Group を消す・人を入れるには、それを持っていなければならない。
func groupPermissions(ctx context.Context, tx port.Tx, realmID string, g port.Group) ([]port.RoleBinding, []string, error) {
	bs, err := tx.RoleBindings().ListByPrincipal(ctx, realmID, port.PrincipalGroup, g.ID)
	if err != nil {
		return nil, nil, err
	}
	var perms []string
	for _, b := range bs {
		if bi, ok := role.Lookup(b.Role); ok {
			perms = append(perms, bi.Permissions...)
		} else if r, err := tx.Roles().Get(ctx, realmID, b.Role); err == nil {
			perms = append(perms, r.Permissions...)
		} else if !errors.Is(err, errs.NotFound) {
			return nil, nil, err
		}
	}
	return bs, perms, nil
}

// DeleteGroup は Group と、その所属と付与を消す。
func (s *Service) DeleteGroup(ctx context.Context, tx port.Tx, sc Scope, a Actor, g port.Group) error {
	if g.OrgID != sc.OrgID {
		return errs.New(errs.KindNotFound, "group")
	}
	bs, perms, err := groupPermissions(ctx, tx, sc.RealmID, g)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermGroupsManage, role.PermOrgGroups, perms); err != nil {
		return err
	}
	for _, b := range bs {
		if err := tx.RoleBindings().Delete(ctx, sc.RealmID, b.ID); err != nil {
			return err
		}
	}
	if err := tx.Groups().Delete(ctx, sc.RealmID, g.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, sc, a, "group.deleted", map[string]any{"group_id": g.PublicID, "name": g.Name, "bindings_removed": len(bs)})
}

// AddMember は Group に主体を入れる（ユーザーかサービスアカウント。Org の Group には、その Org の使える所属が要る）。
// Group に付与されたロールの権限をすべて持っていなければならない。
func (s *Service) AddMember(ctx context.Context, tx port.Tx, sc Scope, a Actor, g port.Group, t Target) error {
	if g.OrgID != sc.OrgID {
		return errs.New(errs.KindNotFound, "group")
	}
	if t.Principal.Type != port.PrincipalUser && t.Principal.Type != port.PrincipalServiceAccount {
		return ErrInvalidPrincipal
	}
	if err := s.requireMember(ctx, tx, sc, t.Principal); err != nil {
		return err
	}
	_, perms, err := groupPermissions(ctx, tx, sc.RealmID, g)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermGroupsManage, role.PermOrgGroups, perms); err != nil {
		return err
	}
	if err := tx.Groups().AddMember(ctx, sc.RealmID, port.GroupMember{GroupID: g.ID, MemberType: t.Principal.Type, MemberID: t.Principal.ID,
		CreatedAt: s.Clock.Now()}); err != nil {
		return err
	}
	return s.record(ctx, tx, sc, a, "group.member_added", map[string]any{"group_id": g.PublicID, "member_type": string(t.Principal.Type),
		"member_id": t.PublicID})
}

// RemoveMember は Group から主体を外す。
func (s *Service) RemoveMember(ctx context.Context, tx port.Tx, sc Scope, a Actor, g port.Group, t Target) error {
	if g.OrgID != sc.OrgID {
		return errs.New(errs.KindNotFound, "group")
	}
	if err := s.authorize(ctx, tx, sc, a, role.PermGroupsManage, role.PermOrgGroups, nil); err != nil {
		return err
	}
	if err := tx.Groups().RemoveMember(ctx, sc.RealmID, g.ID, t.Principal.Type, t.Principal.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, sc, a, "group.member_removed", map[string]any{"group_id": g.PublicID, "member_type": string(t.Principal.Type),
		"member_id": t.PublicID})
}
