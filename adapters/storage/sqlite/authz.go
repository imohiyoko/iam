package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可側（design.md 3.2、ADR 0064）。

type roleBindings struct{ q *db.Queries }

func toRoleBinding(r db.AuthzRoleBinding) (port.RoleBinding, error) {
	t, err := parseTime(r.CreatedAt)
	return port.RoleBinding{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, Role: r.Role, PrincipalType: port.PrincipalType(r.PrincipalType),
		PrincipalID: r.PrincipalID, OrgID: r.OrgID, ResourceType: r.ResourceType, ResourceID: r.ResourceID, CreatedAt: t}, err
}

func (r roleBindings) Create(ctx context.Context, b port.RoleBinding) error {
	return mapErr(r.q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: b.ID, PublicID: b.PublicID, RealmID: b.RealmID, Role: b.Role,
		PrincipalType: string(b.PrincipalType), PrincipalID: b.PrincipalID, OrgID: b.OrgID, ResourceType: b.ResourceType,
		ResourceID: b.ResourceID, CreatedAt: formatTime(b.CreatedAt)}))
}

func (r roleBindings) GetByPublicID(ctx context.Context, realmID, publicID string) (port.RoleBinding, error) {
	row, err := r.q.GetRoleBindingByPublicID(ctx, db.GetRoleBindingByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toRoleBinding)
}

func (r roleBindings) Delete(ctx context.Context, realmID, id string) error {
	n, err := r.q.DeleteRoleBinding(ctx, db.DeleteRoleBindingParams{RealmID: realmID, ID: id})
	return affected(n, err, "role binding")
}

func (r roleBindings) ListByPrincipal(ctx context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.RoleBinding, error) {
	rs, err := r.q.ListRoleBindingsByPrincipal(ctx, db.ListRoleBindingsByPrincipalParams{RealmID: realmID, PrincipalType: string(t), PrincipalID: principalID})
	return rows(rs, err, toRoleBinding)
}

func (r roleBindings) ListByRole(ctx context.Context, realmID, role string) ([]port.RoleBinding, error) {
	rs, err := r.q.ListRoleBindingsByRole(ctx, db.ListRoleBindingsByRoleParams{RealmID: realmID, Role: role})
	return rows(rs, err, toRoleBinding)
}

func (r roleBindings) ListByOrg(ctx context.Context, realmID, orgID string) ([]port.RoleBinding, error) {
	rs, err := r.q.ListRoleBindingsByOrg(ctx, db.ListRoleBindingsByOrgParams{RealmID: realmID, OrgID: orgID})
	return rows(rs, err, toRoleBinding)
}

// ListEffective は1つのクエリで、直接の付与と所属する Group の付与を、Group の Org と独自のロールの中身とともに集める。
func (r roleBindings) ListEffective(ctx context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.EffectiveBinding, error) {
	rs, err := r.q.ListEffectiveRoleBindings(ctx, db.ListEffectiveRoleBindingsParams{RealmID: realmID, PrincipalType: string(t), PrincipalID: principalID})
	return rows(rs, err, func(x db.ListEffectiveRoleBindingsRow) (port.EffectiveBinding, error) {
		b, err := toRoleBinding(db.AuthzRoleBinding{ID: x.ID, PublicID: x.PublicID, RealmID: x.RealmID, Role: x.Role, PrincipalType: x.PrincipalType,
			PrincipalID: x.PrincipalID, OrgID: x.OrgID, ResourceType: x.ResourceType, ResourceID: x.ResourceID, CreatedAt: x.CreatedAt})
		if err != nil {
			return port.EffectiveBinding{}, err
		}
		e := port.EffectiveBinding{RoleBinding: b}
		if x.PrincipalType == string(port.PrincipalGroup) {
			e.GroupOrgID = x.GroupOrgID
		}
		if x.CustomPublicID.Valid {
			c, err := toRole(db.AuthzRole{ID: x.Role, PublicID: x.CustomPublicID.String, RealmID: x.RealmID, OrgID: x.CustomOrgID.String,
				Name: x.CustomName.String, Permissions: x.CustomPermissions.String, CreatedAt: x.CustomCreatedAt.String, UpdatedAt: x.CustomUpdatedAt.String})
			if err != nil {
				return port.EffectiveBinding{}, err
			}
			e.Custom = &c
		}
		return e, nil
	})
}

// ---------------------------------------------------------------------------

type roles struct{ q *db.Queries }

func toRole(r db.AuthzRole) (port.Role, error) {
	var p times
	x := port.Role{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, OrgID: r.OrgID, Name: r.Name,
		CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	if p.err != nil {
		return port.Role{}, p.err
	}
	return x, json.Unmarshal([]byte(r.Permissions), &x.Permissions)
}

func permissionsJSON(ps []string) (string, error) {
	if ps == nil {
		ps = []string{}
	}
	b, err := json.Marshal(ps)
	return string(b), err
}

func (r roles) Create(ctx context.Context, x port.Role) error {
	ps, err := permissionsJSON(x.Permissions)
	if err != nil {
		return err
	}
	return mapErr(r.q.CreateRole(ctx, db.CreateRoleParams{ID: x.ID, PublicID: x.PublicID, RealmID: x.RealmID, OrgID: x.OrgID, Name: x.Name,
		Permissions: ps, CreatedAt: formatTime(x.CreatedAt), UpdatedAt: formatTime(x.UpdatedAt)}))
}

func (r roles) Get(ctx context.Context, realmID, id string) (port.Role, error) {
	row, err := r.q.GetRole(ctx, db.GetRoleParams{RealmID: realmID, ID: id})
	return one(row, err, toRole)
}

func (r roles) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Role, error) {
	row, err := r.q.GetRoleByPublicID(ctx, db.GetRoleByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toRole)
}

func (r roles) ListByOrg(ctx context.Context, realmID, orgID string) ([]port.Role, error) {
	rs, err := r.q.ListRolesByOrg(ctx, db.ListRolesByOrgParams{RealmID: realmID, OrgID: orgID})
	return rows(rs, err, toRole)
}

func (r roles) Update(ctx context.Context, x port.Role) error {
	ps, err := permissionsJSON(x.Permissions)
	if err != nil {
		return err
	}
	n, err := r.q.UpdateRole(ctx, db.UpdateRoleParams{Name: x.Name, Permissions: ps, UpdatedAt: formatTime(x.UpdatedAt), RealmID: x.RealmID, ID: x.ID})
	return affected(n, err, "role")
}

func (r roles) Delete(ctx context.Context, realmID, id string) error {
	n, err := r.q.DeleteRole(ctx, db.DeleteRoleParams{RealmID: realmID, ID: id})
	return affected(n, err, "role")
}

// ---------------------------------------------------------------------------

type groups struct{ q *db.Queries }

func toGroup(r db.AuthzGroup) (port.Group, error) {
	var p times
	g := port.Group{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, OrgID: r.OrgID, Name: r.Name, CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	return g, p.err
}

func toGroupMember(r db.AuthzGroupMember) (port.GroupMember, error) {
	t, err := parseTime(r.CreatedAt)
	return port.GroupMember{GroupID: r.GroupID, MemberType: port.PrincipalType(r.MemberType), MemberID: r.MemberID, CreatedAt: t}, err
}

func (r groups) Create(ctx context.Context, g port.Group) error {
	return mapErr(r.q.CreateGroup(ctx, db.CreateGroupParams{ID: g.ID, PublicID: g.PublicID, RealmID: g.RealmID, OrgID: g.OrgID, Name: g.Name,
		CreatedAt: formatTime(g.CreatedAt), UpdatedAt: formatTime(g.UpdatedAt)}))
}

func (r groups) Get(ctx context.Context, realmID, id string) (port.Group, error) {
	row, err := r.q.GetGroup(ctx, db.GetGroupParams{RealmID: realmID, ID: id})
	return one(row, err, toGroup)
}

func (r groups) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Group, error) {
	row, err := r.q.GetGroupByPublicID(ctx, db.GetGroupByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toGroup)
}

func (r groups) ListByOrg(ctx context.Context, realmID, orgID string) ([]port.Group, error) {
	rs, err := r.q.ListGroupsByOrg(ctx, db.ListGroupsByOrgParams{RealmID: realmID, OrgID: orgID})
	return rows(rs, err, toGroup)
}

func (r groups) Rename(ctx context.Context, realmID, id, name string, updatedAt time.Time) error {
	n, err := r.q.RenameGroup(ctx, db.RenameGroupParams{Name: name, UpdatedAt: formatTime(updatedAt), RealmID: realmID, ID: id})
	return affected(n, err, "group")
}

func (r groups) Delete(ctx context.Context, realmID, id string) error {
	if _, err := r.Get(ctx, realmID, id); err != nil {
		return err
	}
	if err := r.q.DeleteGroupMembers(ctx, id); err != nil {
		return mapErr(err)
	}
	n, err := r.q.DeleteGroup(ctx, db.DeleteGroupParams{RealmID: realmID, ID: id})
	return affected(n, err, "group")
}

func (r groups) AddMember(ctx context.Context, realmID string, m port.GroupMember) error {
	if _, err := r.Get(ctx, realmID, m.GroupID); err != nil {
		return err
	}
	return mapErr(r.q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: m.GroupID, MemberType: string(m.MemberType), MemberID: m.MemberID,
		CreatedAt: formatTime(m.CreatedAt)}))
}

func (r groups) RemoveMember(ctx context.Context, realmID, groupID string, t port.PrincipalType, memberID string) error {
	if _, err := r.Get(ctx, realmID, groupID); err != nil {
		return err
	}
	n, err := r.q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: groupID, MemberType: string(t), MemberID: memberID})
	return affected(n, err, "group member")
}

func (r groups) ListMembers(ctx context.Context, realmID, groupID string) ([]port.GroupMember, error) {
	if _, err := r.Get(ctx, realmID, groupID); err != nil {
		return nil, err
	}
	rs, err := r.q.ListGroupMembers(ctx, groupID)
	return rows(rs, err, toGroupMember)
}

func (r groups) ListByMember(ctx context.Context, realmID string, t port.PrincipalType, memberID string) ([]port.Group, error) {
	rs, err := r.q.ListGroupsByMember(ctx, db.ListGroupsByMemberParams{RealmID: realmID, MemberType: string(t), MemberID: memberID})
	return rows(rs, err, toGroup)
}
