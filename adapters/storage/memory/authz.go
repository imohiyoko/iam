package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可側（design.md 3.2、ADR 0064）。

type roleBindings struct{ t *tx }

func (r roleBindings) Create(_ context.Context, b port.RoleBinding) error {
	if _, ok := r.t.s.roleBindings[b.ID]; ok {
		return errs.New(errs.KindConflict, "role binding %s exists", b.ID)
	}
	for _, x := range r.t.s.roleBindings {
		if x.RealmID != b.RealmID {
			continue
		}
		if x.PublicID == b.PublicID {
			return errs.New(errs.KindConflict, "role binding public id exists in realm")
		}
		if x.Role == b.Role && x.PrincipalType == b.PrincipalType && x.PrincipalID == b.PrincipalID && x.OrgID == b.OrgID &&
			x.ResourceType == b.ResourceType && x.ResourceID == b.ResourceID {
			return errs.New(errs.KindConflict, "role binding exists")
		}
	}
	b.Condition = bytes.Clone(b.Condition)
	setKey(r.t, r.t.s.roleBindings, b.ID, b)
	return nil
}

func (r roleBindings) GetByPublicID(_ context.Context, realmID, publicID string) (port.RoleBinding, error) {
	for _, x := range r.t.s.roleBindings {
		if x.RealmID == realmID && x.PublicID == publicID {
			return x, nil
		}
	}
	return port.RoleBinding{}, errs.New(errs.KindNotFound, "role binding")
}

func (r roleBindings) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.roleBindings, realmID, id, func(b port.RoleBinding) string { return b.RealmID }, "role binding"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.roleBindings, id)
	return nil
}

func (r roleBindings) list(match func(port.RoleBinding) bool) []port.RoleBinding {
	var out []port.RoleBinding
	for _, x := range r.t.s.roleBindings {
		if match(x) {
			out = append(out, x)
		}
	}
	sortByCreated(out, func(x port.RoleBinding) (time.Time, string) { return x.CreatedAt, x.ID })
	return out
}

func (r roleBindings) ListByPrincipal(_ context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.RoleBinding, error) {
	return r.list(func(x port.RoleBinding) bool {
		return x.RealmID == realmID && x.PrincipalType == t && x.PrincipalID == principalID
	}), nil
}

func (r roleBindings) ListByRole(_ context.Context, realmID, role string) ([]port.RoleBinding, error) {
	return r.list(func(x port.RoleBinding) bool { return x.RealmID == realmID && x.Role == role }), nil
}

func (r roleBindings) ListByOrg(_ context.Context, realmID, orgID string) ([]port.RoleBinding, error) {
	return r.list(func(x port.RoleBinding) bool { return x.RealmID == realmID && x.OrgID == orgID }), nil
}

func (r roleBindings) ListEffective(_ context.Context, realmID string, t port.PrincipalType, principalID string, nested bool) ([]port.EffectiveBinding, error) {
	groupOrg := map[string]string{}
	for _, m := range r.t.s.groupMembers {
		if m.MemberType == t && m.MemberID == principalID {
			if g, ok := r.t.s.groups[m.GroupID]; ok && g.RealmID == realmID {
				groupOrg[g.ID] = g.OrgID
			}
		}
	}
	if nested {
		for _, l := range r.t.s.groupClosure {
			if _, ok := groupOrg[l.group]; ok && l.realm == realmID {
				if g, ok := r.t.s.groups[l.ancestor]; ok {
					groupOrg[g.ID] = g.OrgID
				}
			}
		}
	}
	bs := r.list(func(x port.RoleBinding) bool {
		if x.RealmID != realmID {
			return false
		}
		if x.PrincipalType == t && x.PrincipalID == principalID {
			return true
		}
		_, ok := groupOrg[x.PrincipalID]
		return ok && x.PrincipalType == port.PrincipalGroup
	})
	out := make([]port.EffectiveBinding, 0, len(bs))
	for _, b := range bs {
		e := port.EffectiveBinding{RoleBinding: b}
		if b.PrincipalType == port.PrincipalGroup {
			e.GroupOrgID = groupOrg[b.PrincipalID]
		}
		if x, ok := r.t.s.roles[b.Role]; ok && x.RealmID == realmID {
			c := cloneRole(x)
			e.Custom = &c
		}
		out = append(out, e)
	}
	return out, nil
}

// ---------------------------------------------------------------------------

type roles struct{ t *tx }

func cloneRole(r port.Role) port.Role {
	r.Permissions = slices.Clone(r.Permissions)
	return r
}

func (r roles) conflict(x port.Role) error {
	for _, o := range r.t.s.roles {
		if o.RealmID != x.RealmID || o.ID == x.ID {
			continue
		}
		if o.PublicID == x.PublicID {
			return errs.New(errs.KindConflict, "role public id exists in realm")
		}
		if o.OrgID == x.OrgID && o.Name == x.Name {
			return errs.New(errs.KindConflict, "role name exists")
		}
	}
	return nil
}

func (r roles) Create(_ context.Context, x port.Role) error {
	if _, ok := r.t.s.roles[x.ID]; ok {
		return errs.New(errs.KindConflict, "role %s exists", x.ID)
	}
	if err := r.conflict(x); err != nil {
		return err
	}
	setKey(r.t, r.t.s.roles, x.ID, cloneRole(x))
	return nil
}

func (r roles) Get(_ context.Context, realmID, id string) (port.Role, error) {
	x, err := get(r.t.s.roles, realmID, id, func(x port.Role) string { return x.RealmID }, "role")
	return cloneRole(x), err
}

func (r roles) GetByPublicID(_ context.Context, realmID, publicID string) (port.Role, error) {
	for _, x := range r.t.s.roles {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneRole(x), nil
		}
	}
	return port.Role{}, errs.New(errs.KindNotFound, "role")
}

func (r roles) ListByOrg(_ context.Context, realmID, orgID string) ([]port.Role, error) {
	var out []port.Role
	for _, x := range r.t.s.roles {
		if x.RealmID == realmID && x.OrgID == orgID {
			out = append(out, cloneRole(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r roles) Update(_ context.Context, x port.Role) error {
	cur, err := get(r.t.s.roles, x.RealmID, x.ID, func(x port.Role) string { return x.RealmID }, "role")
	if err != nil {
		return err
	}
	cur.Name, cur.Permissions, cur.UpdatedAt = x.Name, slices.Clone(x.Permissions), x.UpdatedAt
	if err := r.conflict(cur); err != nil {
		return err
	}
	setKey(r.t, r.t.s.roles, cur.ID, cur)
	return nil
}

func (r roles) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.roles, realmID, id, func(x port.Role) string { return x.RealmID }, "role"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.roles, id)
	return nil
}

// ---------------------------------------------------------------------------

type groups struct{ t *tx }

func memberKey(groupID string, t port.PrincipalType, memberID string) string {
	return groupID + "\x00" + string(t) + "\x00" + memberID
}

func (r groups) conflict(g port.Group) error {
	for _, o := range r.t.s.groups {
		if o.RealmID != g.RealmID || o.ID == g.ID {
			continue
		}
		if o.PublicID == g.PublicID {
			return errs.New(errs.KindConflict, "group public id exists in realm")
		}
		if o.OrgID == g.OrgID && o.Name == g.Name {
			return errs.New(errs.KindConflict, "group name exists")
		}
	}
	return nil
}

func (r groups) Create(_ context.Context, g port.Group) error {
	if _, ok := r.t.s.groups[g.ID]; ok {
		return errs.New(errs.KindConflict, "group %s exists", g.ID)
	}
	if err := r.conflict(g); err != nil {
		return err
	}
	setKey(r.t, r.t.s.groups, g.ID, g)
	return nil
}

func (r groups) Get(_ context.Context, realmID, id string) (port.Group, error) {
	return get(r.t.s.groups, realmID, id, func(g port.Group) string { return g.RealmID }, "group")
}

func (r groups) GetByPublicID(_ context.Context, realmID, publicID string) (port.Group, error) {
	for _, g := range r.t.s.groups {
		if g.RealmID == realmID && g.PublicID == publicID {
			return g, nil
		}
	}
	return port.Group{}, errs.New(errs.KindNotFound, "group")
}

func (r groups) ListByOrg(_ context.Context, realmID, orgID string) ([]port.Group, error) {
	var out []port.Group
	for _, g := range r.t.s.groups {
		if g.RealmID == realmID && g.OrgID == orgID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r groups) Rename(_ context.Context, realmID, id, name string, updatedAt time.Time) error {
	g, err := r.Get(context.Background(), realmID, id)
	if err != nil {
		return err
	}
	g.Name, g.UpdatedAt = name, updatedAt
	if err := r.conflict(g); err != nil {
		return err
	}
	setKey(r.t, r.t.s.groups, id, g)
	return nil
}

func (r groups) Delete(_ context.Context, realmID, id string) error {
	if _, err := r.Get(context.Background(), realmID, id); err != nil {
		return err
	}
	for k, m := range r.t.s.groupMembers {
		if m.GroupID == id || m.MemberType == port.PrincipalGroup && m.MemberID == id {
			deleteKey(r.t, r.t.s.groupMembers, k)
		}
	}
	for k, l := range r.t.s.groupClosure {
		if l.realm == realmID && (l.group == id || l.ancestor == id) {
			deleteKey(r.t, r.t.s.groupClosure, k)
		}
	}
	deleteKey(r.t, r.t.s.groups, id)
	return nil
}

func (r groups) AddMember(_ context.Context, realmID string, m port.GroupMember) error {
	if _, err := r.Get(context.Background(), realmID, m.GroupID); err != nil {
		return err
	}
	k := memberKey(m.GroupID, m.MemberType, m.MemberID)
	if _, ok := r.t.s.groupMembers[k]; ok {
		return errs.New(errs.KindConflict, "group member exists")
	}
	setKey(r.t, r.t.s.groupMembers, k, m)
	return nil
}

func (r groups) RemoveMember(_ context.Context, realmID, groupID string, t port.PrincipalType, memberID string) error {
	if _, err := r.Get(context.Background(), realmID, groupID); err != nil {
		return err
	}
	k := memberKey(groupID, t, memberID)
	if _, ok := r.t.s.groupMembers[k]; !ok {
		return errs.New(errs.KindNotFound, "group member")
	}
	deleteKey(r.t, r.t.s.groupMembers, k)
	return nil
}

func (r groups) ListMembers(_ context.Context, realmID, groupID string) ([]port.GroupMember, error) {
	if _, err := r.Get(context.Background(), realmID, groupID); err != nil {
		return nil, err
	}
	var out []port.GroupMember
	for _, m := range r.t.s.groupMembers {
		if m.GroupID == groupID {
			out = append(out, m)
		}
	}
	sortByCreated(out, func(m port.GroupMember) (time.Time, string) { return m.CreatedAt, string(m.MemberType) + m.MemberID })
	return out, nil
}

func (r groups) ListByMember(_ context.Context, realmID string, t port.PrincipalType, memberID string) ([]port.Group, error) {
	type joined struct {
		g  port.Group
		at time.Time
	}
	var js []joined
	for _, m := range r.t.s.groupMembers {
		if m.MemberType != t || m.MemberID != memberID {
			continue
		}
		if g, ok := r.t.s.groups[m.GroupID]; ok && g.RealmID == realmID {
			js = append(js, joined{g, m.CreatedAt})
		}
	}
	sortByCreated(js, func(j joined) (time.Time, string) { return j.at, j.g.ID })
	out := make([]port.Group, len(js))
	for i, j := range js {
		out[i] = j.g
	}
	return out, nil
}

// groupLink は Group のネストの閉包の1行。
type groupLink struct {
	realm, group, ancestor string
	depth                  int
}

func (r groups) links(match func(groupLink) bool, key func(groupLink) string) []port.GroupLink {
	var out []port.GroupLink
	for _, l := range r.t.s.groupClosure {
		if match(l) {
			out = append(out, port.GroupLink{GroupID: key(l), Depth: l.depth})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].GroupID < out[j].GroupID
	})
	return out
}

func (r groups) Ancestors(_ context.Context, realmID, groupID string) ([]port.GroupLink, error) {
	return r.links(func(l groupLink) bool { return l.realm == realmID && l.group == groupID }, func(l groupLink) string { return l.ancestor }), nil
}

func (r groups) Descendants(_ context.Context, realmID, groupID string) ([]port.GroupLink, error) {
	return r.links(func(l groupLink) bool { return l.realm == realmID && l.ancestor == groupID }, func(l groupLink) string { return l.group }), nil
}

func (r groups) SetAncestors(_ context.Context, realmID, groupID string, ancestors []port.GroupLink) error {
	for k, l := range r.t.s.groupClosure {
		if l.realm == realmID && l.group == groupID {
			deleteKey(r.t, r.t.s.groupClosure, k)
		}
	}
	for _, a := range ancestors {
		k := realmID + "\x00" + groupID + "\x00" + a.GroupID
		if _, ok := r.t.s.groupClosure[k]; ok {
			return errs.New(errs.KindConflict, "group ancestor exists")
		}
		setKey(r.t, r.t.s.groupClosure, k, groupLink{realm: realmID, group: groupID, ancestor: a.GroupID, depth: a.Depth})
	}
	return nil
}

func (r groups) CountNested(context.Context) (int, error) {
	n := len(r.t.s.groupClosure)
	for _, m := range r.t.s.groupMembers {
		if m.MemberType == port.PrincipalGroup {
			n++
		}
	}
	return n, nil
}

func (r groups) PurgeNested(_ context.Context, limit int) (int, error) {
	n := 0
	for k := range r.t.s.groupClosure {
		if n >= limit {
			return n, nil
		}
		deleteKey(r.t, r.t.s.groupClosure, k)
		n++
	}
	for k, m := range r.t.s.groupMembers {
		if n >= limit {
			break
		}
		if m.MemberType == port.PrincipalGroup {
			deleteKey(r.t, r.t.s.groupMembers, k)
			n++
		}
	}
	return n, nil
}

type riskTypes struct{ t *tx }

func (r riskTypes) List(_ context.Context, realmID string) ([]port.RiskType, error) {
	var out []port.RiskType
	for _, t := range r.t.s.riskTypes {
		if t.RealmID == realmID {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b port.RiskType) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (r riskTypes) Put(_ context.Context, t port.RiskType) error {
	k := attrKey(t.RealmID, t.Name)
	if old, ok := r.t.s.riskTypes[k]; ok {
		t.CreatedAt = old.CreatedAt
	}
	setKey(r.t, r.t.s.riskTypes, k, t)
	return nil
}
