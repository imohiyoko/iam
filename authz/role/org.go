package role

import (
	"slices"

	"github.com/imohiyoko/iam/shared/port"
)

// Org の中の権限（design.md 4.11）。M4 で Org 範囲のロールに置き換えるまでの、org_role ごとの固定の権限。
const (
	PermOrgRead     = "org:read"
	PermOrgInvite   = "org:invite"
	PermOrgRemove   = "org:remove"
	PermOrgSuspend  = "org:suspend" // Membership の customer_request の停止と解除
	PermOrgSettings = "org:settings"
	PermOrgTransfer = "org:transfer"
	PermOrgDelete   = "org:delete"
	// PermOrgRoles は Org の独自のロールと、Org の範囲のロールの付与の管理（M4。4.11）。
	PermOrgRoles = "org:roles"
	// PermOrgGroups は Org の Group と所属の管理（M4）。
	PermOrgGroups = "org:groups"
	// PermOrgGroupsRead は Org の Group と所属の参照だけ（ADR 0085）。Group をリソースに限って付与すると（resource_type が
	// group）、その Group の所属だけを読める。
	PermOrgGroupsRead = "org:groups.read"
)

var orgBuiltin = map[port.OrgRole][]string{
	port.OrgOwner:  {PermOrgRead, PermOrgInvite, PermOrgRemove, PermOrgSuspend, PermOrgSettings, PermOrgTransfer, PermOrgDelete, PermOrgRoles, PermOrgGroups, PermOrgGroupsRead},
	port.OrgAdmin:  {PermOrgRead, PermOrgInvite, PermOrgRemove, PermOrgSuspend, PermOrgRoles, PermOrgGroups, PermOrgGroupsRead},
	port.OrgMember: {PermOrgRead},
}

// OrgAllows は Membership が perm を持つかを返す。active でない Membership と、知らない org_role は権限を持たない。
func OrgAllows(m port.Membership, perm string) bool {
	return m.Status == port.MembershipActive && slices.Contains(orgBuiltin[m.Role], perm)
}
