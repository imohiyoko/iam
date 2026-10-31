package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ロール・付与・Group の管理の API の応答の組み立て（authzapi.go）。

func (s publicServer) ListMyOrgRoles(ctx context.Context, req publicapi.ListMyOrgRolesRequestObject) (publicapi.ListMyOrgRolesResponseObject, error) {
	var out []publicapi.Role
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listRoles(ctx, tx, c)
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.ListMyOrgRoles200JSONResponse{Roles: out}, nil
	case http.StatusUnauthorized:
		return publicapi.ListMyOrgRoles401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.ListMyOrgRoles403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.ListMyOrgRoles404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) ListRoles(ctx context.Context, req adminapi.ListRolesRequestObject) (adminapi.ListRolesResponseObject, error) {
	var out []publicapi.Role
	o, err := s.adminAuthz(ctx, role.PermRolesManage, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listRoles(ctx, tx, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		v := make([]adminapi.Role, 0, len(out))
		for _, x := range out {
			v = append(v, adminapi.Role(x))
		}
		return adminapi.ListRoles200JSONResponse{Roles: v}, nil
	case http.StatusUnauthorized:
		return adminapi.ListRoles401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.ListRoles403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.ListRoles404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) CreateMyOrgRole(ctx context.Context, req publicapi.CreateMyOrgRoleRequestObject) (publicapi.CreateMyOrgRoleResponseObject, error) {
	var out publicapi.Role
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createRole(ctx, tx, c, publicapi.RoleInput(*req.Body))
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.CreateMyOrgRole201JSONResponse(out), nil
	case http.StatusBadRequest:
		return publicapi.CreateMyOrgRole400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.CreateMyOrgRole401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.CreateMyOrgRole403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.CreateMyOrgRole404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.CreateMyOrgRole409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) CreateRole(ctx context.Context, req adminapi.CreateRoleRequestObject) (adminapi.CreateRoleResponseObject, error) {
	var out publicapi.Role
	o, err := s.adminAuthz(ctx, role.PermRolesManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createRole(ctx, tx, c, publicapi.RoleInput(*req.Body))
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.CreateRole201JSONResponse(adminapi.Role(out)), nil
	case http.StatusBadRequest:
		return adminapi.CreateRole400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.CreateRole401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.CreateRole403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.CreateRole404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.CreateRole409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) UpdateMyOrgRole(ctx context.Context, req publicapi.UpdateMyOrgRoleRequestObject) (publicapi.UpdateMyOrgRoleResponseObject, error) {
	var out publicapi.Role
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.updateRole(ctx, tx, c, req.RoleId, publicapi.RoleInput(*req.Body))
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.UpdateMyOrgRole200JSONResponse(out), nil
	case http.StatusBadRequest:
		return publicapi.UpdateMyOrgRole400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.UpdateMyOrgRole401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.UpdateMyOrgRole403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.UpdateMyOrgRole404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.UpdateMyOrgRole409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) UpdateRole(ctx context.Context, req adminapi.UpdateRoleRequestObject) (adminapi.UpdateRoleResponseObject, error) {
	var out publicapi.Role
	o, err := s.adminAuthz(ctx, role.PermRolesManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.updateRole(ctx, tx, c, req.RoleId, publicapi.RoleInput(*req.Body))
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.UpdateRole200JSONResponse(adminapi.Role(out)), nil
	case http.StatusBadRequest:
		return adminapi.UpdateRole400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.UpdateRole401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.UpdateRole403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.UpdateRole404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.UpdateRole409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) DeleteMyOrgRole(ctx context.Context, req publicapi.DeleteMyOrgRoleRequestObject) (publicapi.DeleteMyOrgRoleResponseObject, error) {
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteRole(ctx, tx, c, req.RoleId)
	})
	switch st {
	case http.StatusOK:
		return publicapi.DeleteMyOrgRole204Response{}, nil
	case http.StatusUnauthorized:
		return publicapi.DeleteMyOrgRole401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.DeleteMyOrgRole403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.DeleteMyOrgRole404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) DeleteRole(ctx context.Context, req adminapi.DeleteRoleRequestObject) (adminapi.DeleteRoleResponseObject, error) {
	o, err := s.adminAuthz(ctx, role.PermRolesManage, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteRole(ctx, tx, c, req.RoleId)
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.DeleteRole204Response{}, nil
	case http.StatusUnauthorized:
		return adminapi.DeleteRole401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.DeleteRole403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.DeleteRole404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) ListMyOrgRoleBindings(ctx context.Context, req publicapi.ListMyOrgRoleBindingsRequestObject) (publicapi.ListMyOrgRoleBindingsResponseObject, error) {
	var out []publicapi.RoleBinding
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listBindings(ctx, tx, c)
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.ListMyOrgRoleBindings200JSONResponse{Bindings: out}, nil
	case http.StatusUnauthorized:
		return publicapi.ListMyOrgRoleBindings401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.ListMyOrgRoleBindings403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.ListMyOrgRoleBindings404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) ListRoleBindings(ctx context.Context, req adminapi.ListRoleBindingsRequestObject) (adminapi.ListRoleBindingsResponseObject, error) {
	var out []publicapi.RoleBinding
	o, err := s.adminAuthz(ctx, role.PermRolesManage, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listBindings(ctx, tx, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		v := make([]adminapi.RoleBinding, 0, len(out))
		for _, x := range out {
			v = append(v, adminapi.RoleBinding(x))
		}
		return adminapi.ListRoleBindings200JSONResponse{Bindings: v}, nil
	case http.StatusUnauthorized:
		return adminapi.ListRoleBindings401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.ListRoleBindings403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.ListRoleBindings404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) CreateMyOrgRoleBinding(ctx context.Context, req publicapi.CreateMyOrgRoleBindingRequestObject) (publicapi.CreateMyOrgRoleBindingResponseObject, error) {
	var out publicapi.RoleBinding
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createBinding(ctx, tx, c, publicapi.RoleBindingInput(*req.Body))
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.CreateMyOrgRoleBinding201JSONResponse(out), nil
	case http.StatusBadRequest:
		return publicapi.CreateMyOrgRoleBinding400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.CreateMyOrgRoleBinding401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.CreateMyOrgRoleBinding403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.CreateMyOrgRoleBinding404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.CreateMyOrgRoleBinding409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) CreateRoleBinding(ctx context.Context, req adminapi.CreateRoleBindingRequestObject) (adminapi.CreateRoleBindingResponseObject, error) {
	var out publicapi.RoleBinding
	o, err := s.adminAuthz(ctx, role.PermRolesManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createBinding(ctx, tx, c, publicapi.RoleBindingInput(*req.Body))
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.CreateRoleBinding201JSONResponse(adminapi.RoleBinding(out)), nil
	case http.StatusBadRequest:
		return adminapi.CreateRoleBinding400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.CreateRoleBinding401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.CreateRoleBinding403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.CreateRoleBinding404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.CreateRoleBinding409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) DeleteMyOrgRoleBinding(ctx context.Context, req publicapi.DeleteMyOrgRoleBindingRequestObject) (publicapi.DeleteMyOrgRoleBindingResponseObject, error) {
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgRoles, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteBinding(ctx, tx, c, req.BindingId)
	})
	switch st {
	case http.StatusOK:
		return publicapi.DeleteMyOrgRoleBinding204Response{}, nil
	case http.StatusUnauthorized:
		return publicapi.DeleteMyOrgRoleBinding401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.DeleteMyOrgRoleBinding403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.DeleteMyOrgRoleBinding404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.DeleteMyOrgRoleBinding409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) DeleteRoleBinding(ctx context.Context, req adminapi.DeleteRoleBindingRequestObject) (adminapi.DeleteRoleBindingResponseObject, error) {
	o, err := s.adminAuthz(ctx, role.PermRolesManage, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteBinding(ctx, tx, c, req.BindingId)
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.DeleteRoleBinding204Response{}, nil
	case http.StatusUnauthorized:
		return adminapi.DeleteRoleBinding401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.DeleteRoleBinding403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.DeleteRoleBinding404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.DeleteRoleBinding409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) ListMyOrgGroups(ctx context.Context, req publicapi.ListMyOrgGroupsRequestObject) (publicapi.ListMyOrgGroupsResponseObject, error) {
	var out []publicapi.Group
	st, e, err := s.orgAuthz(ctx, req.Id, "", false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		if err := s.a.readGroups(ctx, tx, c, ""); err != nil {
			return err
		}
		out, err = s.a.listGroups(ctx, tx, c)
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.ListMyOrgGroups200JSONResponse{Groups: out}, nil
	case http.StatusUnauthorized:
		return publicapi.ListMyOrgGroups401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.ListMyOrgGroups403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.ListMyOrgGroups404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s publicServer) ListMyGroupsInOrg(ctx context.Context, req publicapi.ListMyGroupsInOrgRequestObject) (publicapi.ListMyGroupsInOrgResponseObject, error) {
	au, ok := authFrom(ctx)
	switch {
	case !ok:
		return publicapi.ListMyGroupsInOrg401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case s.a.orgs == nil:
		return publicapi.ListMyGroupsInOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var out []publicapi.MyGroup
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, "")
		if err != nil {
			return err
		}
		out, err = s.a.myGroups(ctx, tx, s.a.realm.ID, au.PrincipalID, o.ID)
		return err
	})
	switch {
	case err == nil:
		return publicapi.ListMyGroupsInOrg200JSONResponse{Groups: out}, nil
	case errors.Is(err, errs.NotFound):
		return publicapi.ListMyGroupsInOrg404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.ListMyGroupsInOrg403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	}
	return nil, err
}

func (s adminServer) ListGroups(ctx context.Context, req adminapi.ListGroupsRequestObject) (adminapi.ListGroupsResponseObject, error) {
	var out []publicapi.Group
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listGroups(ctx, tx, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		v := make([]adminapi.Group, 0, len(out))
		for _, x := range out {
			v = append(v, adminapi.Group(x))
		}
		return adminapi.ListGroups200JSONResponse{Groups: v}, nil
	case http.StatusUnauthorized:
		return adminapi.ListGroups401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.ListGroups403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.ListGroups404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) CreateMyOrgGroup(ctx context.Context, req publicapi.CreateMyOrgGroupRequestObject) (publicapi.CreateMyOrgGroupResponseObject, error) {
	var out publicapi.Group
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgGroups, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createGroup(ctx, tx, c, publicapi.GroupInput(*req.Body))
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.CreateMyOrgGroup201JSONResponse(out), nil
	case http.StatusBadRequest:
		return publicapi.CreateMyOrgGroup400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.CreateMyOrgGroup401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.CreateMyOrgGroup403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.CreateMyOrgGroup404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.CreateMyOrgGroup409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) CreateGroup(ctx context.Context, req adminapi.CreateGroupRequestObject) (adminapi.CreateGroupResponseObject, error) {
	var out publicapi.Group
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.createGroup(ctx, tx, c, publicapi.GroupInput(*req.Body))
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.CreateGroup201JSONResponse(adminapi.Group(out)), nil
	case http.StatusBadRequest:
		return adminapi.CreateGroup400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.CreateGroup401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.CreateGroup403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.CreateGroup404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.CreateGroup409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) RenameMyOrgGroup(ctx context.Context, req publicapi.RenameMyOrgGroupRequestObject) (publicapi.RenameMyOrgGroupResponseObject, error) {
	var out publicapi.Group
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgGroups, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.renameGroup(ctx, tx, c, req.GroupId, publicapi.GroupInput(*req.Body))
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.RenameMyOrgGroup200JSONResponse(out), nil
	case http.StatusBadRequest:
		return publicapi.RenameMyOrgGroup400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.RenameMyOrgGroup401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.RenameMyOrgGroup403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.RenameMyOrgGroup404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.RenameMyOrgGroup409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) RenameGroup(ctx context.Context, req adminapi.RenameGroupRequestObject) (adminapi.RenameGroupResponseObject, error) {
	var out publicapi.Group
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.renameGroup(ctx, tx, c, req.GroupId, publicapi.GroupInput(*req.Body))
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.RenameGroup200JSONResponse(adminapi.Group(out)), nil
	case http.StatusBadRequest:
		return adminapi.RenameGroup400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.RenameGroup401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.RenameGroup403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.RenameGroup404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.RenameGroup409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) DeleteMyOrgGroup(ctx context.Context, req publicapi.DeleteMyOrgGroupRequestObject) (publicapi.DeleteMyOrgGroupResponseObject, error) {
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgGroups, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteGroup(ctx, tx, c, req.GroupId)
	})
	switch st {
	case http.StatusOK:
		return publicapi.DeleteMyOrgGroup204Response{}, nil
	case http.StatusUnauthorized:
		return publicapi.DeleteMyOrgGroup401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.DeleteMyOrgGroup403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.DeleteMyOrgGroup404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) DeleteGroup(ctx context.Context, req adminapi.DeleteGroupRequestObject) (adminapi.DeleteGroupResponseObject, error) {
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, false, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.deleteGroup(ctx, tx, c, req.GroupId)
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.DeleteGroup204Response{}, nil
	case http.StatusUnauthorized:
		return adminapi.DeleteGroup401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.DeleteGroup403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.DeleteGroup404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) ListMyOrgGroupMembers(ctx context.Context, req publicapi.ListMyOrgGroupMembersRequestObject) (publicapi.ListMyOrgGroupMembersResponseObject, error) {
	var out []publicapi.GroupMember
	st, e, err := s.orgAuthz(ctx, req.Id, "", false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		if err := s.a.readGroups(ctx, tx, c, req.GroupId); err != nil {
			return err
		}
		out, err = s.a.listGroupMembers(ctx, tx, c, req.GroupId)
		return err
	})
	switch st {
	case http.StatusOK:
		return publicapi.ListMyOrgGroupMembers200JSONResponse{Members: out}, nil
	case http.StatusUnauthorized:
		return publicapi.ListMyOrgGroupMembers401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.ListMyOrgGroupMembers403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.ListMyOrgGroupMembers404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) ListGroupMembers(ctx context.Context, req adminapi.ListGroupMembersRequestObject) (adminapi.ListGroupMembersResponseObject, error) {
	var out []publicapi.GroupMember
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, false, func(ctx context.Context, tx port.Tx, c authzCall) (err error) {
		out, err = s.a.listGroupMembers(ctx, tx, c, req.GroupId)
		return err
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		v := make([]adminapi.GroupMember, 0, len(out))
		for _, x := range out {
			v = append(v, adminapi.GroupMember(x))
		}
		return adminapi.ListGroupMembers200JSONResponse{Members: v}, nil
	case http.StatusUnauthorized:
		return adminapi.ListGroupMembers401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusForbidden:
		return adminapi.ListGroupMembers403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.ListGroupMembers404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) AddMyOrgGroupMember(ctx context.Context, req publicapi.AddMyOrgGroupMemberRequestObject) (publicapi.AddMyOrgGroupMemberResponseObject, error) {
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgGroups, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.addGroupMember(ctx, tx, c, req.GroupId, publicapi.GroupMemberInput(*req.Body))
	})
	switch st {
	case http.StatusOK:
		return publicapi.AddMyOrgGroupMember204Response{}, nil
	case http.StatusBadRequest:
		return publicapi.AddMyOrgGroupMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.AddMyOrgGroupMember401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.AddMyOrgGroupMember403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.AddMyOrgGroupMember404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	case http.StatusConflict:
		return publicapi.AddMyOrgGroupMember409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) AddGroupMember(ctx context.Context, req adminapi.AddGroupMemberRequestObject) (adminapi.AddGroupMemberResponseObject, error) {
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.addGroupMember(ctx, tx, c, req.GroupId, publicapi.GroupMemberInput(*req.Body))
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.AddGroupMember204Response{}, nil
	case http.StatusBadRequest:
		return adminapi.AddGroupMember400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.AddGroupMember401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.AddGroupMember403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.AddGroupMember404JSONResponse(e), nil
	case http.StatusConflict:
		return adminapi.AddGroupMember409JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}

func (s publicServer) RemoveMyOrgGroupMember(ctx context.Context, req publicapi.RemoveMyOrgGroupMemberRequestObject) (publicapi.RemoveMyOrgGroupMemberResponseObject, error) {
	st, e, err := s.orgAuthz(ctx, req.Id, role.PermOrgGroups, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.removeGroupMember(ctx, tx, c, req.GroupId, publicapi.GroupMemberInput(*req.Body))
	})
	switch st {
	case http.StatusOK:
		return publicapi.RemoveMyOrgGroupMember204Response{}, nil
	case http.StatusBadRequest:
		return publicapi.RemoveMyOrgGroupMember400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return publicapi.RemoveMyOrgGroupMember401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse(e)}, nil
	case http.StatusForbidden:
		return publicapi.RemoveMyOrgGroupMember403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse(e)}, nil
	case http.StatusNotFound:
		return publicapi.RemoveMyOrgGroupMember404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse(e)}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errStatus(st)
}

func (s adminServer) RemoveGroupMember(ctx context.Context, req adminapi.RemoveGroupMemberRequestObject) (adminapi.RemoveGroupMemberResponseObject, error) {
	o, err := s.adminAuthz(ctx, role.PermGroupsManage, req.Body == nil, func(ctx context.Context, tx port.Tx, c authzCall) error {
		return s.a.removeGroupMember(ctx, tx, c, req.GroupId, publicapi.GroupMemberInput(*req.Body))
	})
	if err != nil {
		return nil, err
	}
	e := o.body
	switch o.status {
	case http.StatusOK:
		return adminapi.RemoveGroupMember204Response{}, nil
	case http.StatusBadRequest:
		return adminapi.RemoveGroupMember400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(e)}, nil
	case http.StatusUnauthorized:
		return adminapi.RemoveGroupMember401JSONResponse(e), nil
	case http.StatusForbidden:
		return adminapi.RemoveGroupMember403JSONResponse(e), nil
	case http.StatusNotFound:
		return adminapi.RemoveGroupMember404JSONResponse(e), nil
	}
	return nil, errStatus(o.status)
}
