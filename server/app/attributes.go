package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// カスタム属性（design.md 11.7、ADR 0080）。運営者が定義と値を扱い、本人は編集できる属性を書く。

func attributeDefOut(d port.AttributeDef) adminapi.AttributeDef {
	out := adminapi.AttributeDef{Key: d.Key, Type: adminapi.AttributeDefType(d.Type), Values: append([]string{}, d.Values...), UserEditable: d.UserEditable,
		InToken: d.InToken, Encrypted: d.Encrypted, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}
	if d.Type == port.AttributeString {
		out.MaxLength = &d.MaxLength
	}
	return out
}

// rawValues は API の値を、属性の検証に渡す JSON にする。
func rawValues(in map[string]any) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = b
	}
	return out, nil
}

// attributesOff はフィーチャー custom_attributes が動いていなければ 404 attributes_disabled を返す。
func (s adminServer) attributesOff() (outcome, bool) {
	if s.a.attributes == nil {
		return failed(http.StatusNotFound, "attributes_disabled"), true
	}
	return outcome{}, false
}

// attributesCall は権限とフィーチャーを確かめて fn を1つのトランザクションで実行する。成功なら status は 200。
func (s adminServer) attributesCall(ctx context.Context, perm string, fn func(ctx context.Context, tx port.Tx, a attribute.Actor) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, perm)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.attributesOff(); off {
		return o, nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return fn(ctx, tx, attribute.Actor{Audit: p.Actor, RequestID: requestID(ctx)})
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListAttributeDefs(ctx context.Context, _ adminapi.ListAttributeDefsRequestObject) (adminapi.ListAttributeDefsResponseObject, error) {
	out := adminapi.ListAttributeDefs200JSONResponse{Attributes: []adminapi.AttributeDef{}}
	o, err := s.attributesCall(ctx, role.PermAttributesRead, func(ctx context.Context, tx port.Tx, _ attribute.Actor) error {
		ds, err := tx.Attributes().ListDefs(ctx, s.a.realm.ID)
		for _, d := range ds {
			out.Attributes = append(out.Attributes, attributeDefOut(d))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListAttributeDefs401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListAttributeDefs403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListAttributeDefs404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateAttributeDef(ctx context.Context, req adminapi.CreateAttributeDefRequestObject) (adminapi.CreateAttributeDefResponseObject, error) {
	var out port.AttributeDef
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if b := req.Body; b != nil {
		in := attribute.Def{Key: b.Key, Type: port.AttributeType(b.Type), Values: deref(b.Values), MaxLength: deref(b.MaxLength),
			UserEditable: deref(b.UserEditable), InToken: deref(b.InToken), Encrypted: deref(b.Encrypted)}
		o, err = s.attributesCall(ctx, role.PermAttributesManage, func(ctx context.Context, tx port.Tx, a attribute.Actor) error {
			out, err = s.a.attributes.Define(ctx, tx, s.a.realm.ID, in, a)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateAttributeDef201JSONResponse(attributeDefOut(out)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateAttributeDef400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateAttributeDef401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateAttributeDef403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateAttributeDef404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateAttributeDef409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateAttributeDef(ctx context.Context, req adminapi.UpdateAttributeDefRequestObject) (adminapi.UpdateAttributeDefResponseObject, error) {
	var out port.AttributeDef
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if b := req.Body; b != nil {
		in := attribute.Def{Key: req.Key, Values: deref(b.Values), MaxLength: deref(b.MaxLength), UserEditable: deref(b.UserEditable),
			InToken: deref(b.InToken)}
		o, err = s.attributesCall(ctx, role.PermAttributesManage, func(ctx context.Context, tx port.Tx, a attribute.Actor) error {
			out, err = s.a.attributes.Update(ctx, tx, s.a.realm.ID, in, a)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateAttributeDef200JSONResponse(attributeDefOut(out)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateAttributeDef400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateAttributeDef401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateAttributeDef403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateAttributeDef404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteAttributeDef(ctx context.Context, req adminapi.DeleteAttributeDefRequestObject) (adminapi.DeleteAttributeDefResponseObject, error) {
	o, err := s.attributesCall(ctx, role.PermAttributesManage, func(ctx context.Context, tx port.Tx, a attribute.Actor) error {
		return s.a.attributes.Delete(ctx, tx, s.a.realm.ID, req.Key, a)
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteAttributeDef204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteAttributeDef401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteAttributeDef403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteAttributeDef404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// attributeUser は管理 API の、値を扱うユーザー（削除済みは見つからない）。
func (s adminServer) attributeUser(ctx context.Context, tx port.Tx, publicID string) (port.User, error) {
	u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID)
	if err == nil && u.Status == port.UserDeleted {
		return port.User{}, errs.New(errs.KindNotFound, "user")
	}
	return u, err
}

func (s adminServer) GetUserAttributes(ctx context.Context, req adminapi.GetUserAttributesRequestObject) (adminapi.GetUserAttributesResponseObject, error) {
	var out map[string]any
	o, err := s.attributesCall(ctx, role.PermAttributesRead, func(ctx context.Context, tx port.Tx, _ attribute.Actor) error {
		u, err := s.attributeUser(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		out, err = s.a.attributes.Values(ctx, tx, u, false)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetUserAttributes200JSONResponse{Attributes: out}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetUserAttributes401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetUserAttributes403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetUserAttributes404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateUserAttributes(ctx context.Context, req adminapi.UpdateUserAttributesRequestObject) (adminapi.UpdateUserAttributesResponseObject, error) {
	var out map[string]any
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if req.Body != nil {
		var in map[string]json.RawMessage
		if in, err = rawValues(req.Body.Attributes); err != nil {
			return nil, err
		}
		o, err = s.attributesCall(ctx, role.PermAttributesWrite, func(ctx context.Context, tx port.Tx, a attribute.Actor) error {
			u, err := s.attributeUser(ctx, tx, req.Id)
			if err != nil {
				return err
			}
			if err := s.a.attributes.Set(ctx, tx, u, in, false, a); err != nil {
				return err
			}
			out, err = s.a.attributes.Values(ctx, tx, u, false)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateUserAttributes200JSONResponse{Attributes: out}, nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateUserAttributes400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateUserAttributes401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateUserAttributes403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateUserAttributes404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// myAttributes は本人の値と、本人が書ける属性の key。
func (s publicServer) myAttributes(ctx context.Context, tx port.Tx, u port.User) (publicapi.MyAttributes, error) {
	out := publicapi.MyAttributes{Editable: []string{}}
	vs, err := s.a.attributes.Values(ctx, tx, u, false)
	if err != nil {
		return out, err
	}
	out.Attributes = vs
	ds, err := tx.Attributes().ListDefs(ctx, s.a.realm.ID)
	for _, d := range ds {
		if d.UserEditable {
			out.Editable = append(out.Editable, d.Key)
		}
	}
	return out, err
}

func (s publicServer) GetMyAttributes(ctx context.Context, _ publicapi.GetMyAttributesRequestObject) (publicapi.GetMyAttributesResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.GetMyAttributes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.attributes == nil {
		return publicapi.GetMyAttributes404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var out publicapi.MyAttributes
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		out, err = s.myAttributes(ctx, tx, u)
		return err
	})
	if err != nil {
		return nil, err
	}
	return publicapi.GetMyAttributes200JSONResponse(out), nil
}

func (s publicServer) UpdateMyAttributes(ctx context.Context, req publicapi.UpdateMyAttributesRequestObject) (publicapi.UpdateMyAttributesResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.UpdateMyAttributes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.attributes == nil {
		return publicapi.UpdateMyAttributes404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.UpdateMyAttributes400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	in, err := rawValues(req.Body.Attributes)
	if err != nil {
		return nil, err
	}
	var out publicapi.MyAttributes
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		if err := s.a.attributes.Set(ctx, tx, u, in, true, attribute.Actor{Audit: au.Actor(), RequestID: requestID(ctx)}); err != nil {
			return err
		}
		out, err = s.myAttributes(ctx, tx, u)
		return err
	})
	switch {
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.UpdateMyAttributes403JSONResponse{DeniedJSONResponse: publicapi.DeniedJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.UpdateMyAttributes400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.UpdateMyAttributes200JSONResponse(out), nil
}
