package app

import (
	"context"
	"errors"

	"github.com/imohiyoko/iam/authn/merge"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウント統合（design.md 11.6、ADR 0082）。

func (s publicServer) CreateMyMergeToken(ctx context.Context, _ publicapi.CreateMyMergeTokenRequestObject) (publicapi.CreateMyMergeTokenResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CreateMyMergeToken401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.merge == nil {
		return publicapi.CreateMyMergeToken404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if !s.recent(ctx, au, role.ActionMeMerge) {
		return publicapi.CreateMyMergeToken401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: "reauthentication_required"}}, nil
	}
	var t merge.Token
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		t, err = s.a.merge.Issue(ctx, tx, u)
		return err
	})
	if code, ok := stateCode(err); ok {
		return publicapi.CreateMyMergeToken409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.CreateMyMergeToken201JSONResponse{Token: t.Token, ExpiresAt: t.ExpiresAt}, nil
}

func (s publicServer) MergeIntoMe(ctx context.Context, req publicapi.MergeIntoMeRequestObject) (publicapi.MergeIntoMeResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.MergeIntoMe401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.merge == nil {
		return publicapi.MergeIntoMe404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if !s.recent(ctx, au, role.ActionMeMerge) {
		return publicapi.MergeIntoMe401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: "reauthentication_required"}}, nil
	}
	var m merge.Merged
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		m, err = s.a.merge.Merge(ctx, tx, u, req.Body.Token, au.Actor(), requestID(ctx))
		return err
	})
	var d errs.Denial
	switch code, conflict := stateCode(err); {
	case conflict:
		return publicapi.MergeIntoMe409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	case errors.As(err, &d):
		return publicapi.MergeIntoMe403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.MergeIntoMe400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, m.Sessions)
	out := publicapi.MergeIntoMe200JSONResponse{MergedUserId: m.From}
	if m.SharedOrg != "" {
		out.SharedOrgId, out.PersonalOrgId = &m.SharedOrg, &m.PersonalOrg
	}
	return out, nil
}
