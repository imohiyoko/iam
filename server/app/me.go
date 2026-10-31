package app

import (
	"context"

	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/port"
)

// GetMe は本人の情報を返す。内部 ID は出さず、Org も公開 ID で返す（ADR 0045）。
func (s publicServer) GetMe(ctx context.Context, _ publicapi.GetMeRequestObject) (publicapi.GetMeResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.GetMe401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	var out publicapi.GetMe200JSONResponse
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		out.Id, out.CreatedAt, out.DeletionScheduledAt = u.PublicID, u.CreatedAt, u.DeletionScheduledAt
		if u.ManagedOrgID != "" {
			o, err := tx.Orgs().Get(ctx, s.a.realm.ID, u.ManagedOrgID)
			if err != nil {
				return err
			}
			out.ManagedByOrgId = &o.PublicID
		}
		if au.ActiveOrgID != "" {
			o, err := tx.Orgs().Get(ctx, s.a.realm.ID, au.ActiveOrgID)
			if err != nil {
				return err
			}
			unavailable := append([]string{}, au.OrgUnavailable...)
			out.ActiveOrg = &struct {
				Id          string   `json:"id"`
				Unavailable []string `json:"unavailable"`
			}{Id: o.PublicID, Unavailable: unavailable}
		}
		m, err := s.a.accounts.ListMethods(ctx, tx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		for _, e := range m.Emails {
			if !e.IsPrimary {
				continue
			}
			me, err := s.myEmail(ctx, tx, e)
			if err != nil {
				return err
			}
			out.PrimaryEmail = &me
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Session.Id, out.Session.AuthenticatedAt = au.SessionID, au.AuthenticatedAt
	out.Session.AuthMethods = append([]string{}, au.AuthMethods...)
	return out, nil
}
