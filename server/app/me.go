package app

import (
	"cmp"
	"context"
	"slices"

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
			mb, err := tx.Memberships().GetByUserOrg(ctx, s.a.realm.ID, au.PrincipalID, o.ID)
			if err != nil {
				return err
			}
			groups, err := myGroups(ctx, tx, s.a.realm.ID, au.PrincipalID, o.ID)
			if err != nil {
				return err
			}
			out.ActiveOrg = &publicapi.MeActiveOrg{Id: o.PublicID, Kind: publicapi.MeActiveOrgKind(o.Kind), Role: publicapi.MeActiveOrgRole(mb.Role),
				Unavailable: append([]string{}, au.OrgUnavailable...), Groups: groups}
			if o.Name != "" {
				out.ActiveOrg.Name = &o.Name
			}
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

// myGroups は Org の中でユーザーが入っている Group を名前の順に返す。入れ子で上の Group から受け継ぐものも含め、
// 直接の所属かを Direct で表す（design.md 11.5）。
func myGroups(ctx context.Context, tx port.Tx, realmID, userID, orgID string) ([]publicapi.MeGroup, error) {
	direct, err := tx.Groups().ListByMember(ctx, realmID, port.PrincipalUser, userID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*publicapi.MeGroup{}
	for _, g := range direct {
		if g.OrgID != orgID {
			continue
		}
		byID[g.ID] = &publicapi.MeGroup{Id: g.PublicID, Name: g.Name, Direct: true}
	}
	for _, g := range direct {
		if g.OrgID != orgID {
			continue
		}
		up, err := tx.Groups().Ancestors(ctx, realmID, g.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range up {
			if _, ok := byID[l.GroupID]; ok {
				continue
			}
			a, err := tx.Groups().Get(ctx, realmID, l.GroupID)
			if err != nil {
				return nil, err
			}
			if a.OrgID == orgID {
				byID[a.ID] = &publicapi.MeGroup{Id: a.PublicID, Name: a.Name}
			}
		}
	}
	out := make([]publicapi.MeGroup, 0, len(byID))
	for _, g := range byID {
		out = append(out, *g)
	}
	slices.SortFunc(out, func(x, y publicapi.MeGroup) int { return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.Id, y.Id)) })
	return out, nil
}
