package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type orgs struct{ t *tx }

func cloneOrg(o port.Org) port.Org {
	o.ValidFrom, o.ValidUntil = cloneTime(o.ValidFrom), cloneTime(o.ValidUntil)
	return o
}

func (r orgs) Create(_ context.Context, o port.Org) error {
	if _, ok := r.t.s.orgs[o.ID]; ok {
		return errs.New(errs.KindConflict, "org %s exists", o.ID)
	}
	for _, x := range r.t.s.orgs {
		if x.RealmID != o.RealmID {
			continue
		}
		if x.PublicID == o.PublicID {
			return errs.New(errs.KindConflict, "org public id exists in realm")
		}
		if o.Kind == port.OrgPersonal && x.Kind == port.OrgPersonal && x.PersonalOwnerID == o.PersonalOwnerID {
			return errs.New(errs.KindConflict, "personal org exists for user")
		}
	}
	setKey(r.t, r.t.s.orgs, o.ID, cloneOrg(o))
	return nil
}

func (r orgs) Get(_ context.Context, realmID, id string) (port.Org, error) {
	o, err := get(r.t.s.orgs, realmID, id, func(o port.Org) string { return o.RealmID }, "org")
	return cloneOrg(o), err
}

func (r orgs) GetByPublicID(_ context.Context, realmID, publicID string) (port.Org, error) {
	for _, x := range r.t.s.orgs {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneOrg(x), nil
		}
	}
	return port.Org{}, errs.New(errs.KindNotFound, "org")
}

func (r orgs) GetPersonal(_ context.Context, realmID, userID string) (port.Org, error) {
	for _, x := range r.t.s.orgs {
		if x.RealmID == realmID && x.Kind == port.OrgPersonal && x.PersonalOwnerID == userID {
			return cloneOrg(x), nil
		}
	}
	return port.Org{}, errs.New(errs.KindNotFound, "personal org")
}

func (r orgs) SetValidity(_ context.Context, realmID, id string, from, until *time.Time, updatedAt time.Time) error {
	o, err := get(r.t.s.orgs, realmID, id, func(o port.Org) string { return o.RealmID }, "org")
	if err != nil {
		return err
	}
	o = cloneOrg(o)
	o.ValidFrom, o.ValidUntil, o.UpdatedAt = cloneTime(from), cloneTime(until), updatedAt
	setKey(r.t, r.t.s.orgs, id, o)
	return nil
}

// ---------------------------------------------------------------------------

type memberships struct{ t *tx }

func cloneMembership(m port.Membership) port.Membership {
	m.ValidFrom, m.ValidUntil = cloneTime(m.ValidFrom), cloneTime(m.ValidUntil)
	return m
}

func (r memberships) Create(_ context.Context, m port.Membership) error {
	if _, ok := r.t.s.memberships[m.ID]; ok {
		return errs.New(errs.KindConflict, "membership %s exists", m.ID)
	}
	for _, x := range r.t.s.memberships {
		if x.RealmID != m.RealmID {
			continue
		}
		if x.PublicID == m.PublicID {
			return errs.New(errs.KindConflict, "membership public id exists in realm")
		}
		if x.UserID == m.UserID && x.OrgID == m.OrgID {
			return errs.New(errs.KindConflict, "membership exists for user and org")
		}
	}
	setKey(r.t, r.t.s.memberships, m.ID, cloneMembership(m))
	return nil
}

func (r memberships) Get(_ context.Context, realmID, id string) (port.Membership, error) {
	m, err := get(r.t.s.memberships, realmID, id, func(m port.Membership) string { return m.RealmID }, "membership")
	return cloneMembership(m), err
}

func (r memberships) GetByPublicID(_ context.Context, realmID, publicID string) (port.Membership, error) {
	for _, x := range r.t.s.memberships {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneMembership(x), nil
		}
	}
	return port.Membership{}, errs.New(errs.KindNotFound, "membership")
}

func (r memberships) GetByUserOrg(_ context.Context, realmID, userID, orgID string) (port.Membership, error) {
	for _, x := range r.t.s.memberships {
		if x.RealmID == realmID && x.UserID == userID && x.OrgID == orgID {
			return cloneMembership(x), nil
		}
	}
	return port.Membership{}, errs.New(errs.KindNotFound, "membership")
}

func (r memberships) list(match func(port.Membership) bool) []port.Membership {
	var out []port.Membership
	for _, x := range r.t.s.memberships {
		if match(x) {
			out = append(out, cloneMembership(x))
		}
	}
	sortByCreated(out, func(x port.Membership) (time.Time, string) { return x.CreatedAt, x.ID })
	return out
}

func (r memberships) ListByUser(_ context.Context, realmID, userID string) ([]port.Membership, error) {
	return r.list(func(x port.Membership) bool { return x.RealmID == realmID && x.UserID == userID }), nil
}

func (r memberships) ListByOrg(_ context.Context, realmID, orgID, afterPublicID string, limit int) ([]port.Membership, error) {
	out := r.list(func(x port.Membership) bool {
		return x.RealmID == realmID && x.OrgID == orgID && x.PublicID > afterPublicID
	})
	sort.Slice(out, func(i, j int) bool { return out[i].PublicID < out[j].PublicID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r memberships) CountActive(_ context.Context, realmID, orgID string, role port.OrgRole) (int, error) {
	return len(r.list(func(x port.Membership) bool {
		return x.RealmID == realmID && x.OrgID == orgID && x.Status == port.MembershipActive && x.Role == role
	})), nil
}

func (r memberships) Update(_ context.Context, m port.Membership) error {
	old, err := get(r.t.s.memberships, m.RealmID, m.ID, func(m port.Membership) string { return m.RealmID }, "membership")
	if err != nil {
		return err
	}
	m = cloneMembership(m)
	m.PublicID, m.UserID, m.OrgID, m.CreatedAt = old.PublicID, old.UserID, old.OrgID, old.CreatedAt
	setKey(r.t, r.t.s.memberships, m.ID, m)
	return nil
}

// ---------------------------------------------------------------------------

type invitations struct{ t *tx }

func cloneInvitation(i port.Invitation) port.Invitation {
	i.EmailIndex, i.EmailCiphertext, i.TokenHash = bytes.Clone(i.EmailIndex), bytes.Clone(i.EmailCiphertext), bytes.Clone(i.TokenHash)
	i.ValidFrom, i.ValidUntil, i.ClosedAt = cloneTime(i.ValidFrom), cloneTime(i.ValidUntil), cloneTime(i.ClosedAt)
	return i
}

func (r invitations) Create(_ context.Context, i port.Invitation) error {
	if _, ok := r.t.s.invitations[i.ID]; ok {
		return errs.New(errs.KindConflict, "invitation %s exists", i.ID)
	}
	for _, x := range r.t.s.invitations {
		if x.RealmID == i.RealmID && x.PublicID == i.PublicID {
			return errs.New(errs.KindConflict, "invitation public id exists in realm")
		}
	}
	setKey(r.t, r.t.s.invitations, i.ID, cloneInvitation(i))
	return nil
}

func (r invitations) GetByPublicID(_ context.Context, realmID, publicID string) (port.Invitation, error) {
	for _, x := range r.t.s.invitations {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneInvitation(x), nil
		}
	}
	return port.Invitation{}, errs.New(errs.KindNotFound, "invitation")
}

func (r invitations) ListByOrg(_ context.Context, realmID, orgID string) ([]port.Invitation, error) {
	var out []port.Invitation
	for _, x := range r.t.s.invitations {
		if x.RealmID == realmID && x.OrgID == orgID {
			out = append(out, cloneInvitation(x))
		}
	}
	sortByCreated(out, func(x port.Invitation) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r invitations) Close(_ context.Context, realmID, id string, status port.InvitationStatus, at time.Time, by string) (bool, error) {
	i, err := get(r.t.s.invitations, realmID, id, func(i port.Invitation) string { return i.RealmID }, "invitation")
	if err != nil || i.Status != port.InvitationPending {
		return false, err
	}
	i = cloneInvitation(i)
	i.Status, i.ClosedAt, i.ClosedBy = status, &at, by
	setKey(r.t, r.t.s.invitations, id, i)
	return true, nil
}
