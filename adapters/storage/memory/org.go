package memory

import (
	"context"
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

func (r memberships) ListByOrg(_ context.Context, realmID, orgID string) ([]port.Membership, error) {
	return r.list(func(x port.Membership) bool { return x.RealmID == realmID && x.OrgID == orgID }), nil
}
