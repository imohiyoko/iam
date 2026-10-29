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
	o.DeletionScheduledAt, o.DeletedAt = cloneTime(o.DeletionScheduledAt), cloneTime(o.DeletedAt)
	o.Settings = bytes.Clone(o.Settings)
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

func (r orgs) List(_ context.Context, realmID, afterID string, limit int) ([]port.Org, error) {
	var out []port.Org
	for _, o := range r.t.s.orgs {
		if o.RealmID == realmID && o.ID > afterID {
			out = append(out, cloneOrg(o))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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

func (r orgs) SetDeletion(_ context.Context, realmID, id string, scheduledAt, deletedAt *time.Time, updatedAt time.Time) error {
	o, err := get(r.t.s.orgs, realmID, id, func(o port.Org) string { return o.RealmID }, "org")
	if err != nil {
		return err
	}
	o = cloneOrg(o)
	o.DeletionScheduledAt, o.DeletedAt, o.UpdatedAt = cloneTime(scheduledAt), cloneTime(deletedAt), updatedAt
	setKey(r.t, r.t.s.orgs, id, o)
	return nil
}

func (r orgs) SetSettings(_ context.Context, realmID, id string, settings []byte, updatedAt time.Time) error {
	o, err := get(r.t.s.orgs, realmID, id, func(o port.Org) string { return o.RealmID }, "org")
	if err != nil {
		return err
	}
	o = cloneOrg(o)
	o.Settings, o.UpdatedAt = bytes.Clone(settings), updatedAt
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

// ---------------------------------------------------------------------------

type quotaGrants struct{ t *tx }

func cloneQuotaGrant(g port.QuotaGrant) port.QuotaGrant {
	g.EndsAt = cloneTime(g.EndsAt)
	return g
}

func (r quotaGrants) Create(_ context.Context, g port.QuotaGrant) error {
	if _, ok := r.t.s.quotaGrants[g.ID]; ok {
		return errs.New(errs.KindConflict, "quota grant %s exists", g.ID)
	}
	for _, x := range r.t.s.quotaGrants {
		if x.RealmID == g.RealmID && x.PublicID == g.PublicID {
			return errs.New(errs.KindConflict, "quota grant public id exists in realm")
		}
		if g.ExternalRef != "" && x.RealmID == g.RealmID && x.OrgID == g.OrgID && x.QuotaKey == g.QuotaKey && x.ExternalRef == g.ExternalRef {
			return errs.New(errs.KindConflict, "quota grant external ref exists")
		}
	}
	setKey(r.t, r.t.s.quotaGrants, g.ID, cloneQuotaGrant(g))
	return nil
}

func (r quotaGrants) GetByPublicID(_ context.Context, realmID, publicID string) (port.QuotaGrant, error) {
	for _, x := range r.t.s.quotaGrants {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneQuotaGrant(x), nil
		}
	}
	return port.QuotaGrant{}, errs.New(errs.KindNotFound, "quota grant")
}

func (r quotaGrants) GetByExternalRef(_ context.Context, realmID, orgID, quotaKey, ref string) (port.QuotaGrant, error) {
	for _, x := range r.t.s.quotaGrants {
		if ref != "" && x.RealmID == realmID && x.OrgID == orgID && x.QuotaKey == quotaKey && x.ExternalRef == ref {
			return cloneQuotaGrant(x), nil
		}
	}
	return port.QuotaGrant{}, errs.New(errs.KindNotFound, "quota grant")
}

func (r quotaGrants) ListByOrg(_ context.Context, realmID, orgID, quotaKey string) ([]port.QuotaGrant, error) {
	var out []port.QuotaGrant
	for _, x := range r.t.s.quotaGrants {
		if x.RealmID == realmID && x.OrgID == orgID && x.QuotaKey == quotaKey {
			out = append(out, cloneQuotaGrant(x))
		}
	}
	sortByCreated(out, func(x port.QuotaGrant) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r quotaGrants) Update(_ context.Context, g port.QuotaGrant) error {
	x, err := get(r.t.s.quotaGrants, g.RealmID, g.ID, func(g port.QuotaGrant) string { return g.RealmID }, "quota grant")
	if err != nil {
		return err
	}
	x.Kind, x.Quantity, x.StartsAt, x.EndsAt, x.UpdatedAt = g.Kind, g.Quantity, g.StartsAt, cloneTime(g.EndsAt), g.UpdatedAt
	setKey(r.t, r.t.s.quotaGrants, x.ID, x)
	return nil
}

func (r quotaGrants) Count(context.Context) (int, error) { return len(r.t.s.quotaGrants), nil }

func (r quotaGrants) Purge(_ context.Context, limit int) (int, error) {
	n := 0
	for id := range r.t.s.quotaGrants {
		if n >= limit {
			break
		}
		deleteKey(r.t, r.t.s.quotaGrants, id)
		n++
	}
	return n, nil
}

func (r quotaGrants) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.quotaGrants, realmID, id, func(g port.QuotaGrant) string { return g.RealmID }, "quota grant"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.quotaGrants, id)
	return nil
}

// ---------------------------------------------------------------------------

type orgDomains struct{ t *tx }

func cloneOrgDomain(d port.OrgDomain) port.OrgDomain {
	d.VerifiedAt, d.CheckedAt = cloneTime(d.VerifiedAt), cloneTime(d.CheckedAt)
	return d
}

func (r orgDomains) Create(_ context.Context, d port.OrgDomain) error {
	if _, ok := r.t.s.orgDomains[d.ID]; ok {
		return errs.New(errs.KindConflict, "org domain %s exists", d.ID)
	}
	for _, x := range r.t.s.orgDomains {
		if x.RealmID == d.RealmID && x.PublicID == d.PublicID {
			return errs.New(errs.KindConflict, "org domain public id exists in realm")
		}
		if x.RealmID == d.RealmID && x.OrgID == d.OrgID && x.Domain == d.Domain {
			return errs.New(errs.KindConflict, "org domain exists in org")
		}
		if d.VerifiedAt != nil && x.VerifiedAt != nil && x.RealmID == d.RealmID && x.Domain == d.Domain {
			return errs.New(errs.KindConflict, "org domain verified by another org")
		}
	}
	setKey(r.t, r.t.s.orgDomains, d.ID, cloneOrgDomain(d))
	return nil
}

func (r orgDomains) GetByPublicID(_ context.Context, realmID, publicID string) (port.OrgDomain, error) {
	for _, x := range r.t.s.orgDomains {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneOrgDomain(x), nil
		}
	}
	return port.OrgDomain{}, errs.New(errs.KindNotFound, "org domain")
}

func (r orgDomains) GetVerified(_ context.Context, realmID, domain string) (port.OrgDomain, error) {
	for _, x := range r.t.s.orgDomains {
		if x.RealmID == realmID && x.Domain == domain && x.VerifiedAt != nil {
			return cloneOrgDomain(x), nil
		}
	}
	return port.OrgDomain{}, errs.New(errs.KindNotFound, "org domain")
}

func (r orgDomains) ListByOrg(_ context.Context, realmID, orgID string) ([]port.OrgDomain, error) {
	var out []port.OrgDomain
	for _, x := range r.t.s.orgDomains {
		if x.RealmID == realmID && x.OrgID == orgID {
			out = append(out, cloneOrgDomain(x))
		}
	}
	sortByCreated(out, func(x port.OrgDomain) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r orgDomains) Update(_ context.Context, d port.OrgDomain) error {
	x, err := get(r.t.s.orgDomains, d.RealmID, d.ID, func(d port.OrgDomain) string { return d.RealmID }, "org domain")
	if err != nil {
		return err
	}
	if d.VerifiedAt != nil {
		for _, y := range r.t.s.orgDomains {
			if y.ID != x.ID && y.RealmID == x.RealmID && y.Domain == x.Domain && y.VerifiedAt != nil {
				return errs.New(errs.KindConflict, "org domain verified by another org")
			}
		}
	}
	x.VerifiedAt, x.CheckedAt = cloneTime(d.VerifiedAt), cloneTime(d.CheckedAt)
	setKey(r.t, r.t.s.orgDomains, x.ID, x)
	return nil
}

func (r orgDomains) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.orgDomains, realmID, id, func(d port.OrgDomain) string { return d.RealmID }, "org domain"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.orgDomains, id)
	return nil
}

func (r orgDomains) Count(context.Context) (int, error) { return len(r.t.s.orgDomains), nil }

func (r orgDomains) Purge(_ context.Context, limit int) (int, error) {
	n := 0
	for id := range r.t.s.orgDomains {
		if n >= limit {
			break
		}
		deleteKey(r.t, r.t.s.orgDomains, id)
		n++
	}
	return n, nil
}
