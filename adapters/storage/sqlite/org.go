package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type orgs struct{ q *db.Queries }

func toOrg(r db.Org) (port.Org, error) {
	var p times
	o := port.Org{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, Kind: port.OrgKind(r.Kind), Name: r.Name,
		PersonalOwnerID: r.PersonalOwnerID, ValidFrom: p.null(r.ValidFrom), ValidUntil: p.null(r.ValidUntil),
		DeletionScheduledAt: p.null(r.DeletionScheduledAt), DeletedAt: p.null(r.DeletedAt), Settings: r.Settings, CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	return o, p.err
}

func (r orgs) Create(ctx context.Context, o port.Org) error {
	return mapErr(r.q.CreateOrg(ctx, db.CreateOrgParams{ID: o.ID, PublicID: o.PublicID, RealmID: o.RealmID, Kind: string(o.Kind),
		Name: o.Name, PersonalOwnerID: o.PersonalOwnerID, ValidFrom: nullTime(o.ValidFrom), ValidUntil: nullTime(o.ValidUntil),
		CreatedAt: formatTime(o.CreatedAt), UpdatedAt: formatTime(o.UpdatedAt)}))
}

func (r orgs) Get(ctx context.Context, realmID, id string) (port.Org, error) {
	row, err := r.q.GetOrg(ctx, db.GetOrgParams{RealmID: realmID, ID: id})
	return one(row, err, toOrg)
}

func (r orgs) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Org, error) {
	row, err := r.q.GetOrgByPublicID(ctx, db.GetOrgByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toOrg)
}

func (r orgs) GetPersonal(ctx context.Context, realmID, userID string) (port.Org, error) {
	row, err := r.q.GetPersonalOrg(ctx, db.GetPersonalOrgParams{RealmID: realmID, PersonalOwnerID: userID})
	return one(row, err, toOrg)
}

func (r orgs) SetValidity(ctx context.Context, realmID, id string, from, until *time.Time, updatedAt time.Time) error {
	n, err := r.q.SetOrgValidity(ctx, db.SetOrgValidityParams{ValidFrom: nullTime(from), ValidUntil: nullTime(until), UpdatedAt: formatTime(updatedAt),
		RealmID: realmID, ID: id})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "org")
	}
	return nil
}

func (r orgs) SetDeletion(ctx context.Context, realmID, id string, scheduledAt, deletedAt *time.Time, updatedAt time.Time) error {
	n, err := r.q.SetOrgDeletion(ctx, db.SetOrgDeletionParams{DeletionScheduledAt: nullTime(scheduledAt), DeletedAt: nullTime(deletedAt),
		UpdatedAt: formatTime(updatedAt), RealmID: realmID, ID: id})
	return affected(n, err, "org")
}

func (r orgs) SetSettings(ctx context.Context, realmID, id string, settings []byte, updatedAt time.Time) error {
	n, err := r.q.SetOrgSettings(ctx, db.SetOrgSettingsParams{Settings: settings, UpdatedAt: formatTime(updatedAt), RealmID: realmID, ID: id})
	return affected(n, err, "org")
}

// ---------------------------------------------------------------------------

type memberships struct{ q *db.Queries }

func toMembership(r db.Membership) (port.Membership, error) {
	var p times
	m := port.Membership{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, UserID: r.UserID, OrgID: r.OrgID,
		Status: port.MembershipStatus(r.Status), Role: port.OrgRole(r.OrgRole), EmailID: r.EmailID, ValidFrom: p.null(r.ValidFrom),
		ValidUntil: p.null(r.ValidUntil), EndedReason: r.EndedReason, CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	return m, p.err
}

func (r memberships) Create(ctx context.Context, m port.Membership) error {
	return mapErr(r.q.CreateMembership(ctx, db.CreateMembershipParams{ID: m.ID, PublicID: m.PublicID, RealmID: m.RealmID,
		UserID: m.UserID, OrgID: m.OrgID, Status: string(m.Status), OrgRole: string(m.Role), EmailID: m.EmailID,
		ValidFrom: nullTime(m.ValidFrom), ValidUntil: nullTime(m.ValidUntil), EndedReason: m.EndedReason,
		CreatedAt: formatTime(m.CreatedAt), UpdatedAt: formatTime(m.UpdatedAt)}))
}

func (r memberships) Get(ctx context.Context, realmID, id string) (port.Membership, error) {
	row, err := r.q.GetMembership(ctx, db.GetMembershipParams{RealmID: realmID, ID: id})
	return one(row, err, toMembership)
}

func (r memberships) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Membership, error) {
	row, err := r.q.GetMembershipByPublicID(ctx, db.GetMembershipByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toMembership)
}

func (r memberships) GetByUserOrg(ctx context.Context, realmID, userID, orgID string) (port.Membership, error) {
	row, err := r.q.GetMembershipByUserOrg(ctx, db.GetMembershipByUserOrgParams{RealmID: realmID, UserID: userID, OrgID: orgID})
	return one(row, err, toMembership)
}

func (r memberships) ListByUser(ctx context.Context, realmID, userID string) ([]port.Membership, error) {
	rs, err := r.q.ListMembershipsByUser(ctx, db.ListMembershipsByUserParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toMembership)
}

func (r memberships) ListByOrg(ctx context.Context, realmID, orgID, afterPublicID string, limit int) ([]port.Membership, error) {
	rs, err := r.q.ListMembershipsByOrg(ctx, db.ListMembershipsByOrgParams{RealmID: realmID, OrgID: orgID, After: afterPublicID, Lim: int64(limit)})
	return rows(rs, err, toMembership)
}

func (r memberships) CountActive(ctx context.Context, realmID, orgID string, role port.OrgRole) (int, error) {
	n, err := r.q.CountActiveMemberships(ctx, db.CountActiveMembershipsParams{RealmID: realmID, OrgID: orgID, OrgRole: string(role)})
	return int(n), mapErr(err)
}

func (r memberships) Update(ctx context.Context, m port.Membership) error {
	n, err := r.q.UpdateMembership(ctx, db.UpdateMembershipParams{Status: string(m.Status), OrgRole: string(m.Role), EmailID: m.EmailID,
		ValidFrom: nullTime(m.ValidFrom), ValidUntil: nullTime(m.ValidUntil), EndedReason: m.EndedReason, UpdatedAt: formatTime(m.UpdatedAt),
		RealmID: m.RealmID, ID: m.ID})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "membership")
	}
	return nil
}

// ---------------------------------------------------------------------------

type invitations struct{ q *db.Queries }

func toInvitation(r db.Invitation) (port.Invitation, error) {
	var p times
	i := port.Invitation{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, OrgID: r.OrgID, EmailIndex: r.EmailIndex,
		EmailCiphertext: r.EmailCiphertext, IndexKeyID: r.IndexKeyID, Role: port.OrgRole(r.OrgRole), TokenHash: r.TokenHash,
		ValidFrom: p.null(r.ValidFrom), ValidUntil: p.null(r.ValidUntil), InvitedBy: r.InvitedBy, ExpiresAt: p.at(r.ExpiresAt),
		Status: port.InvitationStatus(r.Status), CreatedAt: p.at(r.CreatedAt), ClosedAt: p.null(r.ClosedAt), ClosedBy: r.ClosedBy}
	return i, p.err
}

func (r invitations) Create(ctx context.Context, i port.Invitation) error {
	return mapErr(r.q.CreateInvitation(ctx, db.CreateInvitationParams{ID: i.ID, PublicID: i.PublicID, RealmID: i.RealmID, OrgID: i.OrgID,
		EmailIndex: nonNil(i.EmailIndex), EmailCiphertext: nonNil(i.EmailCiphertext), IndexKeyID: i.IndexKeyID, OrgRole: string(i.Role),
		TokenHash: nonNil(i.TokenHash), ValidFrom: nullTime(i.ValidFrom), ValidUntil: nullTime(i.ValidUntil), InvitedBy: i.InvitedBy,
		ExpiresAt: formatTime(i.ExpiresAt), Status: string(i.Status), CreatedAt: formatTime(i.CreatedAt), ClosedAt: nullTime(i.ClosedAt),
		ClosedBy: i.ClosedBy}))
}

func (r invitations) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Invitation, error) {
	row, err := r.q.GetInvitationByPublicID(ctx, db.GetInvitationByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toInvitation)
}

func (r invitations) ListByOrg(ctx context.Context, realmID, orgID string) ([]port.Invitation, error) {
	rs, err := r.q.ListInvitationsByOrg(ctx, db.ListInvitationsByOrgParams{RealmID: realmID, OrgID: orgID})
	return rows(rs, err, toInvitation)
}

func (r invitations) Close(ctx context.Context, realmID, id string, status port.InvitationStatus, at time.Time, by string) (bool, error) {
	if _, err := r.q.GetInvitation(ctx, db.GetInvitationParams{RealmID: realmID, ID: id}); err != nil {
		return false, mapErr(err)
	}
	n, err := r.q.CloseInvitation(ctx, db.CloseInvitationParams{Status: string(status), ClosedAt: nullTime(&at), ClosedBy: by, RealmID: realmID, ID: id})
	return n > 0, mapErr(err)
}
