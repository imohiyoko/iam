package storagetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func newOrg(realmID string, kind port.OrgKind, owner string) port.Org {
	return port.Org{ID: id.New(id.Org), PublicID: id.NewExternal(id.Org), RealmID: realmID, Kind: kind, Name: "acme",
		PersonalOwnerID: owner, CreatedAt: T0, UpdatedAt: T0}
}

func newMembership(realmID, userID, orgID string) port.Membership {
	return port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: realmID, UserID: userID,
		OrgID: orgID, Status: port.MembershipActive, Role: port.OrgMember, CreatedAt: T0, UpdatedAt: T0}
}

func testOrgs(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	personal := newOrg(r, port.OrgPersonal, u)
	shared := newOrg(r, port.OrgShared, "")
	shared.ValidFrom, shared.ValidUntil = ptr(T0.Add(time.Hour)), ptr(T0.Add(48*time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Orgs()
		for _, o := range []port.Org{personal, shared} {
			if err := repo.Create(ctx, o); err != nil {
				return err
			}
		}
		got, err := repo.Get(ctx, r, shared.ID)
		if err != nil || !reflect.DeepEqual(got, shared) {
			return fmt.Errorf("orgs.Get = %+v, %v", got, err)
		}
		if got, err := repo.GetByPublicID(ctx, r, personal.PublicID); err != nil || !reflect.DeepEqual(got, personal) {
			return fmt.Errorf("orgs.GetByPublicID = %+v, %v", got, err)
		}
		if got, err := repo.GetPersonal(ctx, r, u); err != nil || got.ID != personal.ID {
			return fmt.Errorf("orgs.GetPersonal = %+v, %v", got, err)
		}
		if err := notFound("personal org of another user", second(repo.GetPersonal(ctx, r, id.New(id.User)))); err != nil {
			return err
		}
		// 個人 Org はユーザーに1つ。共有 Org は持ち主を持たないので、いくつでも作れる。
		if err := conflict("second personal org", repo.Create(ctx, newOrg(r, port.OrgPersonal, u))); err != nil {
			return err
		}
		if err := repo.Create(ctx, newOrg(r, port.OrgShared, "")); err != nil {
			return err
		}
		dup := newOrg(r, port.OrgShared, "")
		dup.PublicID = shared.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		from, until, at := T0.Add(time.Hour), T0.Add(2*time.Hour), T0.Add(time.Minute)
		if err := repo.SetValidity(ctx, r, shared.ID, &from, &until, at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, shared.ID); got.ValidFrom == nil || !got.ValidFrom.Equal(from) || !got.ValidUntil.Equal(until) || !got.UpdatedAt.Equal(at) {
			return fmt.Errorf("after SetValidity = %+v", got)
		}
		if err := repo.SetValidity(ctx, r, shared.ID, nil, nil, at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, shared.ID); got.ValidFrom != nil || got.ValidUntil != nil {
			return fmt.Errorf("after clearing validity = %+v", got)
		}
		if err := notFound("set validity in another realm", repo.SetValidity(ctx, id.New(id.Realm), shared.ID, nil, nil, at)); err != nil {
			return err
		}
		if err := repo.SetSettings(ctx, r, shared.ID, []byte(`{"a":1}`), at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, shared.ID); string(got.Settings) != `{"a":1}` {
			return fmt.Errorf("after SetSettings = %q", got.Settings)
		}
		if err := repo.SetSettings(ctx, r, shared.ID, nil, at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, shared.ID); got.Settings != nil {
			return fmt.Errorf("after clearing settings = %q", got.Settings)
		}
		if err := notFound("set settings in another realm", repo.SetSettings(ctx, id.New(id.Realm), shared.ID, nil, at)); err != nil {
			return err
		}
		del := T0.Add(30 * 24 * time.Hour)
		if err := repo.SetDeletion(ctx, r, shared.ID, &del, nil, at); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, shared.ID); got.DeletionScheduledAt == nil || !got.DeletionScheduledAt.Equal(del) || got.DeletedAt != nil {
			return fmt.Errorf("after scheduling deletion = %+v", got)
		}
		if err := repo.SetDeletion(ctx, r, shared.ID, &del, &del, at); err != nil {
			return err
		}
		if got, _ := repo.GetByPublicID(ctx, r, shared.PublicID); got.DeletedAt == nil || !got.DeletedAt.Equal(del) {
			return fmt.Errorf("after deletion = %+v", got)
		}
		if err := notFound("set deletion in another realm", repo.SetDeletion(ctx, id.New(id.Realm), shared.ID, nil, nil, at)); err != nil {
			return err
		}
		return notFound("get in another realm", second(repo.Get(ctx, id.New(id.Realm), shared.ID)))
	})
}

func testPersonalOrgUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Orgs().Create(ctx, newOrg(r, port.OrgPersonal, u))
		})
	}))
}

func testMemberships(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, o := id.New(id.Realm), id.New(id.User), id.New(id.Org)
	a := newMembership(r, u, o)
	a.Role, a.EmailID, a.ValidUntil = port.OrgOwner, id.New(id.Email), ptr(T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Memberships()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, a.PublicID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("memberships.GetByPublicID = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("memberships.Get = %+v, %v", got, err)
		}
		if err := notFound("membership get in another realm", second(repo.Get(ctx, id.New(id.Realm), a.ID))); err != nil {
			return err
		}
		if got, err := repo.GetByUserOrg(ctx, r, u, o); err != nil || got.ID != a.ID {
			return fmt.Errorf("memberships.GetByUserOrg = %+v, %v", got, err)
		}
		if err := conflict("same user and org", repo.Create(ctx, newMembership(r, u, o))); err != nil {
			return err
		}
		later := newMembership(r, u, id.New(id.Org))
		later.CreatedAt = T0.Add(time.Minute)
		other := newMembership(r, id.New(id.User), o)
		for _, m := range []port.Membership{later, other} {
			if err := repo.Create(ctx, m); err != nil {
				return err
			}
		}
		if list, err := repo.ListByUser(ctx, r, u); err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != later.ID {
			return fmt.Errorf("memberships.ListByUser = %+v, %v", list, err)
		}
		var paged []string
		for after := ""; ; {
			page, err := repo.ListByOrg(ctx, r, o, after, 1)
			if err != nil {
				return err
			}
			if len(page) == 0 {
				break
			}
			if len(page) > 1 {
				return fmt.Errorf("memberships.ListByOrg returned %d > limit", len(page))
			}
			paged, after = append(paged, page[0].PublicID), page[0].PublicID
		}
		if want := []string{a.PublicID, other.PublicID}; len(paged) != 2 || !slices.Contains(paged, want[0]) || !slices.Contains(paged, want[1]) || paged[0] > paged[1] {
			return fmt.Errorf("memberships.ListByOrg pages = %v", paged)
		}
		return notFound("get in another realm", second(repo.GetByUserOrg(ctx, id.New(id.Realm), u, o)))
	})
}

func testMembershipUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, o := id.New(id.Realm), id.New(id.User), id.New(id.Org)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Memberships().Create(ctx, newMembership(r, u, o))
		})
	}))
}

const (
	isoOrg        = "org_00000000000000000000000009"
	isoMembership = "mbr_00000000000000000000000009"
)

var orgIsolationCase = IsolationCase{
	Name: "Orgs.Get+GetByPublicID+GetPersonal",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		o := newOrg(r, port.OrgPersonal, isoUser)
		o.ID, o.PublicID = isoOrg, isoOrg
		return tx.Orgs().Create(ctx, o)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		total := 0
		for _, f := range []func() (port.Org, error){
			func() (port.Org, error) { return tx.Orgs().Get(ctx, r, isoOrg) },
			func() (port.Org, error) { return tx.Orgs().GetByPublicID(ctx, r, isoOrg) },
			func() (port.Org, error) { return tx.Orgs().GetPersonal(ctx, r, isoUser) },
		} {
			n, err := countOne(f())
			if err != nil {
				return 0, err
			}
			total += n
		}
		return total, nil
	},
}

var membershipIsolationCase = IsolationCase{
	Name: "Memberships.GetByPublicID+GetByUserOrg+ListByUser+ListByOrg",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		m := newMembership(r, isoUser, isoOrg)
		m.PublicID = isoMembership
		return tx.Memberships().Create(ctx, m)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		a, err := countOne(tx.Memberships().GetByPublicID(ctx, r, isoMembership))
		if err != nil {
			return 0, err
		}
		b, err := countOne(tx.Memberships().GetByUserOrg(ctx, r, isoUser, isoOrg))
		if err != nil {
			return 0, err
		}
		c, err := count(tx.Memberships().ListByUser(ctx, r, isoUser))
		if err != nil {
			return 0, err
		}
		d, err := count(tx.Memberships().ListByOrg(ctx, r, isoOrg, "", 10))
		return a + b + c + d, err
	},
}

func testMembershipUpdate(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	m := newMembership(r, id.New(id.User), id.New(id.Org))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Memberships().Create(ctx, m); err != nil {
			return err
		}
		want := m
		want.Status, want.Role, want.EmailID, want.EndedReason = port.MembershipEnded, port.OrgAdmin, id.New(id.Email), "removed"
		want.ValidFrom, want.ValidUntil, want.UpdatedAt = ptr(T0), ptr(T0.Add(time.Hour)), T0.Add(time.Minute)
		// ユーザー・Org・作成時刻は変わらない。
		changed := want
		changed.UserID, changed.OrgID, changed.CreatedAt = id.New(id.User), id.New(id.Org), T0.Add(time.Hour)
		if err := tx.Memberships().Update(ctx, changed); err != nil {
			return err
		}
		got, err := tx.Memberships().GetByPublicID(ctx, r, m.PublicID)
		if err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("after Update = %+v, %v (want %+v)", got, err, want)
		}
		other := want
		other.RealmID = id.New(id.Realm)
		return notFound("update in another realm", tx.Memberships().Update(ctx, other))
	})
}

func testMembershipCountActive(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, o := id.New(id.Realm), id.New(id.Org)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, c := range []struct {
			role   port.OrgRole
			status port.MembershipStatus
			org    string
		}{{port.OrgOwner, port.MembershipActive, o}, {port.OrgOwner, port.MembershipActive, o}, {port.OrgOwner, port.MembershipEnded, o},
			{port.OrgOwner, port.MembershipInvited, o}, {port.OrgAdmin, port.MembershipActive, o}, {port.OrgOwner, port.MembershipActive, id.New(id.Org)}} {
			m := newMembership(r, id.New(id.User), c.org)
			m.Role, m.Status = c.role, c.status
			if err := tx.Memberships().Create(ctx, m); err != nil {
				return err
			}
		}
		for role, want := range map[port.OrgRole]int{port.OrgOwner: 2, port.OrgAdmin: 1, port.OrgMember: 0} {
			if n, err := tx.Memberships().CountActive(ctx, r, o, role); err != nil || n != want {
				return fmt.Errorf("CountActive(%s) = %d, %v (want %d)", role, n, err, want)
			}
		}
		if n, err := tx.Memberships().CountActive(ctx, id.New(id.Realm), o, port.OrgOwner); err != nil || n != 0 {
			return fmt.Errorf("another realm = %d, %v", n, err)
		}
		return nil
	})
}

func newInvitation(realmID, orgID string) port.Invitation {
	return port.Invitation{ID: id.New(id.Invitation), PublicID: id.NewExternal(id.Invitation), RealmID: realmID, OrgID: orgID,
		EmailIndex: []byte("ix"), EmailCiphertext: []byte("ct"), IndexKeyID: "ik_1", Role: port.OrgMember, TokenHash: []byte("hash"),
		InvitedBy: "usr_admin", ExpiresAt: T0.Add(7 * 24 * time.Hour), Status: port.InvitationPending, CreatedAt: T0}
}

func testInvitations(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, o := id.New(id.Realm), id.New(id.Org)
	a := newInvitation(r, o)
	a.ValidUntil = ptr(T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Invitations()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, a.PublicID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("invitations.GetByPublicID = %+v, %v", got, err)
		}
		dup := newInvitation(r, o)
		dup.PublicID = a.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		b := newInvitation(r, o)
		b.CreatedAt = T0.Add(time.Minute)
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		if list, err := repo.ListByOrg(ctx, r, o); err != nil || len(list) != 2 || list[0].ID != a.ID {
			return fmt.Errorf("invitations.ListByOrg = %+v, %v", list, err)
		}
		at := T0.Add(time.Hour)
		if ok, err := repo.Close(ctx, r, a.ID, port.InvitationAccepted, at, "usr_1"); err != nil || !ok {
			return fmt.Errorf("close = %v, %v", ok, err)
		}
		if ok, err := repo.Close(ctx, r, a.ID, port.InvitationRevoked, at, "usr_2"); err != nil || ok {
			return fmt.Errorf("close again = %v, %v", ok, err)
		}
		got, _ := repo.GetByPublicID(ctx, r, a.PublicID)
		if got.Status != port.InvitationAccepted || got.ClosedAt == nil || !got.ClosedAt.Equal(at) || got.ClosedBy != "usr_1" {
			return fmt.Errorf("closed = %+v", got)
		}
		_, err := repo.Close(ctx, id.New(id.Realm), b.ID, port.InvitationRevoked, at, "x")
		return notFound("close in another realm", err)
	})
}

func testInvitationAcceptConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	i := newInvitation(id.New(id.Realm), id.New(id.Org))
	tx(t, s, func(ctx context.Context, tx port.Tx) error { return tx.Invitations().Create(ctx, i) })
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			ok, err := tx.Invitations().Close(ctx, i.RealmID, i.ID, port.InvitationAccepted, T0, "usr_1")
			if err == nil && !ok {
				return errs.New(errs.KindConflict, "already closed")
			}
			return err
		})
	}))
}

const isoInvitation = "inv_00000000000000000000000009"

var invitationIsolationCase = IsolationCase{
	Name: "Invitations.GetByPublicID+ListByOrg",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		i := newInvitation(r, isoOrg)
		i.PublicID = isoInvitation
		return tx.Invitations().Create(ctx, i)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		n, err := countOne(tx.Invitations().GetByPublicID(ctx, r, isoInvitation))
		if err != nil {
			return 0, err
		}
		m, err := count(tx.Invitations().ListByOrg(ctx, r, isoOrg))
		return n + m, err
	},
}

func newQuotaGrant(realmID, orgID string, kind port.QuotaGrantKind, n int64) port.QuotaGrant {
	return port.QuotaGrant{ID: id.New(id.QuotaGrant), PublicID: id.NewExternal(id.QuotaGrant), RealmID: realmID, OrgID: orgID, QuotaKey: "members",
		Kind: kind, Quantity: n, StartsAt: T0, Source: port.QuotaSourceManual, CreatedBy: "usr_admin", CreatedAt: T0, UpdatedAt: T0}
}

func testQuotaGrants(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, o := id.New(id.Realm), id.New(id.Org)
	a := newQuotaGrant(r, o, port.QuotaBase, 10)
	a.EndsAt = ptr(T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.QuotaGrants()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, a.PublicID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		dup := newQuotaGrant(r, o, port.QuotaAddon, 1)
		dup.PublicID = a.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		// 空の external_ref は重複してよい。空でなければ (Org, quota_key) ごとに一意。
		b := newQuotaGrant(r, o, port.QuotaAddon, 2)
		b.CreatedAt, b.Source, b.ExternalRef = T0.Add(time.Minute), port.QuotaSourceExternal, "sub_1"
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		c := newQuotaGrant(r, o, port.QuotaAddon, 3)
		c.CreatedAt, c.ExternalRef = T0.Add(2*time.Minute), "sub_1"
		if err := conflict("same external ref", repo.Create(ctx, c)); err != nil {
			return err
		}
		c.QuotaKey = "projects"
		if err := repo.Create(ctx, c); err != nil {
			return err
		}
		if got, err := repo.GetByExternalRef(ctx, r, o, "members", "sub_1"); err != nil || got.ID != b.ID {
			return fmt.Errorf("GetByExternalRef = %+v, %v", got, err)
		}
		if _, err := repo.GetByExternalRef(ctx, r, o, "members", ""); notFound("empty external ref", err) != nil {
			return notFound("empty external ref", err)
		}
		if list, err := repo.ListByOrg(ctx, r, o, "members"); err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
			return fmt.Errorf("ListByOrg = %+v, %v", list, err)
		}
		a.Kind, a.Quantity, a.StartsAt, a.EndsAt, a.UpdatedAt = port.QuotaOverride, 4, T0.Add(time.Second), nil, T0.Add(time.Hour)
		if err := repo.Update(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, a.PublicID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("after Update = %+v, %v", got, err)
		}
		other := a
		other.RealmID = id.New(id.Realm)
		if err := notFound("update in another realm", repo.Update(ctx, other)); err != nil {
			return err
		}
		if err := notFound("delete in another realm", repo.Delete(ctx, other.RealmID, a.ID)); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if _, err := repo.GetByPublicID(ctx, r, a.PublicID); notFound("deleted", err) != nil {
			return notFound("deleted", err)
		}
		return notFound("delete again", repo.Delete(ctx, r, a.ID))
	})
}

// testQuotaCountThenAddConcurrent は、件数の確認と追加を同じトランザクションで並行に行っても上限を超えないこと（11.14、12章）。
func testQuotaCountThenAddConcurrent(t *testing.T, h Harness) {
	const limit, workers = 5, 32
	s, _ := open(t, h)
	r, o := id.New(id.Realm), id.New(id.Org)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		return tx.QuotaGrants().Create(ctx, newQuotaGrant(r, o, port.QuotaBase, limit))
	})
	errFull := errors.New("quota exceeded")
	results := Concurrent(workers, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			gs, err := tx.QuotaGrants().ListByOrg(ctx, r, o, "members")
			if err != nil || len(gs) != 1 {
				return fmt.Errorf("grants = %d, %v", len(gs), err)
			}
			ms, err := tx.Memberships().ListByOrg(ctx, r, o, "", 1000)
			if err != nil {
				return err
			}
			if int64(len(ms))+1 > gs[0].Quantity {
				return errFull
			}
			return tx.Memberships().Create(ctx, newMembership(r, id.New(id.User), o))
		})
	})
	ok := 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, errFull):
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		ms, err := tx.Memberships().ListByOrg(ctx, r, o, "", 1000)
		if err != nil || len(ms) != ok || ok != limit {
			return fmt.Errorf("members = %d (succeeded %d), %v; want %d", len(ms), ok, err, limit)
		}
		return nil
	})
}

const isoQuotaGrant = "qgr_00000000000000000000000009"

var quotaGrantIsolationCase = IsolationCase{
	Name: "QuotaGrants.GetByPublicID+GetByExternalRef+ListByOrg",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		g := newQuotaGrant(r, isoOrg, port.QuotaBase, 1)
		g.PublicID, g.ExternalRef = isoQuotaGrant, "ext"
		return tx.QuotaGrants().Create(ctx, g)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		a, err := countOne(tx.QuotaGrants().GetByPublicID(ctx, r, isoQuotaGrant))
		if err != nil {
			return 0, err
		}
		b, err := countOne(tx.QuotaGrants().GetByExternalRef(ctx, r, isoOrg, "members", "ext"))
		if err != nil {
			return 0, err
		}
		c, err := count(tx.QuotaGrants().ListByOrg(ctx, r, isoOrg, "members"))
		return a + b + c, err
	},
}

func newOrgDomain(realmID, orgID, domain string) port.OrgDomain {
	return port.OrgDomain{ID: id.New(id.OrgDomain), PublicID: id.NewExternal(id.OrgDomain), RealmID: realmID, OrgID: orgID, Domain: domain,
		Token: "tok", CreatedBy: "usr_x", CreatedAt: T0}
}

func testOrgDomains(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, o1, o2 := id.New(id.Realm), id.New(id.Org), id.New(id.Org)
	a := newOrgDomain(r, o1, "example.com")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.OrgDomains()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetByPublicID(ctx, r, a.PublicID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		dup := newOrgDomain(r, o1, "example.org")
		dup.PublicID = a.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		if err := conflict("same domain in org", repo.Create(ctx, newOrgDomain(r, o1, "example.com"))); err != nil {
			return err
		}
		// 証明前なら、別の Org も同じドメインを登録できる。
		b := newOrgDomain(r, o2, "example.com")
		b.CreatedAt = T0.Add(time.Minute)
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		c := newOrgDomain(r, o1, "example.net")
		c.CreatedAt = T0.Add(time.Minute)
		if err := repo.Create(ctx, c); err != nil {
			return err
		}
		if list, err := repo.ListByOrg(ctx, r, o1); err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != c.ID {
			return fmt.Errorf("ListByOrg = %+v, %v", list, err)
		}
		if _, err := repo.GetVerified(ctx, r, "example.com"); notFound("not verified", err) != nil {
			return notFound("not verified", err)
		}
		a.VerifiedAt, a.CheckedAt = ptr(T0.Add(time.Hour)), ptr(T0.Add(time.Hour))
		if err := repo.Update(ctx, a); err != nil {
			return err
		}
		if got, err := repo.GetVerified(ctx, r, "example.com"); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("GetVerified = %+v, %v", got, err)
		}
		// 証明済みのドメインは realm で1つの Org だけ。
		b.VerifiedAt, b.CheckedAt = ptr(T0.Add(2*time.Hour)), ptr(T0.Add(2*time.Hour))
		if err := conflict("verified by another org", repo.Update(ctx, b)); err != nil {
			return err
		}
		b.VerifiedAt = nil
		if err := repo.Update(ctx, b); err != nil {
			return err
		}
		other := a
		other.RealmID = id.New(id.Realm)
		if err := notFound("update in another realm", repo.Update(ctx, other)); err != nil {
			return err
		}
		if err := notFound("delete in another realm", repo.Delete(ctx, other.RealmID, a.ID)); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if _, err := repo.GetByPublicID(ctx, r, a.PublicID); notFound("deleted", err) != nil {
			return notFound("deleted", err)
		}
		return notFound("delete again", repo.Delete(ctx, r, a.ID))
	})
}

const isoOrgDomain = "dom_00000000000000000000000009"

var orgDomainIsolationCase = IsolationCase{
	Name: "OrgDomains.GetByPublicID+GetVerified+ListByOrg",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		d := newOrgDomain(r, isoOrg, "iso.example")
		d.PublicID, d.VerifiedAt = isoOrgDomain, ptr(T0)
		return tx.OrgDomains().Create(ctx, d)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		a, err := countOne(tx.OrgDomains().GetByPublicID(ctx, r, isoOrgDomain))
		if err != nil {
			return 0, err
		}
		b, err := countOne(tx.OrgDomains().GetVerified(ctx, r, "iso.example"))
		if err != nil {
			return 0, err
		}
		c, err := count(tx.OrgDomains().ListByOrg(ctx, r, isoOrg))
		return a + b + c, err
	},
}
