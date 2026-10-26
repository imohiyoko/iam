package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
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
		if list, err := repo.ListByOrg(ctx, r, o); err != nil || len(list) != 2 {
			return fmt.Errorf("memberships.ListByOrg = %+v, %v", list, err)
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
		d, err := count(tx.Memberships().ListByOrg(ctx, r, isoOrg))
		return a + b + c + d, err
	},
}
