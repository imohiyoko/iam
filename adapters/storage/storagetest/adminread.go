package storagetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 管理 API の一覧・検索（ADR 0097）の契約。

var adminReadTests = []struct {
	name string
	fn   func(*testing.T, Harness)
}{
	{"UserSearch", testUserSearch},
	{"OrgSearch", testOrgSearch},
	{"ConnectionUpdateAndCount", testConnectionUpdateAndCount},
}

func publicIDs[V any](vs []V, pub func(V) string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, pub(v))
	}
	return out
}

func userPub(u port.User) string { return u.PublicID }
func orgPub(o port.Org) string   { return o.PublicID }

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func testUserSearch(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	now := T0.Add(10 * time.Hour)
	a, b, c, d := newUser(r), newUser(r), newUser(r), newUser(r)
	b.CreatedAt = T0.Add(time.Hour)
	c.CreatedAt, c.Status = T0.Add(2*time.Hour), port.UserDeleted
	d.CreatedAt, d.Status = T0.Add(3*time.Hour), port.UserMerged
	o := newOrg(r, port.OrgShared, "")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, u := range []port.User{a, b, c, d} {
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
		}
		if err := tx.Orgs().Create(ctx, o); err != nil {
			return err
		}
		if err := tx.Memberships().Create(ctx, newMembership(r, a.ID, o.ID)); err != nil {
			return err
		}
		ended := newMembership(r, b.ID, o.ID)
		ended.Status = port.MembershipEnded
		if err := tx.Memberships().Create(ctx, ended); err != nil {
			return err
		}
		// b は今停止中。a の停止は解除済み、c の停止は未来から、d の停止は終わっている。
		sb := newSuspension(r, b.ID)
		sa := newSuspension(r, a.ID)
		sa.LiftedAt = ptr(now.Add(-time.Minute))
		sc := newSuspension(r, c.ID)
		sc.StartsAt = now.Add(time.Hour)
		sd := newSuspension(r, d.ID)
		sd.EndsAt = ptr(now)
		for _, x := range []port.Suspension{sb, sa, sc, sd} {
			if err := tx.Suspensions().Create(ctx, x); err != nil {
				return err
			}
		}
		return nil
	})
	all := sorted(a.PublicID, b.PublicID, c.PublicID, d.PublicID)
	cases := []struct {
		name string
		f    port.UserSearch
		want []string
	}{
		{"all", port.UserSearch{}, all},
		{"user", port.UserSearch{UserID: c.ID}, []string{c.PublicID}},
		{"status", port.UserSearch{Status: port.UserActive}, sorted(a.PublicID, b.PublicID)},
		{"merged", port.UserSearch{Status: port.UserMerged}, []string{d.PublicID}},
		{"suspended", port.UserSearch{Suspended: port.TriYes}, []string{b.PublicID}},
		{"not suspended", port.UserSearch{Suspended: port.TriNo}, sorted(a.PublicID, c.PublicID, d.PublicID)},
		{"active and not suspended", port.UserSearch{Status: port.UserActive, Suspended: port.TriNo}, []string{a.PublicID}},
		{"org", port.UserSearch{OrgID: o.ID}, []string{a.PublicID}},
		{"created from", port.UserSearch{CreatedFrom: ptr(T0.Add(time.Hour))}, sorted(b.PublicID, c.PublicID, d.PublicID)},
		{"created before", port.UserSearch{CreatedBefore: ptr(T0.Add(2 * time.Hour))}, sorted(a.PublicID, b.PublicID)},
		{"created range", port.UserSearch{CreatedFrom: ptr(T0.Add(time.Hour)), CreatedBefore: ptr(T0.Add(3 * time.Hour))}, sorted(b.PublicID, c.PublicID)},
		{"none", port.UserSearch{UserID: id.New(id.User)}, []string{}},
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, tc := range cases {
			tc.f.Now, tc.f.Limit = now, 10
			got, err := tx.Users().Search(ctx, r, tc.f)
			if err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
			if ids := publicIDs(got, userPub); !slices.Equal(ids, tc.want) {
				return fmt.Errorf("%s: Search = %v, want %v", tc.name, ids, tc.want)
			}
		}
		// 公開 ID の順に、After の次から Limit 件ずつ。
		var pages []string
		after := ""
		for range 3 {
			got, err := tx.Users().Search(ctx, r, port.UserSearch{Now: now, After: after, Limit: 3})
			if err != nil {
				return err
			}
			if len(got) == 0 {
				break
			}
			pages = append(pages, publicIDs(got, userPub)...)
			after = got[len(got)-1].PublicID
		}
		if !slices.Equal(pages, all) {
			return fmt.Errorf("paging = %v, want %v", pages, all)
		}
		got, err := tx.Users().Search(ctx, id.New(id.Realm), port.UserSearch{Now: now, Limit: 10})
		if err != nil || len(got) != 0 {
			return fmt.Errorf("other realm: %d, %v", len(got), err)
		}
		return nil
	})
}

func testOrgSearch(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	now := T0.Add(10 * time.Hour)
	parent := newOrg(r, port.OrgShared, "")
	parent.Name = "Acme"
	child := newOrg(r, port.OrgShared, "")
	child.Name, child.ParentID = "Acme Labs", parent.ID
	other := newOrg(r, port.OrgShared, "")
	other.Name = "acme lower"
	gone := newOrg(r, port.OrgShared, "")
	gone.Name = "Beta"
	personal := newOrg(r, port.OrgPersonal, id.New(id.User))
	personal.Name = "Ácme"
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, o := range []port.Org{parent, child, other, gone, personal} {
			if err := tx.Orgs().Create(ctx, o); err != nil {
				return err
			}
		}
		if err := tx.Orgs().SetParent(ctx, r, child.ID, parent.ID, T0); err != nil {
			return err
		}
		if err := tx.Orgs().SetDeletion(ctx, r, gone.ID, nil, ptr(T0), T0); err != nil {
			return err
		}
		sp := newSuspension(r, other.ID)
		sp.TargetType = port.SuspensionTargetOrg
		return tx.Suspensions().Create(ctx, sp)
	})
	cases := []struct {
		name string
		f    port.OrgSearch
		want []string
	}{
		{"all", port.OrgSearch{}, sorted(parent.PublicID, child.PublicID, other.PublicID, gone.PublicID, personal.PublicID)},
		{"kind", port.OrgSearch{Kind: port.OrgPersonal}, []string{personal.PublicID}},
		{"parent", port.OrgSearch{ParentID: parent.ID}, []string{child.PublicID}},
		{"prefix", port.OrgSearch{NamePrefix: "Acme"}, sorted(parent.PublicID, child.PublicID)},
		{"prefix exact", port.OrgSearch{NamePrefix: "Acme Labs"}, []string{child.PublicID}},
		{"prefix case", port.OrgSearch{NamePrefix: "acme"}, []string{other.PublicID}},
		{"prefix multibyte", port.OrgSearch{NamePrefix: "Á"}, []string{personal.PublicID}},
		{"prefix none", port.OrgSearch{NamePrefix: "Acme Labsx"}, []string{}},
		{"deleted", port.OrgSearch{Deleted: port.TriYes}, []string{gone.PublicID}},
		{"suspended", port.OrgSearch{Suspended: port.TriYes}, []string{other.PublicID}},
		{"live", port.OrgSearch{Kind: port.OrgShared, Deleted: port.TriNo, Suspended: port.TriNo}, sorted(parent.PublicID, child.PublicID)},
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, tc := range cases {
			tc.f.Now, tc.f.Limit = now, 10
			got, err := tx.Orgs().Search(ctx, r, tc.f)
			if err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
			if ids := publicIDs(got, orgPub); !slices.Equal(ids, tc.want) {
				return fmt.Errorf("%s: Search = %v, want %v", tc.name, ids, tc.want)
			}
		}
		got, err := tx.Orgs().Search(ctx, r, port.OrgSearch{Now: now, Limit: 2})
		if err != nil || len(got) != 2 {
			return fmt.Errorf("limit: %d, %v", len(got), err)
		}
		next, err := tx.Orgs().Search(ctx, r, port.OrgSearch{Now: now, After: got[1].PublicID, Limit: 10})
		if err != nil || len(next) != 3 || next[0].PublicID <= got[1].PublicID {
			return fmt.Errorf("after: %d, %v", len(next), err)
		}
		return nil
	})
}

func testConnectionUpdateAndCount(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	c := port.Connection{ID: id.NewExternal(id.Connection), RealmID: r, Slug: "google", Type: "oidc", Config: []byte(`{"a":1}`), CreatedAt: T0}
	identity := func(subject string) port.Identity {
		return port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: id.New(id.User),
			ConnectionID: c.ID, ProviderSubject: subject, CreatedAt: T0}
	}
	revoked := identity("s2")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Connections().Create(ctx, c); err != nil {
			return err
		}
		if err := tx.Identities().Create(ctx, identity("s1")); err != nil {
			return err
		}
		if err := tx.Identities().Create(ctx, revoked); err != nil {
			return err
		}
		return tx.Identities().Revoke(ctx, r, revoked.ID, T0, "test")
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if n, err := tx.Identities().CountActiveByConnection(ctx, r, c.ID); err != nil || n != 1 {
			return fmt.Errorf("CountActiveByConnection = %d, %v", n, err)
		}
		if n, err := tx.Identities().CountActiveByConnection(ctx, r, "con_other"); err != nil || n != 0 {
			return fmt.Errorf("CountActiveByConnection(other) = %d, %v", n, err)
		}
		if err := tx.Connections().UpdateConfig(ctx, r, c.ID, []byte(`{"a":2}`)); err != nil {
			return err
		}
		got, err := tx.Connections().Get(ctx, r, c.ID)
		if err != nil || string(got.Config) != `{"a":2}` || got.Slug != c.Slug || !got.CreatedAt.Equal(T0) {
			return fmt.Errorf("after UpdateConfig: %+v, %v", got, err)
		}
		if err := tx.Connections().UpdateConfig(ctx, id.New(id.Realm), c.ID, []byte(`{}`)); err == nil {
			return errors.New("UpdateConfig in another realm: want NotFound")
		}
		return notFound("UpdateConfig missing", tx.Connections().UpdateConfig(ctx, r, "con_missing", []byte(`{}`)))
	})
}

var adminReadIsolationCase = IsolationCase{
	Name: "Users.Search+Orgs.Search+Identities.CountActiveByConnection+Connections.UpdateConfig",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		if err := tx.Users().Create(ctx, newUser(r)); err != nil {
			return err
		}
		return tx.Orgs().Create(ctx, newOrg(r, port.OrgShared, ""))
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		us, err := tx.Users().Search(ctx, r, port.UserSearch{Now: T0, Limit: 100})
		if err != nil {
			return 0, err
		}
		os, err := tx.Orgs().Search(ctx, r, port.OrgSearch{Now: T0, Limit: 100})
		if err != nil {
			return 0, err
		}
		// 分離の検査の先の段で、realm に外部 ID（isoConn）を入れている。
		n, err := tx.Identities().CountActiveByConnection(ctx, r, isoConn)
		if err != nil {
			return 0, err
		}
		u := 0
		switch err := tx.Connections().UpdateConfig(ctx, r, isoConn, []byte("{}")); {
		case err == nil:
			u = 1
		case !errors.Is(err, errs.NotFound):
			return 0, err
		}
		return len(us) + len(os) + n + u, nil
	},
}
