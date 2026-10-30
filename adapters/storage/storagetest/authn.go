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

// 認証側（authn）と認可側（authz）の Repository の契約。

var authnTests = []struct {
	name string
	fn   func(*testing.T, Harness)
}{
	{"Users", testUsers},
	{"UserList", testUserList},
	{"Emails", testEmails},
	{"EmailUniqueConcurrent", testEmailUniqueConcurrent},
	{"Identities", testIdentities},
	{"IdentityUniqueConcurrent", testIdentityUniqueConcurrent},
	{"Passkeys", testPasskeys},
	{"PasskeyUniqueConcurrent", testPasskeyUniqueConcurrent},
	{"TOTP", testTOTP},
	{"TOTPUseConcurrent", testTOTPUseConcurrent},
	{"Passwords", testPasswords},
	{"PasswordCreateConcurrent", testPasswordCreateConcurrent},
	{"RecoveryCodes", testRecoveryCodes},
	{"RecoveryCodeUseConcurrent", testRecoveryCodeUseConcurrent},
	{"UserValidity", testUserValidity},
	{"Suspensions", testSuspensions},
	{"ScheduledEvents", testScheduledEvents},
	{"ScheduledFireConcurrent", testScheduledFireConcurrent},
	{"Connections", testConnections},
	{"Sessions", testSessions},
	{"SessionRevokeByPrincipal", testSessionRevokeByPrincipal},
	{"SessionMoveOrg", testSessionMoveOrg},
	{"UserDeletion", testUserDeletion},
	{"AccountMerge", testAccountMerge},
	{"ServiceAccounts", testServiceAccounts},
	{"ServiceAccountsM7", testServiceAccountsM7},
	{"RoleBindings", testRoleBindings},
	{"Roles", testRoles},
	{"Groups", testGroups},
	{"EffectiveBindings", testEffectiveBindings},
	{"NestedGroups", testNestedGroups},
	{"Attributes", testAttributes},
	{"RiskTypes", testRiskTypes},
	{"ActionNamespaces", testActionNamespaces},
	{"Orgs", testOrgs},
	{"PersonalOrgUniqueConcurrent", testPersonalOrgUniqueConcurrent},
	{"Memberships", testMemberships},
	{"MembershipUniqueConcurrent", testMembershipUniqueConcurrent},
	{"MembershipUpdate", testMembershipUpdate},
	{"MembershipCountActive", testMembershipCountActive},
	{"Invitations", testInvitations},
	{"InvitationAcceptConcurrent", testInvitationAcceptConcurrent},
	{"QuotaGrants", testQuotaGrants},
	{"OrgDomains", testOrgDomains},
	{"OrgHierarchy", testOrgHierarchy},
	{"ManagedUsers", testManagedUsers},
	{"QuotaCountThenAddConcurrent", testQuotaCountThenAddConcurrent},
	{"Clients", testClients},
	{"SigningKeys", testSigningKeys},
	{"Grants", testGrants},
	{"SessionLineage", testSessionLineage},
}

func notFound(what string, err error) error {
	if !errors.Is(err, errs.NotFound) {
		return fmt.Errorf("%s: want NotFound, got %v", what, err)
	}
	return nil
}

func conflict(what string, err error) error {
	if !errors.Is(err, errs.Conflict) {
		return fmt.Errorf("%s: want Conflict, got %v", what, err)
	}
	return nil
}

func ptr(t time.Time) *time.Time { return &t }

func newUser(realmID string) port.User {
	return port.User{ID: id.New(id.User), PublicID: id.NewExternal(id.User), RealmID: realmID, Status: port.UserActive, CreatedAt: T0, UpdatedAt: T0}
}

func newEmail(realmID, userID string, index string) port.UserEmail {
	return port.UserEmail{ID: id.New(id.Email), PublicID: id.NewExternal(id.Email), RealmID: realmID, UserID: userID, Ciphertext: []byte("ct-" + index),
		Index: []byte(index), DomainIndex: []byte("dom"), IndexKeyID: "ik_1", VerifiedAt: ptr(T0),
		VerifiedVia: port.VerifiedViaCode, IsPrimary: true, CreatedAt: T0}
}

func newSession(realmID, userID string, created time.Time) port.Session {
	sid := id.NewExternal(id.Session)
	return port.Session{ID: sid, SID: sid, RealmID: realmID, PrincipalType: port.PrincipalUser, PrincipalID: userID,
		TokenHash: []byte("hash"), AuthMethods: []string{"otp"}, AuthCredentialIDs: []string{"eml_x"}, Warnings: []byte(`[]`),
		IP: []byte("ip-ct"), UserAgent: []byte("ua-ct"), AuthenticatedAt: created.Add(-time.Second), CreatedAt: created, LastSeenAt: created, ExpiresAt: created.Add(24 * time.Hour)}
}

func testUsers(t *testing.T, h Harness) {
	s, _ := open(t, h)
	u := newUser(id.New(id.Realm))
	u.ValidUntil = ptr(T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		if err := conflict("duplicate user", tx.Users().Create(ctx, u)); err != nil {
			return err
		}
		got, err := tx.Users().Get(ctx, u.RealmID, u.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, u) {
			return fmt.Errorf("users.Get = %+v, want %+v", got, u)
		}
		got, err = tx.Users().GetByPublicID(ctx, u.RealmID, u.PublicID)
		if err != nil || got.ID != u.ID {
			return fmt.Errorf("users.GetByPublicID = %+v, %v", got, err)
		}
		// 外部 ID は realm 内で一意。内部 ID では引けない。
		dup := newUser(u.RealmID)
		dup.PublicID = u.PublicID
		if err := conflict("duplicate public id", tx.Users().Create(ctx, dup)); err != nil {
			return err
		}
		_, err = tx.Users().GetByPublicID(ctx, u.RealmID, u.ID)
		if err := notFound("public lookup by internal id", err); err != nil {
			return err
		}
		other := newUser(id.New(id.Realm))
		other.PublicID = u.PublicID
		if err := tx.Users().Create(ctx, other); err != nil {
			return err
		}
		_, err = tx.Users().Get(ctx, id.New(id.Realm), u.ID)
		return notFound("user from another realm", err)
	})
}

func testUserList(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	var ids []string
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for range 5 {
			u := newUser(r)
			ids = append(ids, u.ID)
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
		}
		slices.Sort(ids)
		var got []string
		for after := ""; ; {
			page, err := tx.Users().List(ctx, r, after, 2)
			if err != nil {
				return err
			}
			if len(page) == 0 {
				break
			}
			if len(page) > 2 {
				return fmt.Errorf("users.List returned %d > limit", len(page))
			}
			for _, u := range page {
				got = append(got, u.ID)
			}
			after = page[len(page)-1].ID
		}
		if !slices.Equal(got, ids) {
			return fmt.Errorf("users.List = %v, want %v", got, ids)
		}
		return nil
	})
}

func testEmails(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	u1, u2 := id.New(id.User), id.New(id.User)
	e1 := newEmail(r1, u1, "a")
	e2 := newEmail(r1, u1, "b")
	e2.VerifiedAt, e2.IsPrimary = nil, false
	// 作成時刻の順に並ぶことを確かめるため、後に作る e2 の時刻を前にする（ID の順とは逆になりうる）。
	e2.CreatedAt = T0.Add(-time.Minute)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		r := tx.Emails()
		for _, e := range []port.UserEmail{e1, e2} {
			if err := r.Create(ctx, e); err != nil {
				return err
			}
		}
		// 1つのアドレスは realm 内で1ユーザーにだけ紐付く。
		if err := conflict("same address, other user", r.Create(ctx, newEmail(r1, u2, "a"))); err != nil {
			return err
		}
		// 別の realm では同じアドレスを使える。
		if err := r.Create(ctx, newEmail(r2, u2, "a")); err != nil {
			return err
		}
		got, err := r.GetByIndex(ctx, r1, []byte("a"))
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, e1) {
			return fmt.Errorf("emails.GetByIndex = %+v, want %+v", got, e1)
		}
		_, err = r.GetByIndex(ctx, r1, []byte("zzz"))
		if err := notFound("missing index", err); err != nil {
			return err
		}
		list, err := r.ListByUser(ctx, r1, u1)
		if err != nil || len(list) != 2 || !reflect.DeepEqual(list[0], e2) || list[1].ID != e1.ID {
			return fmt.Errorf("emails.ListByUser = %+v, %v", list, err)
		}
		if got, err := r.GetByPublicID(ctx, r1, e1.PublicID); err != nil || !reflect.DeepEqual(got, e1) {
			return fmt.Errorf("emails.GetByPublicID = %+v, %v", got, err)
		}
		_, err = r.GetByPublicID(ctx, r2, e1.PublicID)
		return notFound("public id from another realm", err)
	})
	// primary の付け替えと削除。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		r := tx.Emails()
		if err := r.SetPrimary(ctx, r1, u1, e2.ID); err != nil {
			return err
		}
		list, err := r.ListByUser(ctx, r1, u1)
		if err != nil || len(list) != 2 || !list[0].IsPrimary || list[1].IsPrimary {
			return fmt.Errorf("after SetPrimary = %+v, %v", list, err)
		}
		if err := notFound("SetPrimary for another user", r.SetPrimary(ctx, r1, u2, e1.ID)); err != nil {
			return err
		}
		if err := notFound("SetPrimary in another realm", r.SetPrimary(ctx, r2, u1, e1.ID)); err != nil {
			return err
		}
		if err := notFound("Delete in another realm", r.Delete(ctx, r2, e1.ID)); err != nil {
			return err
		}
		if err := r.Delete(ctx, r1, e1.ID); err != nil {
			return err
		}
		if err := notFound("Delete twice", r.Delete(ctx, r1, e1.ID)); err != nil {
			return err
		}
		_, err = r.GetByIndex(ctx, r1, []byte("a"))
		if err := notFound("deleted email", err); err != nil {
			return err
		}
		// 消したアドレスは別のユーザーが使える。
		return r.Create(ctx, newEmail(r1, u2, "a"))
	})
}

func testEmailUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Emails().Create(ctx, newEmail(r, id.New(id.User), "same"))
		})
	}))
}

func testIdentities(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	conn := id.New(id.Connection)
	i := port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: u, ConnectionID: conn, ProviderSubject: "sub-1", CreatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Identities()
		if err := repo.Create(ctx, i); err != nil {
			return err
		}
		dup := i
		dup.ID, dup.PublicID, dup.UserID = id.New(id.Identity), id.NewExternal(id.Identity), id.New(id.User)
		if err := conflict("same subject", repo.Create(ctx, dup)); err != nil {
			return err
		}
		other := i
		other.ID, other.PublicID, other.ConnectionID = id.New(id.Identity), id.NewExternal(id.Identity), id.New(id.Connection)
		if err := repo.Create(ctx, other); err != nil {
			return err
		}
		got, err := repo.GetBySubject(ctx, r, conn, "sub-1")
		if err != nil || !reflect.DeepEqual(got, i) {
			return fmt.Errorf("identities.GetBySubject = %+v, %v", got, err)
		}
		_, err = repo.GetBySubject(ctx, r, conn, "sub-2")
		if err := notFound("missing subject", err); err != nil {
			return err
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil || len(list) != 2 {
			return fmt.Errorf("identities.ListByUser = %+v, %v", list, err)
		}
		if got, err := repo.GetByPublicID(ctx, r, i.PublicID); err != nil || got.ID != i.ID {
			return fmt.Errorf("identities.GetByPublicID = %+v, %v", got, err)
		}
		_, err = repo.GetByPublicID(ctx, r, id.NewExternal(id.Identity))
		return notFound("missing public id", err)
	})
	// 無効化：GetBySubject から消え、同じ外部 ID を別の行として紐付け直せる。無効化は1回だけ効く。
	at := T0.Add(time.Hour)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Identities()
		if err := repo.Revoke(ctx, r, i.ID, at, "unlinked"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, i.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, err := repo.GetByPublicID(ctx, r, i.PublicID)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "unlinked" {
			return fmt.Errorf("revoked identity = %+v, %v", got, err)
		}
		_, err = repo.GetBySubject(ctx, r, conn, "sub-1")
		if err := notFound("revoked subject", err); err != nil {
			return err
		}
		again := i
		again.ID, again.PublicID = id.New(id.Identity), id.NewExternal(id.Identity)
		if err := repo.Create(ctx, again); err != nil {
			return fmt.Errorf("relink after revoke: %w", err)
		}
		if got, err := repo.GetBySubject(ctx, r, conn, "sub-1"); err != nil || got.ID != again.ID {
			return fmt.Errorf("GetBySubject after relink = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, r, i.ID); err != nil || got.RevokedAt == nil {
			return fmt.Errorf("identities.Get(revoked) = %+v, %v", got, err)
		}
		if _, err := repo.Get(ctx, id.New(id.Realm), i.ID); err == nil || !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("identities.Get(other realm) = %v", err)
		}
		return notFound("revoke in another realm", repo.Revoke(ctx, id.New(id.Realm), again.ID, at, "x"))
	})
	// connection ごとの無効化：無効化されていないものだけを数え、別の connection と realm には触れない。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Identities()
		if n, err := repo.RevokeByConnection(ctx, id.New(id.Realm), conn, at, "x"); err != nil || n != 0 {
			return fmt.Errorf("RevokeByConnection(other realm) = %d, %v", n, err)
		}
		if n, err := repo.RevokeByConnection(ctx, r, conn, at, "connection_deleted"); err != nil || n != 1 {
			return fmt.Errorf("RevokeByConnection = %d, %v", n, err)
		}
		if _, err := repo.GetBySubject(ctx, r, conn, "sub-1"); !errors.Is(err, errs.NotFound) {
			return fmt.Errorf("GetBySubject after RevokeByConnection = %v", err)
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil {
			return err
		}
		active := 0
		for _, x := range list {
			if x.RevokedAt == nil {
				active++
			}
		}
		if active != 1 { // 別の connection のもの
			return fmt.Errorf("active identities after RevokeByConnection = %d", active)
		}
		return nil
	})
}

func testIdentityUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, conn := id.New(id.Realm), id.New(id.Connection)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Identities().Create(ctx, port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: id.New(id.User),
				ConnectionID: conn, ProviderSubject: "same", CreatedAt: T0})
		})
	}))
}

func testConnections(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	c := port.Connection{ID: id.New(id.Connection), RealmID: r1, Slug: "google", Type: "oidc", Config: []byte(`{"x":1}`), CreatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Connections()
		if err := repo.Create(ctx, c); err != nil {
			return err
		}
		dup := c
		dup.ID = id.New(id.Connection)
		if err := conflict("same slug", repo.Create(ctx, dup)); err != nil {
			return err
		}
		dup.RealmID = r2
		if err := repo.Create(ctx, dup); err != nil {
			return err
		}
		got, err := repo.Get(ctx, r1, c.ID)
		if err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("connections.Get = %+v, %v", got, err)
		}
		got, err = repo.GetBySlug(ctx, r1, "google")
		if err != nil || got.ID != c.ID {
			return fmt.Errorf("connections.GetBySlug = %+v, %v", got, err)
		}
		list, err := repo.List(ctx, r1)
		if err != nil || len(list) != 1 {
			return fmt.Errorf("connections.List = %+v, %v", list, err)
		}
		_, err = repo.Get(ctx, r2, c.ID)
		return notFound("connection from another realm", err)
	})
	// Org 専用の connection（ADR 0077）。
	o1, o2 := id.New(id.Org), id.New(id.Org)
	owned := []port.Connection{
		{ID: id.New(id.Connection), RealmID: r1, Slug: "o1-b", Type: "oidc", Config: []byte("{}"), CreatedAt: T0.Add(time.Minute), OwnerOrgID: o1},
		{ID: id.New(id.Connection), RealmID: r1, Slug: "o1-a", Type: "oidc", Config: []byte("{}"), CreatedAt: T0.Add(2 * time.Minute), OwnerOrgID: o1},
		{ID: id.New(id.Connection), RealmID: r1, Slug: "o2", Type: "oidc", Config: []byte("{}"), CreatedAt: T0, OwnerOrgID: o2},
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Connections()
		for _, c := range owned {
			if err := repo.Create(ctx, c); err != nil {
				return err
			}
		}
		got, err := repo.Get(ctx, r1, owned[0].ID)
		if err != nil || !reflect.DeepEqual(got, owned[0]) {
			return fmt.Errorf("connections.Get(owned) = %+v, %v", got, err)
		}
		list, err := repo.ListByOwner(ctx, r1, o1)
		if err != nil || len(list) != 2 || list[0].ID != owned[0].ID || list[1].ID != owned[1].ID {
			return fmt.Errorf("connections.ListByOwner = %+v, %v", list, err)
		}
		if list, err := repo.ListByOwner(ctx, r2, o1); err != nil || len(list) != 0 {
			return fmt.Errorf("connections.ListByOwner(other realm) = %+v, %v", list, err)
		}
		if n, err := repo.CountOwned(ctx, r1); err != nil || n != 3 {
			return fmt.Errorf("connections.CountOwned = %d, %v", n, err)
		}
		if n, err := repo.CountOwned(ctx, r2); err != nil || n != 0 {
			return fmt.Errorf("connections.CountOwned(other realm) = %d, %v", n, err)
		}
		if err := notFound("delete in another realm", repo.Delete(ctx, r2, owned[0].ID)); err != nil {
			return err
		}
		if err := repo.Delete(ctx, r1, owned[0].ID); err != nil {
			return err
		}
		if err := notFound("deleted connection", repo.Delete(ctx, r1, owned[0].ID)); err != nil {
			return err
		}
		_, err = repo.Get(ctx, r1, owned[0].ID)
		if err := notFound("get deleted connection", err); err != nil {
			return err
		}
		n, err := repo.CountOwned(ctx, r1)
		if err != nil || n != 2 {
			return fmt.Errorf("connections.CountOwned after delete = %d, %v", n, err)
		}
		return nil
	})
}

func testSessions(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	a := newSession(r, u, T0)
	a.Restriction, a.Risk = port.RestrictionSecondFactor, []byte(`{"ip":10}`)
	b := newSession(r, u, T0.Add(time.Minute))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Sessions()
		for _, x := range []port.Session{a, b} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("duplicate session", repo.Create(ctx, a)); err != nil {
			return err
		}
		got, err := repo.Get(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("sessions.Get = %+v, %v; want %+v", got, err, a)
		}
		list, err := repo.ListByPrincipal(ctx, r, port.PrincipalUser, u)
		if err != nil || len(list) != 2 || list[0].ID != b.ID {
			return fmt.Errorf("sessions.ListByPrincipal must be newest first: %+v, %v", list, err)
		}

		// Touch は時刻を戻さない。
		if err := repo.Touch(ctx, r, a.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if err := repo.Touch(ctx, r, a.ID, T0.Add(time.Minute)); err != nil {
			return err
		}
		// Revoke は失効の時刻を早めるだけで遅らせない（予定の失効を前倒しできる）。
		if err := repo.Revoke(ctx, r, a.ID, T0.Add(4*time.Hour), "rotated"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, a.ID, T0.Add(3*time.Hour), "logout"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, a.ID, T0.Add(5*time.Hour), "admin"); err != nil {
			return err
		}
		got, err = repo.Get(ctx, r, a.ID)
		if err != nil {
			return err
		}
		if !got.LastSeenAt.Equal(T0.Add(time.Hour)) || got.RevokedAt == nil || !got.RevokedAt.Equal(T0.Add(3*time.Hour)) || got.RevokeReason != "logout" {
			return fmt.Errorf("after updates: %+v", got)
		}

		// SetRisk は点数を置き換え、空なら無しに戻す。
		if err := repo.SetRisk(ctx, r, b.ID, []byte(`{"account":80}`)); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, b.ID); err != nil || string(got.Risk) != `{"account":80}` {
			return fmt.Errorf("after SetRisk: %q, %v", got.Risk, err)
		}
		if err := repo.SetRisk(ctx, r, a.ID, nil); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || got.Risk != nil {
			return fmt.Errorf("after clearing the risk: %q, %v", got.Risk, err)
		}
		if err := notFound("SetRisk missing", repo.SetRisk(ctx, r, id.NewExternal(id.Session), nil)); err != nil {
			return err
		}

		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"Get":     func() error { _, err := repo.Get(ctx, other, a.ID); return err }(),
			"Touch":   repo.Touch(ctx, other, b.ID, T0.Add(time.Hour)),
			"Revoke":  repo.Revoke(ctx, other, b.ID, T0, "x"),
			"SetRisk": repo.SetRisk(ctx, other, b.ID, []byte(`{}`)),
		} {
			if err := notFound("sessions."+name+" from another realm", err); err != nil {
				return err
			}
		}
		got, err = repo.Get(ctx, r, b.ID)
		if err != nil || got.RevokedAt != nil || !got.LastSeenAt.Equal(b.LastSeenAt) {
			return fmt.Errorf("another realm changed the session: %+v, %v", got, err)
		}
		return nil
	})
}

func testSessionRevokeByPrincipal(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, v := id.New(id.Realm), id.New(id.User), id.New(id.User)
	keep, x1, x2, done, otherUser := newSession(r, u, T0), newSession(r, u, T0), newSession(r, u, T0), newSession(r, u, T0), newSession(r, v, T0)
	// 失効の予定（ID の入れ替え後の猶予）があるセッションも、一括失効で前倒しする。
	x2.RevokedAt, x2.RevokeReason = ptr(T0.Add(24*time.Hour)), "rotated"
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Sessions()
		for _, x := range []port.Session{keep, x1, x2, done, otherUser} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := repo.Revoke(ctx, r, done.ID, T0, "logout"); err != nil {
			return err
		}
		ids, err := repo.RevokeByPrincipal(ctx, r, port.PrincipalUser, u, keep.ID, T0.Add(time.Hour), "credential_changed")
		if err != nil {
			return err
		}
		if len(ids) != 2 {
			return fmt.Errorf("revoked %v, want x1 and x2", ids)
		}
		for _, x := range []port.Session{x1, x2} {
			got, _ := repo.Get(ctx, r, x.ID)
			if got.RevokedAt == nil || got.RevokeReason != "credential_changed" {
				return fmt.Errorf("%s not revoked: %+v", x.ID, got)
			}
		}
		for _, x := range []port.Session{keep, otherUser} {
			if got, _ := repo.Get(ctx, r, x.ID); got.RevokedAt != nil {
				return fmt.Errorf("%s must stay active", x.ID)
			}
		}
		if got, _ := repo.Get(ctx, r, done.ID); got.RevokeReason != "logout" {
			return fmt.Errorf("already revoked session changed: %+v", got)
		}
		ids, err = repo.RevokeByPrincipal(ctx, id.New(id.Realm), port.PrincipalUser, v, "", T0, "x")
		if err != nil || len(ids) != 0 {
			return fmt.Errorf("another realm revoked %v, %v", ids, err)
		}
		return nil
	})
}

func testSessionMoveOrg(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, v := id.New(id.Realm), id.New(id.User), id.New(id.User)
	from, to, other := id.New(id.Org), id.New(id.Org), id.New(id.Org)
	a, b, elsewhere, otherUser := newSession(r, u, T0), newSession(r, u, T0), newSession(r, u, T0), newSession(r, v, T0)
	a.ActiveOrgID, b.ActiveOrgID, elsewhere.ActiveOrgID, otherUser.ActiveOrgID = from, from, other, from
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Sessions()
		for _, x := range []port.Session{a, b, elsewhere, otherUser} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		ids, err := repo.MoveOrg(ctx, r, u, from, to)
		if err != nil {
			return err
		}
		want := []string{a.ID, b.ID}
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			return fmt.Errorf("moved %v, want %v", ids, want)
		}
		for x, org := range map[string]string{a.ID: to, b.ID: to, elsewhere.ID: other, otherUser.ID: from} {
			if got, _ := repo.Get(ctx, r, x); got.ActiveOrgID != org {
				return fmt.Errorf("%s org = %s, want %s", x, got.ActiveOrgID, org)
			}
		}
		if ids, err := repo.MoveOrg(ctx, id.New(id.Realm), v, from, to); err != nil || len(ids) != 0 {
			return fmt.Errorf("another realm moved %v, %v", ids, err)
		}
		return nil
	})
}

func testUserDeletion(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	u, other := newUser(r), newUser(r)
	e, oe := newEmail(r, u.ID, "u"), newEmail(r, other.ID, "o")
	ses, os := newSession(r, u.ID, T0), newSession(r, other.ID, T0)
	pk, pw, tp, rc := newPasskey(r, u.ID, "cred-u"), newPassword(r, u.ID), newTOTP(r, u.ID), newRecoveryCode(r, u.ID, "l1")
	rb := port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: r, Role: "realm:admin", PrincipalType: port.PrincipalUser, PrincipalID: u.ID, CreatedAt: T0}
	r2 := id.New(id.Realm)
	g := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r, Name: "team", CreatedAt: T0, UpdatedAt: T0}
	g2 := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: r2, Name: "team", CreatedAt: T0, UpdatedAt: T0}
	member := func(gid, uid string) port.GroupMember {
		return port.GroupMember{GroupID: gid, MemberType: port.PrincipalUser, MemberID: uid, CreatedAt: T0}
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, x := range []port.User{u, other} {
			if err := tx.Users().Create(ctx, x); err != nil {
				return err
			}
		}
		for _, err := range []error{tx.Emails().Create(ctx, e), tx.Emails().Create(ctx, oe), tx.Sessions().Create(ctx, ses), tx.Sessions().Create(ctx, os),
			tx.Passkeys().Create(ctx, pk), tx.Passwords().Create(ctx, pw), tx.TOTP().Create(ctx, tp), tx.RecoveryCodes().Replace(ctx, r, u.ID, []port.RecoveryCode{rc}),
			tx.RoleBindings().Create(ctx, rb), tx.Groups().Create(ctx, g), tx.Groups().Create(ctx, g2),
			tx.Groups().AddMember(ctx, r, member(g.ID, u.ID)), tx.Groups().AddMember(ctx, r, member(g.ID, other.ID)),
			tx.Groups().AddMember(ctx, r2, member(g2.ID, u.ID))} {
			if err != nil {
				return err
			}
		}
		at := T0.Add(30 * 24 * time.Hour)
		if err := tx.Users().SetDeletion(ctx, r, u.ID, &at, T0); err != nil {
			return err
		}
		if err := tx.Users().SetLegalHold(ctx, r, u.ID, true, T0); err != nil {
			return err
		}
		if got, _ := tx.Users().Get(ctx, r, u.ID); got.DeletionScheduledAt == nil || !got.DeletionScheduledAt.Equal(at) || !got.LegalHold {
			return fmt.Errorf("after scheduling = %+v", got)
		}
		if err := tx.Users().SetLegalHold(ctx, r, u.ID, false, T0); err != nil {
			return err
		}
		if err := tx.Users().Erase(ctx, r, u.ID, at); err != nil {
			return err
		}
		got, err := tx.Users().Get(ctx, r, u.ID)
		if err != nil || got.Status != port.UserDeleted || got.DeletionScheduledAt != nil || got.LegalHold || !got.UpdatedAt.Equal(at) {
			return fmt.Errorf("tombstone = %+v, %v", got, err)
		}
		// メールのインデックスは消え、同じアドレスで登録し直せる。
		if err := notFound("erased email", second(tx.Emails().GetByIndex(ctx, r, e.Index))); err != nil {
			return err
		}
		if err := notFound("erased session", second(tx.Sessions().Get(ctx, r, ses.ID))); err != nil {
			return err
		}
		if err := notFound("erased passkey", second(tx.Passkeys().GetByPublicID(ctx, r, pk.PublicID))); err != nil {
			return err
		}
		if err := notFound("erased password", second(tx.Passwords().Get(ctx, r, pw.ID))); err != nil {
			return err
		}
		for name, n := range map[string]func() (int, error){
			"totp":     func() (int, error) { return count(tx.TOTP().ListByUser(ctx, r, u.ID)) },
			"recovery": func() (int, error) { return count(tx.RecoveryCodes().ListByUser(ctx, r, u.ID)) },
			"roles":    func() (int, error) { return count(tx.RoleBindings().ListByPrincipal(ctx, r, port.PrincipalUser, u.ID)) },
			"groups":   func() (int, error) { return count(tx.Groups().ListByMember(ctx, r, port.PrincipalUser, u.ID)) },
		} {
			if got, err := n(); err != nil || got != 0 {
				return fmt.Errorf("%s after erase = %d, %v", name, got, err)
			}
		}
		// 別のユーザーのものは残る。
		if _, err := tx.Emails().GetByIndex(ctx, r, oe.Index); err != nil {
			return fmt.Errorf("other email: %v", err)
		}
		if _, err := tx.Sessions().Get(ctx, r, os.ID); err != nil {
			return fmt.Errorf("other session: %v", err)
		}
		// 別のユーザーの所属と、別の realm の所属は残る。
		if n, err := count(tx.Groups().ListByMember(ctx, r, port.PrincipalUser, other.ID)); err != nil || n != 1 {
			return fmt.Errorf("other user's groups = %d, %v", n, err)
		}
		if n, err := count(tx.Groups().ListByMember(ctx, r2, port.PrincipalUser, u.ID)); err != nil || n != 1 {
			return fmt.Errorf("groups in another realm = %d, %v", n, err)
		}
		if err := notFound("erase in another realm", tx.Users().Erase(ctx, id.New(id.Realm), other.ID, at)); err != nil {
			return err
		}
		return notFound("set deletion in another realm", tx.Users().SetDeletion(ctx, id.New(id.Realm), other.ID, nil, at))
	})
}

func testServiceAccounts(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	a := port.ServiceAccount{ID: id.New(id.ServiceAccount), RealmID: r, Name: "notification-delivery", CreatedAt: T0}
	c := port.ServiceAccountCredential{ID: id.New(id.SACredential), RealmID: r, ServiceAccountID: a.ID, Type: "api_key",
		SecretHash: []byte("h"), CreatedAt: T0, ExpiresAt: ptr(T0.Add(time.Hour))}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.ServiceAccounts()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		if err := repo.CreateCredential(ctx, c); err != nil {
			return err
		}
		// 別の realm のサービスアカウントには付けられない。
		bad := c
		bad.ID, bad.RealmID = id.New(id.SACredential), id.New(id.Realm)
		if err := notFound("credential for another realm's account", repo.CreateCredential(ctx, bad)); err != nil {
			return err
		}
		got, err := repo.Get(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("serviceAccounts.Get = %+v, %v", got, err)
		}
		gc, err := repo.GetCredential(ctx, r, c.ID)
		if err != nil || !reflect.DeepEqual(gc, c) {
			return fmt.Errorf("GetCredential = %+v, %v", gc, err)
		}
		if err := repo.RevokeCredential(ctx, r, c.ID, T0.Add(time.Minute)); err != nil {
			return err
		}
		if err := repo.RevokeCredential(ctx, r, c.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		gc, _ = repo.GetCredential(ctx, r, c.ID)
		if gc.RevokedAt == nil || !gc.RevokedAt.Equal(T0.Add(time.Minute)) {
			return fmt.Errorf("revoked_at = %v", gc.RevokedAt)
		}
		other := id.New(id.Realm)
		if err := notFound("RevokeCredential from another realm", repo.RevokeCredential(ctx, other, c.ID, T0)); err != nil {
			return err
		}
		_, err = repo.GetCredential(ctx, other, c.ID)
		return notFound("GetCredential from another realm", err)
	})
}

// testServiceAccountsM7 は Org・有効期間・論理削除・公開鍵・アクセストークン（ADR 0074）。
func testServiceAccountsM7(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	a := port.ServiceAccount{ID: "sva_00000000000000000000000001", RealmID: r, OrgID: id.New(id.Org), Name: "ci", ValidFrom: ptr(T0),
		ValidUntil: ptr(T0.Add(24 * time.Hour)), CreatedBy: "usr_x", CreatedAt: T0}
	b := port.ServiceAccount{ID: "sva_00000000000000000000000002", RealmID: r, Name: "batch", CreatedAt: T0}
	k := port.ServiceAccountCredential{ID: id.New(id.SACredential), RealmID: r, ServiceAccountID: a.ID, Type: "private_key_jwt",
		PublicKey: []byte(`{"kty":"OKP"}`), Alg: "EdDSA", CreatedAt: T0.Add(time.Second)}
	c := port.ServiceAccountCredential{ID: id.New(id.SACredential), RealmID: r, ServiceAccountID: a.ID, Type: "client_secret",
		SecretHash: []byte("h"), CreatedAt: T0}
	tok := port.ServiceAccountToken{ID: id.New(id.SAToken), RealmID: r, ServiceAccountID: a.ID, CredentialID: c.ID, Hash: []byte("t"),
		CreatedAt: T0, ExpiresAt: T0.Add(10 * time.Minute)}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.ServiceAccounts()
		for _, x := range []port.ServiceAccount{b, a} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		for _, x := range []port.ServiceAccountCredential{k, c} {
			if err := repo.CreateCredential(ctx, x); err != nil {
				return err
			}
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("serviceAccounts.Get = %+v, %v", got, err)
		}
		l, err := repo.List(ctx, r, "", 1)
		if err != nil || len(l) != 1 || l[0].ID != a.ID {
			return fmt.Errorf("serviceAccounts.List = %+v, %v", l, err)
		}
		if l, err = repo.List(ctx, r, a.ID, 10); err != nil || len(l) != 1 || !reflect.DeepEqual(l[0], b) {
			return fmt.Errorf("serviceAccounts.List after = %+v, %v", l, err)
		}
		cs, err := repo.ListCredentials(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(cs, []port.ServiceAccountCredential{c, k}) {
			return fmt.Errorf("serviceAccounts.ListCredentials = %+v, %v", cs, err)
		}
		if err := repo.SetDeleted(ctx, r, a.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if err := repo.SetDeleted(ctx, r, a.ID, T0.Add(2*time.Hour)); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, a.ID); got.DeletedAt == nil || !got.DeletedAt.Equal(T0.Add(time.Hour)) {
			return fmt.Errorf("deleted_at = %v", got.DeletedAt)
		}
		if err := notFound("SetDeleted missing", repo.SetDeleted(ctx, r, id.New(id.ServiceAccount), T0)); err != nil {
			return err
		}
		if err := notFound("SetDeleted from another realm", repo.SetDeleted(ctx, id.New(id.Realm), b.ID, T0)); err != nil {
			return err
		}
		if err := repo.CreateToken(ctx, tok); err != nil {
			return err
		}
		later := tok
		later.ID, later.ExpiresAt = id.New(id.SAToken), T0.Add(time.Hour)
		if err := repo.CreateToken(ctx, later); err != nil {
			return err
		}
		if got, err := repo.GetToken(ctx, r, tok.ID); err != nil || !reflect.DeepEqual(got, tok) {
			return fmt.Errorf("serviceAccounts.GetToken = %+v, %v", got, err)
		}
		if _, err := repo.GetToken(ctx, id.New(id.Realm), tok.ID); notFound("GetToken from another realm", err) != nil {
			return notFound("GetToken from another realm", err)
		}
		n, err := repo.DeleteExpiredTokens(ctx, T0.Add(30*time.Minute), 10)
		if err != nil || n != 1 {
			return fmt.Errorf("serviceAccounts.DeleteExpiredTokens = %d, %v", n, err)
		}
		if _, err := repo.GetToken(ctx, r, tok.ID); notFound("expired token", err) != nil {
			return notFound("expired token", err)
		}
		_, err = repo.GetToken(ctx, r, later.ID)
		return err
	})
}

// ---------------------------------------------------------------------------

// seedUser は realm にユーザー1人と、そのメール・外部 ID・セッション・ロールを入れる。
// 分離の検査で引く値は固定にして、別の realm からも同じ引数で問い合わせる。
const (
	isoUser    = "usr_00000000000000000000000000"
	isoPublic  = "usr_00000000000000000000000009"
	isoPasskey = "psk_00000000000000000000000009"
	isoTOTP    = "otp_00000000000000000000000009"
	isoConn    = "con_00000000000000000000000000"
	isoSubject = "iso-subject"
	isoEmail   = "iso-email-index"
	isoSession = "ses_00000000000000000000000000"
	isoAccount = "sva_00000000000000000000000000"
	isoCred    = "sac_00000000000000000000000000"
)

func count[V any](vs []V, err error) (int, error) { return len(vs), err }

func countOne[V any](_ V, err error) (int, error) {
	if errors.Is(err, errs.NotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return 1, nil
}

var authnIsolationCases = []IsolationCase{
	{
		Name: "Users.Get+GetByPublicID+List",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			u := newUser(r)
			u.ID, u.PublicID = isoUser, isoPublic
			return tx.Users().Create(ctx, u)
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := countOne(tx.Users().Get(ctx, r, isoUser))
			if err != nil {
				return 0, err
			}
			m, err := countOne(tx.Users().GetByPublicID(ctx, r, isoPublic))
			if err != nil {
				return 0, err
			}
			l, err := count(tx.Users().List(ctx, r, "", 10))
			return n + m + l, err
		},
	},
	{
		Name: "Emails.GetByIndex+ListByUser",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.Emails().Create(ctx, newEmail(r, isoUser, isoEmail))
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := countOne(tx.Emails().GetByIndex(ctx, r, []byte(isoEmail)))
			if err != nil {
				return 0, err
			}
			m, err := count(tx.Emails().ListByUser(ctx, r, isoUser))
			return n + m, err
		},
	},
	{
		Name: "Identities.GetBySubject+ListByUser",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.Identities().Create(ctx, port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: r, UserID: isoUser,
				ConnectionID: isoConn, ProviderSubject: isoSubject, CreatedAt: T0})
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := countOne(tx.Identities().GetBySubject(ctx, r, isoConn, isoSubject))
			if err != nil {
				return 0, err
			}
			m, err := count(tx.Identities().ListByUser(ctx, r, isoUser))
			return n + m, err
		},
	},
	{
		Name: "Connections.Get+GetBySlug+List+ListByOwner+CountOwned",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.Connections().Create(ctx, port.Connection{ID: isoConn, RealmID: r, Slug: "iso", Type: "oidc", Config: []byte("{}"), CreatedAt: T0,
				OwnerOrgID: isoOrg})
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			a, err := countOne(tx.Connections().Get(ctx, r, isoConn))
			if err != nil {
				return 0, err
			}
			b, err := countOne(tx.Connections().GetBySlug(ctx, r, "iso"))
			if err != nil {
				return 0, err
			}
			c, err := count(tx.Connections().List(ctx, r))
			if err != nil {
				return 0, err
			}
			d, err := count(tx.Connections().ListByOwner(ctx, r, isoOrg))
			if err != nil {
				return 0, err
			}
			e, err := tx.Connections().CountOwned(ctx, r)
			return a + b + c + d + e, err
		},
	},
	{
		Name: "Sessions.Get+ListByPrincipal",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			s := newSession(r, isoUser, T0)
			s.ID = isoSession
			return tx.Sessions().Create(ctx, s)
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := countOne(tx.Sessions().Get(ctx, r, isoSession))
			if err != nil {
				return 0, err
			}
			m, err := count(tx.Sessions().ListByPrincipal(ctx, r, port.PrincipalUser, isoUser))
			return n + m, err
		},
	},
	{
		Name: "ServiceAccounts.Get+GetCredential",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			if err := tx.ServiceAccounts().Create(ctx, port.ServiceAccount{ID: isoAccount, RealmID: r, Name: "iso", CreatedAt: T0}); err != nil {
				return err
			}
			return tx.ServiceAccounts().CreateCredential(ctx, port.ServiceAccountCredential{ID: isoCred, RealmID: r,
				ServiceAccountID: isoAccount, Type: "api_key", SecretHash: []byte("h"), CreatedAt: T0})
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := countOne(tx.ServiceAccounts().Get(ctx, r, isoAccount))
			if err != nil {
				return 0, err
			}
			m, err := countOne(tx.ServiceAccounts().GetCredential(ctx, r, isoCred))
			if err != nil {
				return 0, err
			}
			l, err := count(tx.ServiceAccounts().List(ctx, r, "", 10))
			if err != nil {
				return 0, err
			}
			c, err := count(tx.ServiceAccounts().ListCredentials(ctx, r, isoAccount))
			return n + m + l + c, err
		},
	},
	{
		Name: "RoleBindings.ListByPrincipal+ListByRole",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.RoleBindings().Create(ctx, port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: r, Role: "realm:owner",
				PrincipalType: port.PrincipalUser, PrincipalID: isoUser, CreatedAt: T0})
		},
		Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
			n, err := count(tx.RoleBindings().ListByPrincipal(ctx, r, port.PrincipalUser, isoUser))
			if err != nil {
				return 0, err
			}
			m, err := count(tx.RoleBindings().ListByRole(ctx, r, "realm:owner"))
			return n + m, err
		},
	},
	passkeyIsolationCase,
	totpIsolationCase,
	passwordIsolationCase,
	recoveryCodeIsolationCase,
	suspensionIsolationCase,
	orgIsolationCase,
	membershipIsolationCase,
	invitationIsolationCase,
	quotaGrantIsolationCase,
	orgDomainIsolationCase,
	orgHierarchyIsolationCase,
	managedUserIsolationCase,
}
