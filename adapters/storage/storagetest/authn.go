package storagetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	{"Emails", testEmails},
	{"EmailUniqueConcurrent", testEmailUniqueConcurrent},
	{"Identities", testIdentities},
	{"IdentityUniqueConcurrent", testIdentityUniqueConcurrent},
	{"Connections", testConnections},
	{"Sessions", testSessions},
	{"SessionRevokeByPrincipal", testSessionRevokeByPrincipal},
	{"ServiceAccounts", testServiceAccounts},
	{"RoleBindings", testRoleBindings},
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
	return port.UserEmail{ID: id.New(id.Email), RealmID: realmID, UserID: userID, Ciphertext: []byte("ct-" + index),
		Index: []byte(index), DomainIndex: []byte("dom"), IndexKeyID: "ik_1", VerifiedAt: ptr(T0),
		VerifiedVia: port.VerifiedViaCode, IsPrimary: true, CreatedAt: T0}
}

func newSession(realmID, userID string, created time.Time) port.Session {
	return port.Session{ID: id.NewExternal(id.Session), RealmID: realmID, PrincipalType: port.PrincipalUser, PrincipalID: userID,
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
		return nil
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
	i := port.Identity{ID: id.New(id.Identity), RealmID: r, UserID: u, ConnectionID: conn, ProviderSubject: "sub-1", CreatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Identities()
		if err := repo.Create(ctx, i); err != nil {
			return err
		}
		dup := i
		dup.ID, dup.UserID = id.New(id.Identity), id.New(id.User)
		if err := conflict("same subject", repo.Create(ctx, dup)); err != nil {
			return err
		}
		other := i
		other.ID, other.ConnectionID = id.New(id.Identity), id.New(id.Connection)
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
		return nil
	})
}

func testIdentityUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, conn := id.New(id.Realm), id.New(id.Connection)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Identities().Create(ctx, port.Identity{ID: id.New(id.Identity), RealmID: r, UserID: id.New(id.User),
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
}

func testSessions(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	a := newSession(r, u, T0)
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

		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"Get":    func() error { _, err := repo.Get(ctx, other, a.ID); return err }(),
			"Touch":  repo.Touch(ctx, other, b.ID, T0.Add(time.Hour)),
			"Revoke": repo.Revoke(ctx, other, b.ID, T0, "x"),
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

func testRoleBindings(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	b := port.RoleBinding{ID: id.New(id.RoleBinding), RealmID: r, Role: "realm:owner", PrincipalType: port.PrincipalUser, PrincipalID: u, CreatedAt: T0}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.RoleBindings()
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		dup := b
		dup.ID = id.New(id.RoleBinding)
		if err := conflict("same binding", repo.Create(ctx, dup)); err != nil {
			return err
		}
		dup.Role, dup.CreatedAt = "realm:security", T0.Add(time.Minute)
		if err := repo.Create(ctx, dup); err != nil {
			return err
		}
		list, err := repo.ListByPrincipal(ctx, r, port.PrincipalUser, u)
		if err != nil || len(list) != 2 || !reflect.DeepEqual(list[0], b) {
			return fmt.Errorf("ListByPrincipal = %+v, %v", list, err)
		}
		list, err = repo.ListByRole(ctx, r, "realm:owner")
		if err != nil || len(list) != 1 || list[0].ID != b.ID {
			return fmt.Errorf("ListByRole = %+v, %v", list, err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------

// seedUser は realm にユーザー1人と、そのメール・外部 ID・セッション・ロールを入れる。
// 分離の検査で引く値は固定にして、別の realm からも同じ引数で問い合わせる。
const (
	isoUser    = "usr_00000000000000000000000000"
	isoPublic  = "usr_00000000000000000000000009"
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
		Name: "Users.Get+GetByPublicID",
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
			return n + m, err
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
			return tx.Identities().Create(ctx, port.Identity{ID: id.New(id.Identity), RealmID: r, UserID: isoUser,
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
		Name: "Connections.Get+GetBySlug+List",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.Connections().Create(ctx, port.Connection{ID: isoConn, RealmID: r, Slug: "iso", Type: "oidc", Config: []byte("{}"), CreatedAt: T0})
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
			return a + b + c, err
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
			return n + m, err
		},
	},
	{
		Name: "RoleBindings.ListByPrincipal+ListByRole",
		Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
			return tx.RoleBindings().Create(ctx, port.RoleBinding{ID: id.New(id.RoleBinding), RealmID: r, Role: "realm:owner",
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
}
