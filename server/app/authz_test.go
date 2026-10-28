package app

import (
	"context"
	"testing"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/port"
)

// internalIDs は公開 ID のユーザーと Org の内部 ID を返す。
func (l *loginEnv) internalIDs(t *testing.T, userPublicID, orgPublicID string) (string, string) {
	t.Helper()
	var uid, oid string
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, userPublicID)
		if err != nil {
			return err
		}
		o, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, orgPublicID)
		uid, oid = u.ID, o.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return uid, oid
}

func TestAuthzOrgRoles(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "sam@acme.example", "member")
	_, _ = l.login(t, "zed@example.com")
	boss, oid := l.internalIDs(t, l.userID(t, "boss@acme.example"), acme)
	sam, _ := l.internalIDs(t, l.userID(t, "sam@acme.example"), acme)
	zed, _ := l.internalIDs(t, l.userID(t, "zed@example.com"), acme)

	for _, c := range []struct {
		who, perm string
		want      bool
	}{
		{boss, role.PermOrgDelete, true},
		{sam, role.PermOrgRead, true},
		{sam, role.PermOrgInvite, false},
		{zed, role.PermOrgRead, false},
	} {
		got, err := l.a.authz.Check(t.Context(), l.a.realm.ID, check.Request{Principal: check.Principal{Type: port.PrincipalUser, ID: c.who},
			Action: c.perm, OrgID: oid})
		if err != nil || got != c.want {
			t.Errorf("Check(%s, %s) = %v, %v; want %v", c.who, c.perm, got, err, c.want)
		}
	}
}

// internalUserID は公開 ID のユーザーの内部 ID を返す。
func (l *loginEnv) internalUserID(t *testing.T, userPublicID string) string {
	t.Helper()
	var uid string
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, userPublicID)
		uid = u.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return uid
}
