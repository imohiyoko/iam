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

func newPasskey(realmID, userID, credentialID string) port.Passkey {
	return port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: realmID, UserID: userID,
		CredentialID: []byte(credentialID), PublicKey: []byte("cose-key"), Alg: -7, SignCount: 0, Flags: 0x1d,
		AAGUID: make([]byte, 16), Transports: []string{"internal", "hybrid"}, Name: "Passkey", CreatedAt: T0}
}

func testPasskeys(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	p := newPasskey(r, u, "cred-1")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Passkeys()
		if err := repo.Create(ctx, p); err != nil {
			return err
		}
		dup := newPasskey(r, id.New(id.User), "cred-1")
		if err := conflict("same credential id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		samePublic := newPasskey(r, u, "cred-x")
		samePublic.PublicID = p.PublicID
		if err := conflict("same public id", repo.Create(ctx, samePublic)); err != nil {
			return err
		}
		// 別の realm では同じ credential_id を登録できる（RP ID が realm ごとに違いうるため）。
		if err := repo.Create(ctx, newPasskey(id.New(id.Realm), u, "cred-1")); err != nil {
			return fmt.Errorf("same credential in another realm: %w", err)
		}
		bare := newPasskey(r, u, "cred-2")
		bare.AAGUID, bare.Transports = nil, nil
		bare.CreatedAt = T0.Add(time.Second)
		if err := repo.Create(ctx, bare); err != nil {
			return err
		}
		got, err := repo.GetByCredentialID(ctx, r, []byte("cred-1"))
		if err != nil || !reflect.DeepEqual(got, p) {
			return fmt.Errorf("passkeys.GetByCredentialID = %+v, %v", got, err)
		}
		if got, err := repo.GetByPublicID(ctx, r, p.PublicID); err != nil || got.ID != p.ID {
			return fmt.Errorf("passkeys.GetByPublicID = %+v, %v", got, err)
		}
		_, err = repo.GetByCredentialID(ctx, r, []byte("cred-3"))
		if err := notFound("missing credential", err); err != nil {
			return err
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil || len(list) != 2 || list[0].ID != p.ID || list[1].ID != bare.ID || len(list[1].Transports) != 0 {
			return fmt.Errorf("passkeys.ListByUser = %+v, %v", list, err)
		}
		return nil
	})
	at := T0.Add(time.Hour)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Passkeys()
		if err := repo.Used(ctx, r, p.ID, 7, 0x5d, at); err != nil {
			return err
		}
		if err := repo.Rename(ctx, r, p.ID, "Laptop"); err != nil {
			return err
		}
		org := id.New(id.Org)
		if err := repo.SetPreferredOrg(ctx, r, p.ID, org); err != nil {
			return err
		}
		got, err := repo.GetByPublicID(ctx, r, p.PublicID)
		if err != nil || got.SignCount != 7 || got.Flags != 0x5d || got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) || got.Name != "Laptop" ||
			got.PreferredOrgID != org {
			return fmt.Errorf("after Used and Rename = %+v, %v", got, err)
		}
		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"used in another realm":   repo.Used(ctx, other, p.ID, 8, 0, at),
			"rename in another realm": repo.Rename(ctx, other, p.ID, "x"),
			"org in another realm":    repo.SetPreferredOrg(ctx, other, p.ID, ""),
			"revoke in another realm": repo.Revoke(ctx, other, p.ID, at, "x"),
			"revoke missing":          repo.Revoke(ctx, r, id.New(id.Passkey), at, "x"),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		return nil
	})
	// 無効化：GetByCredentialID から消え、同じ credential_id は再登録できない（4.6）。無効化は1回だけ効く。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Passkeys()
		if err := repo.Revoke(ctx, r, p.ID, at, "revoked_by_user"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, p.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, err := repo.GetByPublicID(ctx, r, p.PublicID)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "revoked_by_user" {
			return fmt.Errorf("revoked passkey = %+v, %v", got, err)
		}
		_, err = repo.GetByCredentialID(ctx, r, p.CredentialID)
		if err := notFound("revoked credential", err); err != nil {
			return err
		}
		return conflict("re-register revoked credential", repo.Create(ctx, newPasskey(r, u, "cred-1")))
	})
}

func testPasskeyUniqueConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Passkeys().Create(ctx, newPasskey(r, id.New(id.User), "same"))
		})
	}))
}

var passkeyIsolationCase = IsolationCase{
	Name: "Passkeys.GetByCredentialID+GetByPublicID+ListByUser",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		p := newPasskey(r, isoUser, "iso-cred")
		p.PublicID = isoPasskey
		return tx.Passkeys().Create(ctx, p)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		n, err := countOne(tx.Passkeys().GetByCredentialID(ctx, r, []byte("iso-cred")))
		if err != nil {
			return 0, err
		}
		m, err := countOne(tx.Passkeys().GetByPublicID(ctx, r, isoPasskey))
		if err != nil {
			return 0, err
		}
		l, err := count(tx.Passkeys().ListByUser(ctx, r, isoUser))
		return n + m + l, err
	},
}
