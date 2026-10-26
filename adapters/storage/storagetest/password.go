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

func newPassword(realmID, userID string) port.PasswordCredential {
	return port.PasswordCredential{ID: id.New(id.Password), RealmID: realmID, UserID: userID, Hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA", CreatedAt: T0}
}

func testPasswords(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	c := newPassword(r, u)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Passwords()
		if err := notFound("active before create", second(repo.GetActive(ctx, r, u))); err != nil {
			return err
		}
		if err := repo.Create(ctx, c); err != nil {
			return err
		}
		// 有効なパスワードはユーザーに1つまで。
		if err := conflict("second active password", repo.Create(ctx, newPassword(r, u))); err != nil {
			return err
		}
		got, err := repo.GetActive(ctx, r, u)
		if err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("password.GetActive = %+v, %v", got, err)
		}
		if err := repo.UpdateHash(ctx, r, c.ID, "$argon2id$new"); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, c.ID); got.Hash != "$argon2id$new" {
			return fmt.Errorf("hash after update = %q", got.Hash)
		}
		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"get in another realm":         second(repo.Get(ctx, other, c.ID)),
			"active in another realm":      second(repo.GetActive(ctx, other, u)),
			"update hash in another realm": repo.UpdateHash(ctx, other, c.ID, "x"),
			"revoke in another realm":      repo.Revoke(ctx, other, c.ID, T0, "x"),
			"revoke missing":               repo.Revoke(ctx, r, id.New(id.Password), T0, "x"),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		at := T0.Add(time.Hour)
		if err := repo.Revoke(ctx, r, c.ID, at, "changed"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, c.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, err = repo.Get(ctx, r, c.ID)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "changed" {
			return fmt.Errorf("revoked password = %+v, %v", got, err)
		}
		for name, err := range map[string]error{
			"active after revoke":      second(repo.GetActive(ctx, r, u)),
			"update hash after revoke": repo.UpdateHash(ctx, r, c.ID, "x"),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		// 無効化の後は新しいパスワードを作れる。
		next := newPassword(r, u)
		next.CreatedAt = at
		return repo.Create(ctx, next)
	})
}

// testPasswordCreateConcurrent は同じユーザーに同時にパスワードを作っても1つしか通らないことを確かめる。
func testPasswordCreateConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.Passwords().Create(ctx, newPassword(r, u))
		})
	}))
}

var passwordIsolationCase = IsolationCase{
	Name: "Passwords.GetActive",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		return tx.Passwords().Create(ctx, newPassword(r, isoUser))
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		return countOne(tx.Passwords().GetActive(ctx, r, isoUser))
	},
}

// second は2つ目の戻り値（エラー）だけを返す。
func second[V any](_ V, err error) error { return err }
