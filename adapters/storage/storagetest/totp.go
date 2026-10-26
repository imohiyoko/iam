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

func newTOTP(realmID, userID string) port.TOTPCredential {
	return port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: realmID, UserID: userID,
		SecretCiphertext: []byte("secret-ct"), LastUsedStep: 100, CreatedAt: T0}
}

func testTOTP(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	c := newTOTP(r, u)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.TOTP()
		if err := repo.Create(ctx, c); err != nil {
			return err
		}
		dup := newTOTP(r, u)
		dup.PublicID = c.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		got, err := repo.GetByPublicID(ctx, r, c.PublicID)
		if err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("totp.GetByPublicID = %+v, %v", got, err)
		}
		second := newTOTP(r, u)
		second.CreatedAt = T0.Add(time.Second)
		if err := repo.Create(ctx, second); err != nil {
			return err
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil || len(list) != 2 || list[0].ID != c.ID {
			return fmt.Errorf("totp.ListByUser = %+v, %v", list, err)
		}
		// 時間窓は進むだけ。同じか前の窓は再利用として拒否する。
		if err := repo.Use(ctx, r, c.ID, 101); err != nil {
			return err
		}
		for _, step := range []int64{101, 100} {
			if err := conflict(fmt.Sprintf("reuse step %d", step), repo.Use(ctx, r, c.ID, step)); err != nil {
				return err
			}
		}
		if got, _ := repo.GetByPublicID(ctx, r, c.PublicID); got.LastUsedStep != 101 {
			return fmt.Errorf("last used step = %d", got.LastUsedStep)
		}
		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"use in another realm":    repo.Use(ctx, other, c.ID, 200),
			"revoke in another realm": repo.Revoke(ctx, other, c.ID, T0, "x"),
			"use missing":             repo.Use(ctx, r, id.New(id.TOTP), 200),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		at := T0.Add(time.Hour)
		if err := repo.Revoke(ctx, r, c.ID, at, "revoked_by_user"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, c.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, err = repo.GetByPublicID(ctx, r, c.PublicID)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "revoked_by_user" {
			return fmt.Errorf("revoked totp = %+v, %v", got, err)
		}
		return nil
	})
}

// testTOTPUseConcurrent は同じ時間窓のコードを同時に使っても1つしか通らないことを確かめる。
func testTOTPUseConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	c := newTOTP(r, id.New(id.User))
	tx(t, s, func(ctx context.Context, tx port.Tx) error { return tx.TOTP().Create(ctx, c) })
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.TOTP().Use(ctx, r, c.ID, 200)
		})
	}))
}

var totpIsolationCase = IsolationCase{
	Name: "TOTP.GetByPublicID+ListByUser",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		c := newTOTP(r, isoUser)
		c.PublicID = isoTOTP
		return tx.TOTP().Create(ctx, c)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		n, err := countOne(tx.TOTP().GetByPublicID(ctx, r, isoTOTP))
		if err != nil {
			return 0, err
		}
		m, err := count(tx.TOTP().ListByUser(ctx, r, isoUser))
		return n + m, err
	},
}
