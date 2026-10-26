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

func newRecoveryCode(realmID, userID, lookup string) port.RecoveryCode {
	return port.RecoveryCode{ID: id.New(id.RecoveryCode), RealmID: realmID, UserID: userID, Lookup: lookup,
		Hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA", CreatedAt: T0}
}

func testRecoveryCodes(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, other := id.New(id.Realm), id.New(id.User), id.New(id.User)
	a, b := newRecoveryCode(r, u, "AAAA"), newRecoveryCode(r, u, "BBBB")
	if b.ID < a.ID {
		a, b = b, a
	}
	keep := newRecoveryCode(r, other, "AAAA")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.RecoveryCodes()
		if err := repo.Replace(ctx, r, u, []port.RecoveryCode{a, b}); err != nil {
			return err
		}
		if err := repo.Replace(ctx, r, other, []port.RecoveryCode{keep}); err != nil {
			return err
		}
		got, err := repo.ListByUser(ctx, r, u)
		if err != nil || !reflect.DeepEqual(got, []port.RecoveryCode{a, b}) {
			return fmt.Errorf("ListByUser = %+v, %v", got, err)
		}
		at := T0.Add(time.Minute)
		if ok, err := repo.MarkUsed(ctx, r, a.ID, at); err != nil || !ok {
			return fmt.Errorf("MarkUsed = %v, %v", ok, err)
		}
		if ok, err := repo.MarkUsed(ctx, r, a.ID, at); err != nil || ok {
			return fmt.Errorf("MarkUsed twice = %v, %v", ok, err)
		}
		if ok, err := repo.MarkUsed(ctx, id.New(id.Realm), b.ID, at); err != nil || ok {
			return fmt.Errorf("MarkUsed in another realm = %v, %v", ok, err)
		}
		got, _ = repo.ListByUser(ctx, r, u)
		if len(got) != 2 || got[0].UsedAt == nil || !got[0].UsedAt.Equal(at) || got[1].UsedAt != nil {
			return fmt.Errorf("after use = %+v", got)
		}
		// 作り直すと古いコード（使用済みも）は消える。他のユーザーのものは残る。
		c := newRecoveryCode(r, u, "AAAA")
		if err := repo.Replace(ctx, r, u, []port.RecoveryCode{c}); err != nil {
			return err
		}
		if got, _ := repo.ListByUser(ctx, r, u); len(got) != 1 || got[0].ID != c.ID {
			return fmt.Errorf("after replace = %+v", got)
		}
		if got, _ := repo.ListByUser(ctx, r, other); len(got) != 1 {
			return fmt.Errorf("other user after replace = %+v", got)
		}
		if ok, _ := repo.MarkUsed(ctx, r, b.ID, at); ok {
			return fmt.Errorf("replaced code still usable")
		}
		if err := repo.Replace(ctx, r, u, nil); err != nil {
			return err
		}
		if got, _ := repo.ListByUser(ctx, r, u); len(got) != 0 {
			return fmt.Errorf("after clear = %+v", got)
		}
		return nil
	})
	// lookup はユーザーの組の中で一意。
	err := s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return tx.RecoveryCodes().Replace(ctx, r, u, []port.RecoveryCode{newRecoveryCode(r, u, "CCCC"), newRecoveryCode(r, u, "CCCC")})
	})
	if !errors.Is(err, errs.Conflict) {
		t.Fatalf("duplicate lookup = %v", err)
	}
}

func testRecoveryCodeUseConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	c := newRecoveryCode(id.New(id.Realm), id.New(id.User), "AAAA")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		return tx.RecoveryCodes().Replace(ctx, c.RealmID, c.UserID, []port.RecoveryCode{c})
	})
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			ok, err := tx.RecoveryCodes().MarkUsed(ctx, c.RealmID, c.ID, T0)
			if err == nil && !ok {
				return errs.New(errs.KindConflict, "already used")
			}
			return err
		})
	}))
}

var recoveryCodeIsolationCase = IsolationCase{
	Name: "RecoveryCodes.ListByUser",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		return tx.RecoveryCodes().Replace(ctx, r, isoUser, []port.RecoveryCode{newRecoveryCode(r, isoUser, "AAAA")})
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		return count(tx.RecoveryCodes().ListByUser(ctx, r, isoUser))
	},
}
