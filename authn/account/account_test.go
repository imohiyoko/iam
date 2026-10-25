package account_test

import (
	"context"
	"errors"
	"testing"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// countingTx はユーザーの作成を数える。
type countingTx struct {
	port.Tx
	n *int
}

func (t countingTx) Users() port.UserRepo { return countingUsers{t.Tx.Users(), t.n} }

type countingUsers struct {
	port.UserRepo
	n *int
}

func (r countingUsers) Create(ctx context.Context, u port.User) error {
	*r.n++
	return r.UserRepo.Create(ctx, u)
}

// 登録済みのアドレスでは、何も書かずに errs.Conflict を返す。呼び出し側が Conflict を受けて
// 処理を続けても、メールの無いユーザーが残らない（13.5）。
func TestCreateWithEmailConflictWritesNothing(t *testing.T) {
	k := testkit.New(t)
	s := &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: []port.VerifiedVia{port.VerifiedViaAdmin}}
	create := func(ctx context.Context, tx port.Tx, email string) error {
		_, err := s.CreateWithEmail(ctx, tx, k.RealmID, email, port.VerifiedViaAdmin, audit.Actor{Type: "test"}, "")
		return err
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return create(ctx, tx, "a@example.com") })

	var n int
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := create(ctx, countingTx{tx, &n}, "A@example.com"); !errors.Is(err, errs.Conflict) {
			t.Fatalf("got %v, want conflict", err)
		}
		return nil // 呼び出し側が続けてコミットする場合
	})
	if n != 0 {
		t.Fatalf("users created on conflict: %d", n)
	}
}
