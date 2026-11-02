package storagetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// testCredentialDeliveryMethods は SMS・音声の OTP とプッシュの承認（ADR 0104）が汎用の認証情報に頼る契約を確かめる。
//   - sms は検索キーを持たない（同じ番号の別の人も登録できる）
//   - push は端末の ID を検索キーにし、realm と方式の中で一意。無効化した端末の ID は引けず、宛先の更新（比較と交換）も通らない
//   - フィーチャーの無効化は方式ごとに片付け、もう一方を残す
func testCredentialDeliveryMethods(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, alice, bob := id.New(id.Realm), id.New(id.User), id.New(id.User)
	device := newCredential(r, alice, "push", []byte("dev-1"))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		for _, c := range []port.Credential{newCredential(r, alice, "sms", nil), newCredential(r, bob, "sms", nil), device} {
			if err := repo.Create(ctx, c); err != nil {
				return fmt.Errorf("create %s: %w", c.Method, err)
			}
		}
		if err := conflict("same device id", repo.Create(ctx, newCredential(r, bob, "push", []byte("dev-1")))); err != nil {
			return err
		}
		got, err := repo.GetByLookup(ctx, r, "push", []byte("dev-1"))
		if err != nil || got.ID != device.ID || got.UserID != alice {
			return fmt.Errorf("device lookup = %+v, %v", got, err)
		}
		if err := repo.UpdateData(ctx, r, device.ID, device.Data, []byte("token-2"), 1); err != nil {
			return fmt.Errorf("token update: %w", err)
		}
		if err := conflict("stale token update", repo.UpdateData(ctx, r, device.ID, device.Data, []byte("token-3"), 1)); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, device.ID, T0, "user"); err != nil {
			return err
		}
		if err := notFound("revoked device", second(repo.GetByLookup(ctx, r, "push", []byte("dev-1")))); err != nil {
			return err
		}
		if err := conflict("update of revoked device", repo.UpdateData(ctx, r, device.ID, []byte("token-2"), []byte("token-4"), 1)); err != nil {
			return err
		}
		// 無効化した端末の ID は、新しい端末が使ってよい（部分一意インデックス）。
		return repo.Create(ctx, newCredential(r, bob, "push", []byte("dev-1")))
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		if n, err := repo.Purge(ctx, "push", 10); err != nil || n != 2 {
			return fmt.Errorf("purge push = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx, "sms"); err != nil || n != 2 {
			return fmt.Errorf("sms after purging push = %d, %v", n, err)
		}
		return nil
	})
}
