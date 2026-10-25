// Package testkit はコア（authn、authz）のテストで使う、インメモリの参照実装の組み合わせ（design.md 12章）。
//
// コアの本体はアダプタを import しない（archtest）。テストだけがこのパッケージを通して参照実装を使う。
package testkit

import (
	"context"
	"testing"
	"time"

	ephemeral "github.com/imohiyoko/iam/adapters/ephemeral/memory"
	"github.com/imohiyoko/iam/adapters/keystore/file"
	storage "github.com/imohiyoko/iam/adapters/storage/memory"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// T0 はテストの開始時刻。
var T0 = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

// Kit はテスト用の依存一式。
type Kit struct {
	Storage *storage.Storage
	Cache   *ephemeral.Store
	Keys    port.KeyStore
	Crypter *pii.Crypter
	Clock   *clock.Fake
	RealmID string
}

// New は空の Kit を返す。realm を1つ作る。
func New(t testing.TB) *Kit {
	t.Helper()
	clk := clock.NewFake(T0)
	keys, err := file.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := file.FromKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	k := &Kit{Storage: storage.New(clk), Cache: ephemeral.New(clk), Keys: ks, Crypter: pii.New(ks), Clock: clk}
	r := port.Realm{ID: id.New(id.Realm), Slug: "test", Settings: []byte(`{}`), CreatedAt: T0}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Realms().Create(ctx, r) })
	k.RealmID = r.ID
	return k
}

// Tx は fn を1つのトランザクションで実行し、失敗したらテストを止める。
func (k *Kit) Tx(t testing.TB, fn func(context.Context, port.Tx) error) {
	t.Helper()
	if err := k.Storage.Tx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// SeedUser は有効なユーザー（とデータ鍵）を直接作る。登録の流れを通さないテスト用。
func (k *Kit) SeedUser(t testing.TB) port.User {
	t.Helper()
	u := port.User{ID: id.New(id.User), RealmID: k.RealmID, Status: port.UserActive, CreatedAt: k.Clock.Now(), UpdatedAt: k.Clock.Now()}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		return k.Crypter.CreateDataKey(ctx, tx.DataKeys(), u.ID, k.Clock.Now())
	})
	return u
}
