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

// 本人がログインした端末（authn_known_devices。ADR 0105）の契約。

func newKnownDevice(realmID, userID, lookup string) port.KnownDevice {
	return port.KnownDevice{ID: id.New(id.KnownDevice), PublicID: id.NewExternal(id.KnownDevice), RealmID: realmID, UserID: userID,
		Lookup: []byte(lookup), Data: []byte("device-ct"), CreatedAt: T0, LastSeenAt: T0}
}

func testKnownDevices(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, other := id.New(id.Realm), id.New(id.User), id.New(id.User)
	a, b := newKnownDevice(r, u, "browser-1"), newKnownDevice(r, u, "browser-2")
	b.CreatedAt, b.LastSeenAt = T0.Add(time.Second), T0.Add(time.Second)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.KnownDevices()
		for _, d := range []port.KnownDevice{a, b} {
			if err := repo.Create(ctx, d); err != nil {
				return err
			}
		}
		// 検索キーはユーザーごとに一意。同じブラウザ（同じ検索キー）をほかのユーザー・ほかの realm が使える。
		if err := conflict("same lookup for user", repo.Create(ctx, newKnownDevice(r, u, "browser-1"))); err != nil {
			return err
		}
		dup := newKnownDevice(r, other, "x")
		dup.PublicID = a.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		for _, d := range []port.KnownDevice{newKnownDevice(r, other, "browser-1"), newKnownDevice(id.New(id.Realm), u, "browser-1")} {
			if err := repo.Create(ctx, d); err != nil {
				return fmt.Errorf("create shared browser: %w", err)
			}
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil || len(list) != 2 || !reflect.DeepEqual(list[0], a) || !reflect.DeepEqual(list[1], b) {
			return fmt.Errorf("devices.ListByUser = %+v, %v", list, err)
		}
		at := T0.Add(time.Hour)
		if err := repo.Seen(ctx, r, a.ID, []byte("data-2"), at); err != nil {
			return err
		}
		if list, _ = repo.ListByUser(ctx, r, u); string(list[0].Data) != "data-2" || !list[0].LastSeenAt.Equal(at) || !list[0].CreatedAt.Equal(T0) {
			return fmt.Errorf("after Seen = %+v", list[0])
		}
		other := id.New(id.Realm)
		for name, err := range map[string]error{
			"seen in another realm":   repo.Seen(ctx, other, a.ID, []byte("x"), at),
			"delete in another realm": repo.Delete(ctx, other, a.ID),
			"seen missing":            repo.Seen(ctx, r, id.New(id.KnownDevice), []byte("x"), at),
			"delete missing":          repo.Delete(ctx, r, id.New(id.KnownDevice)),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		if err := repo.Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if n, err := count(repo.ListByUser(ctx, r, u)); err != nil || n != 1 {
			return fmt.Errorf("after delete = %d, %v", n, err)
		}
		// 消した後は同じ検索キーで作り直せる。
		if err := repo.Create(ctx, newKnownDevice(r, u, "browser-1")); err != nil {
			return fmt.Errorf("re-create after delete: %w", err)
		}
		if n, err := repo.DeleteByUser(ctx, r, u); err != nil || n != 2 {
			return fmt.Errorf("devices.DeleteByUser = %d, %v", n, err)
		}
		if n, err := count(repo.ListByUser(ctx, r, other)); err != nil || n != 0 {
			return fmt.Errorf("list in another realm = %d, %v", n, err)
		}
		// 数え上げと片付けは全 realm（フィーチャーの無効化）。残りは other の 1 件と別の realm の 1 件。
		if n, err := repo.Count(ctx); err != nil || n != 2 {
			return fmt.Errorf("devices.Count = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 1); err != nil || n != 1 {
			return fmt.Errorf("devices.Purge(1) = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("devices.Purge = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("devices.Count after purge = %d, %v", n, err)
		}
		return nil
	})
}

// testKnownDeviceLookupConcurrent は同じユーザーの同じ検索キーを同時に作っても1つしか通らないことを確かめる。
func testKnownDeviceLookupConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			return tx.KnownDevices().Create(ctx, newKnownDevice(r, u, "same"))
		})
	}))
}

const isoKnownDevice = "dev_00000000000000000000000009"

var knownDeviceIsolationCase = IsolationCase{
	Name: "KnownDevices.ListByUser+Seen",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		d := newKnownDevice(r, isoUser, "iso")
		d.ID, d.PublicID = isoKnownDevice, isoKnownDevice
		return tx.KnownDevices().Create(ctx, d)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		n, err := count(tx.KnownDevices().ListByUser(ctx, r, isoUser))
		if err != nil {
			return 0, err
		}
		if tx.KnownDevices().Seen(ctx, r, isoKnownDevice, []byte("x"), T0) == nil {
			n++
		}
		return n, nil
	},
}
