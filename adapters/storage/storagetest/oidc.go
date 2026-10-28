package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// OIDC Provider の契約（design.md 3.1、5.5、9.3）。

func testClients(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	mk := func(name string, at time.Time) port.Client {
		return port.Client{ID: id.New(id.Client), PublicID: id.NewExternal(id.Client), RealmID: r, Name: name, TrustLevel: port.TrustFirstParty,
			RedirectURIs: []string{"https://app.example.com/cb", "https://app.example.com/cb2"}, PostLogoutRedirectURIs: []string{},
			AuthMethod: port.ClientAuthSecret, SecretHash: []byte{1, 2, 3}, IDTokenAlg: port.AlgMLDSA65, CreatedAt: at, UpdatedAt: at}
	}
	a, b := mk("A", T0.Add(time.Second)), mk("B", T0)
	b.AuthMethod, b.SecretHash, b.JWKS, b.IDTokenAlg = port.ClientAuthPrivateKeyJWT, nil, []byte(`{"keys":[]}`), port.AlgES256
	b.PostLogoutRedirectURIs, b.BackchannelLogoutURI = []string{"https://b.example.com/"}, "https://b.example.com/bcl"
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Clients()
		for _, c := range []port.Client{a, b} {
			if err := repo.Create(ctx, c); err != nil {
				return err
			}
		}
		dup := mk("C", T0)
		dup.PublicID = a.PublicID
		if err := conflict("same client_id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if got, err := repo.GetByPublicID(ctx, r, b.PublicID); err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("GetByPublicID = %+v, %v", got, err)
		}
		if err := notFound("other realm", func() error { _, err := repo.Get(ctx, other, a.ID); return err }()); err != nil {
			return err
		}
		list, err := repo.List(ctx, r)
		if err != nil || len(list) != 2 || list[0].ID != b.ID {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		a.Name, a.RedirectURIs, a.SecretHash, a.UpdatedAt = "A2", []string{"https://x.example.com/"}, []byte{9}, T0.Add(time.Hour)
		if err := repo.Update(ctx, a); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("after Update = %+v, %v", got, err)
		}
		if err := repo.Delete(ctx, r, a.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", repo.Delete(ctx, r, a.ID)); err != nil {
			return err
		}
		ghost := mk("ghost", T0)
		return notFound("update missing", repo.Update(ctx, ghost))
	})
}

func testSigningKeys(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	k1 := port.SigningKey{ID: id.NewExternal(id.SigningKey), RealmID: r, Alg: port.AlgES256, Public: []byte{1}, Private: []byte{2}, CreatedAt: T0}
	k2 := port.SigningKey{ID: id.NewExternal(id.SigningKey), RealmID: r, Alg: port.AlgMLDSA65, Public: []byte{3}, Private: []byte{4}, CreatedAt: T0.Add(time.Second)}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.SigningKeys()
		for _, k := range []port.SigningKey{k2, k1} {
			if err := repo.Create(ctx, k); err != nil {
				return err
			}
		}
		if err := conflict("same kid", repo.Create(ctx, k1)); err != nil {
			return err
		}
		if err := repo.Retire(ctx, r, k1.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		list, err := repo.List(ctx, r)
		if err != nil || len(list) != 2 || list[0].ID != k1.ID || list[0].RetiredAt == nil || !list[0].RetiredAt.Equal(T0.Add(time.Hour)) ||
			!reflect.DeepEqual(list[1], k2) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		if other, err := repo.List(ctx, id.New(id.Realm)); err != nil || len(other) != 0 {
			return fmt.Errorf("other realm = %+v, %v", other, err)
		}
		if err := repo.Delete(ctx, r, k1.ID); err != nil {
			return err
		}
		if err := notFound("retire missing", repo.Retire(ctx, r, k1.ID, T0)); err != nil {
			return err
		}
		return notFound("delete missing", repo.Delete(ctx, r, k1.ID))
	})
}
