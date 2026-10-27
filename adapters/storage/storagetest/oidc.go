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

func testGrants(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	u := newUser(r)
	c := port.Client{ID: id.New(id.Client), PublicID: id.NewExternal(id.Client), RealmID: r, Name: "A", TrustLevel: port.TrustFirstParty,
		RedirectURIs: []string{"https://a.example.com/cb"}, PostLogoutRedirectURIs: []string{}, AuthMethod: port.ClientAuthNone,
		IDTokenAlg: port.AlgES256, CreatedAt: T0, UpdatedAt: T0}
	sid := id.NewExternal(id.Session)
	mk := func(at time.Time) port.Grant {
		return port.Grant{ID: id.New(id.Grant), RealmID: r, ClientID: c.ID, UserID: u.ID, OrgID: "org_1", SID: sid,
			Scopes: []string{"openid", "email"}, AuthMethods: []string{"pwd"}, AuthTime: T0.Add(-time.Minute), CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
	}
	g1, g2 := mk(T0.Add(time.Second)), mk(T0)
	tok := func(g port.Grant, kind string) port.OIDCToken {
		return port.OIDCToken{ID: id.NewExternal(id.AccessToken), RealmID: r, GrantID: g.ID, Kind: kind, Hash: []byte{7}, CreatedAt: T0,
			ExpiresAt: T0.Add(time.Minute)}
	}
	t1, t2 := tok(g1, port.TokenAccess), tok(g2, port.TokenRefresh)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		if err := tx.Clients().Create(ctx, c); err != nil {
			return err
		}
		repo, toks := tx.Grants(), tx.OIDCTokens()
		for _, g := range []port.Grant{g1, g2} {
			if err := repo.Create(ctx, g); err != nil {
				return err
			}
		}
		if err := conflict("same grant", repo.Create(ctx, g1)); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, g1.ID); err != nil || !reflect.DeepEqual(got, g1) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("other realm", func() error { _, err := repo.Get(ctx, other, g1.ID); return err }()); err != nil {
			return err
		}
		list, err := repo.ListBySID(ctx, r, sid)
		if err != nil || len(list) != 2 || list[0].ID != g2.ID {
			return fmt.Errorf("ListBySID = %+v, %v", list, err)
		}
		// 失効の時刻は早まるだけ。
		if err := repo.Revoke(ctx, r, g1.ID, T0.Add(time.Hour), "logout"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r, g1.ID, T0.Add(2*time.Hour), "later"); err != nil {
			return err
		}
		if got, _ := repo.Get(ctx, r, g1.ID); got.RevokedAt == nil || !got.RevokedAt.Equal(T0.Add(time.Hour)) || got.RevokeReason != "logout" {
			return fmt.Errorf("after Revoke = %+v", got)
		}
		if err := notFound("revoke missing", repo.Revoke(ctx, r, id.New(id.Grant), T0, "x")); err != nil {
			return err
		}

		for _, x := range []port.OIDCToken{t1, t2} {
			if err := toks.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("same token", toks.Create(ctx, t1)); err != nil {
			return err
		}
		if got, err := toks.Get(ctx, r, t2.ID); err != nil || !reflect.DeepEqual(got, t2) {
			return fmt.Errorf("token get = %+v, %v", got, err)
		}
		if err := notFound("token other realm", func() error { _, err := toks.Get(ctx, other, t1.ID); return err }()); err != nil {
			return err
		}
		if ok, err := toks.Use(ctx, r, t2.ID, T0.Add(time.Second)); err != nil || !ok {
			return fmt.Errorf("first Use = %v, %v", ok, err)
		}
		if ok, err := toks.Use(ctx, r, t2.ID, T0.Add(2*time.Second)); err != nil || ok {
			return fmt.Errorf("second Use = %v, %v", ok, err)
		}
		if got, _ := toks.Get(ctx, r, t2.ID); got.UsedAt == nil || !got.UsedAt.Equal(T0.Add(time.Second)) {
			return fmt.Errorf("UsedAt = %v", got.UsedAt)
		}
		if err := notFound("use missing", func() error { _, err := toks.Use(ctx, r, "atk_missing", T0); return err }()); err != nil {
			return err
		}
		return nil
	})

	// 連携先を消すと認可とトークンも消える。ユーザーの消去でも同じ。
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Clients().Delete(ctx, r, c.ID); err != nil {
			return err
		}
		if err := notFound("grant after client delete", func() error { _, err := tx.Grants().Get(ctx, r, g1.ID); return err }()); err != nil {
			return err
		}
		if err := notFound("token after client delete", func() error { _, err := tx.OIDCTokens().Get(ctx, r, t1.ID); return err }()); err != nil {
			return err
		}
		g3 := mk(T0)
		t3 := tok(g3, port.TokenAccess)
		if err := tx.Grants().Create(ctx, g3); err != nil {
			return err
		}
		if err := tx.OIDCTokens().Create(ctx, t3); err != nil {
			return err
		}
		if err := tx.Users().Erase(ctx, r, u.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if err := notFound("grant after erase", func() error { _, err := tx.Grants().Get(ctx, r, g3.ID); return err }()); err != nil {
			return err
		}
		return notFound("token after erase", func() error { _, err := tx.OIDCTokens().Get(ctx, r, t3.ID); return err }())
	})
}

func testSessionLineage(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	u := newUser(r)
	first := newSession(r, u.ID, T0)
	second := newSession(r, u.ID, T0.Add(time.Minute))
	second.SID = first.SID
	unrelated := newSession(r, u.ID, T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		for _, x := range []port.Session{first, second, unrelated} {
			if err := tx.Sessions().Create(ctx, x); err != nil {
				return err
			}
		}
		if got, err := tx.Sessions().GetCurrentBySID(ctx, r, first.SID); err != nil || got.ID != second.ID || got.SID != first.SID {
			return fmt.Errorf("GetCurrentBySID = %+v, %v", got, err)
		}
		if err := notFound("other realm", func() error { _, err := tx.Sessions().GetCurrentBySID(ctx, id.New(id.Realm), first.SID); return err }()); err != nil {
			return err
		}
		return notFound("missing", func() error { _, err := tx.Sessions().GetCurrentBySID(ctx, r, "ses_missing"); return err }())
	})
}
