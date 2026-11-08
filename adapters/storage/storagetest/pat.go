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

// 本人の Personal Access Token と realm のポリシー（ADR 0109）の契約。

func newPAT(realmID, userID string, at time.Time) port.PersonalAccessToken {
	return port.PersonalAccessToken{ID: id.NewExternal(id.PAT), RealmID: realmID, UserID: userID, Name: "ci", Scopes: []string{"docs.doc:read", "users:read"},
		Hash: []byte("hash-of-secret"), CreatedAt: at}
}

func testPersonalAccessTokens(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u, other := id.New(id.Realm), id.New(id.User), id.New(id.User)
	exp := T0.Add(30 * 24 * time.Hour)
	a, b := newPAT(r, u, T0), newPAT(r, u, T0.Add(time.Second))
	a.ExpiresAt = &exp
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.PersonalAccessTokens()
		for _, p := range []port.PersonalAccessToken{a, b, newPAT(r, other, T0), newPAT(id.New(id.Realm), u, T0)} {
			if err := repo.Create(ctx, p); err != nil {
				return err
			}
		}
		if err := conflict("same id", repo.Create(ctx, a)); err != nil {
			return err
		}
		got, err := repo.Get(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("pats.Get = %+v, %v; want %+v", got, err, a)
		}
		list, err := repo.ListByUser(ctx, r, u)
		if err != nil || len(list) != 2 || !reflect.DeepEqual(list[0], a) || !reflect.DeepEqual(list[1], b) {
			return fmt.Errorf("pats.ListByUser = %+v, %v", list, err)
		}
		used := T0.Add(time.Hour)
		if err := repo.Touch(ctx, r, a.ID, used); err != nil {
			return err
		}
		if got, _ = repo.Get(ctx, r, a.ID); got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
			return fmt.Errorf("after Touch = %+v", got.LastUsedAt)
		}
		at := T0.Add(2 * time.Hour)
		if ok, err := repo.Revoke(ctx, r, a.ID, at, "user"); err != nil || !ok {
			return fmt.Errorf("pats.Revoke = %v, %v", ok, err)
		}
		// 2回目は false で、最初の時刻と理由が残る。
		if ok, err := repo.Revoke(ctx, r, a.ID, at.Add(time.Hour), "operator"); err != nil || ok {
			return fmt.Errorf("pats.Revoke again = %v, %v", ok, err)
		}
		if got, _ = repo.Get(ctx, r, a.ID); got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.RevokeReason != "user" {
			return fmt.Errorf("after Revoke = %+v %q", got.RevokedAt, got.RevokeReason)
		}
		otherRealm := id.New(id.Realm)
		for name, err := range map[string]error{
			"get in another realm":   func() error { _, err := repo.Get(ctx, otherRealm, b.ID); return err }(),
			"touch in another realm": repo.Touch(ctx, otherRealm, b.ID, used),
			"revoke in another realm": func() error {
				_, err := repo.Revoke(ctx, otherRealm, b.ID, at, "x")
				return err
			}(),
			"get missing":    func() error { _, err := repo.Get(ctx, r, id.NewExternal(id.PAT)); return err }(),
			"touch missing":  repo.Touch(ctx, r, id.NewExternal(id.PAT), used),
			"revoke missing": func() error { _, err := repo.Revoke(ctx, r, id.NewExternal(id.PAT), at, "x"); return err }(),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		if got, _ = repo.Get(ctx, r, b.ID); got.RevokedAt != nil || got.LastUsedAt != nil {
			return fmt.Errorf("b changed by another realm: %+v", got)
		}
		// RevokeByUser は取り消していないもの（b）だけを数える。
		if n, err := repo.RevokeByUser(ctx, r, u, at, "revoke_all"); err != nil || n != 1 {
			return fmt.Errorf("pats.RevokeByUser = %d, %v", n, err)
		}
		if got, _ = repo.Get(ctx, r, b.ID); got.RevokedAt == nil || got.RevokeReason != "revoke_all" {
			return fmt.Errorf("b after RevokeByUser = %+v", got)
		}
		if got, _ = repo.Get(ctx, r, a.ID); got.RevokeReason != "user" {
			return fmt.Errorf("a after RevokeByUser = %q", got.RevokeReason)
		}
		if n, err := repo.DeleteByUser(ctx, r, u); err != nil || n != 2 {
			return fmt.Errorf("pats.DeleteByUser = %d, %v", n, err)
		}
		if n, err := count(repo.ListByUser(ctx, r, other)); err != nil || n != 1 {
			return fmt.Errorf("other user's tokens = %d, %v", n, err)
		}
		return nil
	})
}

func testPersonalAccessTokenPolicies(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, r2 := id.New(id.Realm), id.New(id.Realm)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.PersonalAccessTokens()
		if _, err := repo.GetPolicy(ctx, r); notFound("missing policy", err) != nil {
			return notFound("missing policy", err)
		}
		p := port.PersonalAccessTokenPolicy{RealmID: r, MaxLifetimeSeconds: 86400, AllowedScopes: []string{"docs.doc:*"}, RequireExpiry: true, UpdatedAt: T0}
		if err := repo.PutPolicy(ctx, p); err != nil {
			return err
		}
		if got, err := repo.GetPolicy(ctx, r); err != nil || !reflect.DeepEqual(got, p) {
			return fmt.Errorf("GetPolicy = %+v, %v", got, err)
		}
		// 置き換え。空のスコープは nil で返る。
		p2 := port.PersonalAccessTokenPolicy{RealmID: r, UpdatedAt: T0.Add(time.Hour)}
		if err := repo.PutPolicy(ctx, p2); err != nil {
			return err
		}
		if got, err := repo.GetPolicy(ctx, r); err != nil || !reflect.DeepEqual(got, p2) {
			return fmt.Errorf("GetPolicy after replace = %+v, %v", got, err)
		}
		if _, err := repo.GetPolicy(ctx, r2); notFound("policy of another realm", err) != nil {
			return notFound("policy of another realm", err)
		}
		// 数え上げと片付けは全 realm のトークンとポリシー。
		for _, x := range []port.PersonalAccessToken{newPAT(r, id.New(id.User), T0), newPAT(r2, id.New(id.User), T0)} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := repo.PutPolicy(ctx, port.PersonalAccessTokenPolicy{RealmID: r2, UpdatedAt: T0}); err != nil {
			return err
		}
		if n, err := repo.Count(ctx); err != nil || n != 4 {
			return fmt.Errorf("pats.Count = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 3); err != nil || n != 3 {
			return fmt.Errorf("pats.Purge(3) = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("pats.Purge = %d, %v", n, err)
		}
		if n, err := repo.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("pats.Count after purge = %d, %v", n, err)
		}
		return nil
	})
}

const isoPAT = "pat_00000000000000000000000009"

var patIsolationCase = IsolationCase{
	Name: "PersonalAccessTokens.Get+ListByUser+Touch+Revoke",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		p := newPAT(r, isoUser, T0)
		p.ID = isoPAT
		if err := tx.PersonalAccessTokens().Create(ctx, p); err != nil {
			return err
		}
		return tx.PersonalAccessTokens().PutPolicy(ctx, port.PersonalAccessTokenPolicy{RealmID: r, UpdatedAt: T0})
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		repo := tx.PersonalAccessTokens()
		n, err := count(repo.ListByUser(ctx, r, isoUser))
		if err != nil {
			return 0, err
		}
		if _, err := repo.Get(ctx, r, isoPAT); err == nil {
			n++
		}
		if repo.Touch(ctx, r, isoPAT, T0) == nil {
			n++
		}
		if ok, err := repo.Revoke(ctx, r, isoPAT, T0, "x"); err == nil || ok {
			n++
		}
		if _, err := repo.GetPolicy(ctx, r); err == nil {
			n++
		}
		return n, nil
	},
}
