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

// Workload Identity Federation の発行者と結び付け（ADR 0116）の契約。

func testWorkloadIdentity(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	prov := func(realm, issuer string, at time.Time) port.WorkloadIdentityProvider {
		return port.WorkloadIdentityProvider{ID: id.NewExternal(id.WorkloadIdentityProvider), RealmID: realm, Issuer: issuer, Name: "P " + issuer,
			Config: []byte(`{"audiences":["iam"]}`), CreatedAt: at, UpdatedAt: at}
	}
	a, b := prov(r, "https://b.example", T0.Add(time.Second)), prov(r, "https://a.example", T0)
	o := prov(other, "https://a.example", T0)
	sa := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: r, Name: "ci", CreatedAt: T0}
	bind := func(p port.WorkloadIdentityProvider, at time.Time) port.WorkloadIdentityBinding {
		return port.WorkloadIdentityBinding{ID: id.NewExternal(id.WorkloadIdentityBinding), RealmID: p.RealmID, ProviderID: p.ID,
			ServiceAccountID: sa.ID, Conditions: []byte(`[{"claim":"/sub","equals":"x"}]`), CreatedAt: at}
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.WorkloadIdentity()
		for _, x := range []port.WorkloadIdentityProvider{a, b, o} {
			if err := w.CreateProvider(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.Issuer, err)
			}
		}
		if err := conflict("same issuer", w.CreateProvider(ctx, prov(r, "https://a.example", T0))); err != nil {
			return err
		}
		dup := prov(r, "https://c.example", T0)
		dup.ID = a.ID
		if err := conflict("same id", w.CreateProvider(ctx, dup)); err != nil {
			return err
		}
		got, err := w.GetProvider(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("get other realm", second(w.GetProvider(ctx, other, a.ID))); err != nil {
			return err
		}
		got, err = w.GetProviderByIssuer(ctx, r, "https://a.example")
		if err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("by issuer = %+v, %v", got, err)
		}
		for _, iss := range []string{"https://a.example/", "HTTPS://A.EXAMPLE", "https://a.exampl"} {
			if err := notFound("by issuer "+iss, second(w.GetProviderByIssuer(ctx, r, iss))); err != nil {
				return err
			}
		}
		list, err := w.ListProviders(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.WorkloadIdentityProvider{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		// 置き換え。作成時刻は変えない。issuer の重複は errs.Conflict。
		up := a
		up.Issuer, up.Name, up.Config, up.Disabled = "https://b2.example", "B2", []byte(`{}`), true
		up.UpdatedAt, up.CreatedAt = T0.Add(time.Hour), T0.Add(2*time.Hour)
		if err := w.UpdateProvider(ctx, up); err != nil {
			return err
		}
		up.CreatedAt = a.CreatedAt
		if got, err := w.GetProvider(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v, %v", got, err)
		}
		clash := up
		clash.Issuer = "https://a.example"
		if err := conflict("update to existing issuer", w.UpdateProvider(ctx, clash)); err != nil {
			return err
		}
		missing := up
		missing.ID = id.NewExternal(id.WorkloadIdentityProvider)
		if err := notFound("update missing", w.UpdateProvider(ctx, missing)); err != nil {
			return err
		}

		// 結び付け。
		if err := tx.ServiceAccounts().Create(ctx, sa); err != nil {
			return err
		}
		b1, b2, bb := bind(a, T0.Add(time.Second)), bind(a, T0), bind(b, T0)
		for _, x := range []port.WorkloadIdentityBinding{b1, b2, bb} {
			if err := w.CreateBinding(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("same binding id", w.CreateBinding(ctx, b1)); err != nil {
			return err
		}
		if got, err := w.GetBinding(ctx, r, b1.ID); err != nil || !reflect.DeepEqual(got, b1) {
			return fmt.Errorf("get binding = %+v, %v", got, err)
		}
		if err := notFound("binding other realm", second(w.GetBinding(ctx, other, b1.ID))); err != nil {
			return err
		}
		bs, err := w.ListBindings(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(bs, []port.WorkloadIdentityBinding{b2, b1}) {
			return fmt.Errorf("bindings = %+v, %v", bs, err)
		}
		if bs, err := w.ListBindings(ctx, other, a.ID); err != nil || len(bs) != 0 {
			return fmt.Errorf("bindings other realm = %+v, %v", bs, err)
		}
		if err := w.DeleteBinding(ctx, r, b2.ID); err != nil {
			return err
		}
		if err := notFound("delete binding twice", w.DeleteBinding(ctx, r, b2.ID)); err != nil {
			return err
		}
		// 発行者を消すと結び付けも消える。
		if err := w.DeleteProvider(ctx, r, b.ID); err != nil {
			return err
		}
		if err := notFound("binding of deleted provider", second(w.GetBinding(ctx, r, bb.ID))); err != nil {
			return err
		}
		if err := notFound("delete provider twice", w.DeleteProvider(ctx, r, b.ID)); err != nil {
			return err
		}
		if err := notFound("delete provider other realm", w.DeleteProvider(ctx, other, a.ID)); err != nil {
			return err
		}

		// 結び付けで発行したトークンは片付けの対象。ほかの認証情報のトークンは残す。
		mk := func(cred string) port.ServiceAccountToken {
			return port.ServiceAccountToken{ID: id.NewExternal(id.SAToken), RealmID: r, ServiceAccountID: sa.ID, CredentialID: cred,
				Hash: []byte{1}, CreatedAt: T0, ExpiresAt: T0.Add(time.Hour)}
		}
		wt, kept := mk(b1.ID), mk(id.NewExternal(id.SACredential))
		for _, x := range []port.ServiceAccountToken{wt, kept} {
			if err := tx.ServiceAccounts().CreateToken(ctx, x); err != nil {
				return err
			}
		}
		// 残り：トークン 1（wt）、結び付け 1（b1）、発行者 2（a、o）。
		if n, err := w.Count(ctx); err != nil || n != 4 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if n, err := w.Purge(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("purge = %d, %v", n, err)
		}
		if err := notFound("purged token", second(tx.ServiceAccounts().GetToken(ctx, r, wt.ID))); err != nil {
			return err
		}
		if n, err := w.Purge(ctx, 10); err != nil || n != 2 {
			return fmt.Errorf("purge rest = %d, %v", n, err)
		}
		if n, err := w.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		if _, err := tx.ServiceAccounts().GetToken(ctx, r, kept.ID); err != nil {
			return fmt.Errorf("other token: %w", err)
		}
		return nil
	})
}
