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

// SAML の SP の登録と IdP の署名の証明書（ADR 0115）の契約。

func testSAMLIdP(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	sp := func(realm, entityID string, at time.Time) port.SAMLServiceProvider {
		return port.SAMLServiceProvider{ID: id.NewExternal(id.SAMLServiceProvider), RealmID: realm, EntityID: entityID, Name: "SP " + entityID,
			Config: []byte(`{"acs":[{"url":"https://sp.example/acs","index":0}]}`), CreatedAt: at, UpdatedAt: at}
	}
	a, b := sp(r, "urn:b", T0.Add(time.Second)), sp(r, "urn:a", T0)
	o := sp(other, "urn:a", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.SAMLIdP()
		for _, x := range []port.SAMLServiceProvider{a, b, o} {
			if err := w.CreateServiceProvider(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.EntityID, err)
			}
		}
		if err := conflict("same entity id", w.CreateServiceProvider(ctx, sp(r, "urn:a", T0))); err != nil {
			return err
		}
		dup := sp(r, "urn:c", T0)
		dup.ID = a.ID
		if err := conflict("same id", w.CreateServiceProvider(ctx, dup)); err != nil {
			return err
		}
		got, err := w.GetServiceProvider(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("get other realm", second(w.GetServiceProvider(ctx, other, a.ID))); err != nil {
			return err
		}
		got, err = w.GetServiceProviderByEntityID(ctx, r, "urn:a")
		if err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("by entity id = %+v, %v", got, err)
		}
		if err := notFound("by entity id prefix", second(w.GetServiceProviderByEntityID(ctx, r, "urn:"))); err != nil {
			return err
		}
		if err := notFound("by entity id case", second(w.GetServiceProviderByEntityID(ctx, r, "URN:A"))); err != nil {
			return err
		}
		list, err := w.ListServiceProviders(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.SAMLServiceProvider{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		// 置き換え。作成時刻は変えない。Entity ID の重複は errs.Conflict。
		up := a
		up.EntityID, up.Name, up.Config = "urn:b2", "B2", []byte(`{}`)
		up.UpdatedAt, up.CreatedAt = T0.Add(time.Hour), T0.Add(2*time.Hour)
		if err := w.UpdateServiceProvider(ctx, up); err != nil {
			return err
		}
		up.CreatedAt = a.CreatedAt
		if got, err := w.GetServiceProvider(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v, %v", got, err)
		}
		clash := up
		clash.EntityID = "urn:a"
		if err := conflict("update to existing entity id", w.UpdateServiceProvider(ctx, clash)); err != nil {
			return err
		}
		missing := up
		missing.ID = id.NewExternal(id.SAMLServiceProvider)
		if err := notFound("update missing", w.UpdateServiceProvider(ctx, missing)); err != nil {
			return err
		}
		if err := w.DeleteServiceProvider(ctx, r, b.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", w.DeleteServiceProvider(ctx, r, b.ID)); err != nil {
			return err
		}
		if err := notFound("delete other realm", w.DeleteServiceProvider(ctx, other, a.ID)); err != nil {
			return err
		}

		// 証明書。
		c1 := port.SAMLIdPCertificate{RealmID: r, KeyID: "k2", DER: []byte{1, 2, 3}, CreatedAt: T0}
		c2 := port.SAMLIdPCertificate{RealmID: r, KeyID: "k1", DER: []byte{4}, CreatedAt: T0.Add(time.Second)}
		c3 := port.SAMLIdPCertificate{RealmID: other, KeyID: "k1", DER: []byte{5}, CreatedAt: T0}
		for _, c := range []port.SAMLIdPCertificate{c1, c2, c3} {
			if err := w.CreateCertificate(ctx, c); err != nil {
				return err
			}
		}
		if err := conflict("same key", w.CreateCertificate(ctx, c1)); err != nil {
			return err
		}
		cs, err := w.ListCertificates(ctx, r)
		if err != nil || !reflect.DeepEqual(cs, []port.SAMLIdPCertificate{c2, c1}) {
			return fmt.Errorf("certificates = %+v, %v", cs, err)
		}
		if err := w.DeleteCertificate(ctx, r, "k2"); err != nil {
			return err
		}
		if err := notFound("delete certificate twice", w.DeleteCertificate(ctx, r, "k2")); err != nil {
			return err
		}
		// 残り：SP 2（a、o）と証明書 2（c2、c3）。
		if n, err := w.Count(ctx); err != nil || n != 4 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if n, err := w.Purge(ctx, 3); err != nil || n != 3 {
			return fmt.Errorf("purge = %d, %v", n, err)
		}
		if n, err := w.Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("purge rest = %d, %v", n, err)
		}
		if n, err := w.Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		return nil
	})
}
