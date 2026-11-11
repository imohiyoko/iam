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

// WS-Federation の RP と署名の証明書（ADR 0110）の契約。

func testWSFed(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	rp := func(realm, wtrealm string, at time.Time) port.WSFedRelyingParty {
		return port.WSFedRelyingParty{ID: id.NewExternal(id.WSFedRelyingParty), RealmID: realm, Realm: wtrealm, Name: "App " + wtrealm,
			ReplyURLs: []string{"https://app.example/" + wtrealm, "https://app.example/b"}, TokenType: "saml11",
			Claims:        []byte(`[{"source":"email","type":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}]`),
			TokenLifetime: 3600, SigningAlg: port.AlgES256, CreatedAt: at, UpdatedAt: at}
	}
	a, b := rp(r, "urn:b", T0.Add(time.Second)), rp(r, "urn:a", T0)
	o := rp(other, "urn:a", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.WSFed()
		for _, x := range []port.WSFedRelyingParty{a, b, o} {
			if err := w.CreateRelyingParty(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.Realm, err)
			}
		}
		if err := conflict("same wtrealm", w.CreateRelyingParty(ctx, rp(r, "urn:a", T0))); err != nil {
			return err
		}
		dup := rp(r, "urn:c", T0)
		dup.ID = a.ID
		if err := conflict("same id", w.CreateRelyingParty(ctx, dup)); err != nil {
			return err
		}
		got, err := w.GetRelyingParty(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("get other realm", second(w.GetRelyingParty(ctx, other, a.ID))); err != nil {
			return err
		}
		got, err = w.GetRelyingPartyByRealm(ctx, r, "urn:a")
		if err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("by realm = %+v, %v", got, err)
		}
		if err := notFound("by realm prefix", second(w.GetRelyingPartyByRealm(ctx, r, "urn:"))); err != nil {
			return err
		}
		list, err := w.ListRelyingParties(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.WSFedRelyingParty{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		// 置き換え。作成時刻は変えない。wtrealm の重複は errs.Conflict。
		up := a
		up.Realm, up.Name, up.ReplyURLs, up.TokenType, up.Claims, up.TokenLifetime = "urn:b2", "B2", []string{"https://b2.example/"}, "saml20", []byte(`[]`), 600
		up.SigningAlg = port.AlgRS256
		up.UpdatedAt, up.CreatedAt = T0.Add(time.Hour), T0.Add(2*time.Hour)
		if err := w.UpdateRelyingParty(ctx, up); err != nil {
			return err
		}
		up.CreatedAt = a.CreatedAt
		if got, err := w.GetRelyingParty(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v, %v", got, err)
		}
		clash := up
		clash.Realm = "urn:a"
		if err := conflict("update to existing wtrealm", w.UpdateRelyingParty(ctx, clash)); err != nil {
			return err
		}
		missing := up
		missing.ID = id.NewExternal(id.WSFedRelyingParty)
		if err := notFound("update missing", w.UpdateRelyingParty(ctx, missing)); err != nil {
			return err
		}
		if err := w.DeleteRelyingParty(ctx, r, b.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", w.DeleteRelyingParty(ctx, r, b.ID)); err != nil {
			return err
		}
		if err := notFound("delete other realm", w.DeleteRelyingParty(ctx, other, a.ID)); err != nil {
			return err
		}

		// 証明書。
		c1 := port.WSFedCertificate{RealmID: r, KeyID: "k2", DER: []byte{1, 2, 3}, CreatedAt: T0}
		c2 := port.WSFedCertificate{RealmID: r, KeyID: "k1", DER: []byte{4}, CreatedAt: T0.Add(time.Second)}
		c3 := port.WSFedCertificate{RealmID: other, KeyID: "k1", DER: []byte{5}, CreatedAt: T0}
		for _, c := range []port.WSFedCertificate{c1, c2, c3} {
			if err := w.CreateCertificate(ctx, c); err != nil {
				return err
			}
		}
		if err := conflict("same key", w.CreateCertificate(ctx, c1)); err != nil {
			return err
		}
		cs, err := w.ListCertificates(ctx, r)
		if err != nil || !reflect.DeepEqual(cs, []port.WSFedCertificate{c2, c1}) {
			return fmt.Errorf("certificates = %+v, %v", cs, err)
		}
		if err := w.DeleteCertificate(ctx, r, "k2"); err != nil {
			return err
		}
		if err := notFound("delete certificate twice", w.DeleteCertificate(ctx, r, "k2")); err != nil {
			return err
		}
		// 残り：RP 2（a、o）と証明書 2（c2、c3）。
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
