package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID4VCI の資格情報の定義と発行の記録（ADR 0119）の契約。

func testVCI(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	cfg := func(realm, cid, scope string, at time.Time) port.VCICredentialConfiguration {
		return port.VCICredentialConfiguration{ID: id.NewExternal(id.VCIConfiguration), RealmID: realm, ConfigurationID: cid, Scope: scope,
			Config: []byte(`{"vct":"urn:example:` + cid + `"}`), CreatedAt: at, UpdatedAt: at}
	}
	a, b := cfg(r, "employee", "vc_employee", T0.Add(time.Second)), cfg(r, "member", "", T0)
	o := cfg(other, "member", "", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.VCI()
		for _, x := range []port.VCICredentialConfiguration{a, b, o} {
			if err := w.CreateConfiguration(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.ConfigurationID, err)
			}
		}
		if err := conflict("same configuration id", w.CreateConfiguration(ctx, cfg(r, "member", "", T0))); err != nil {
			return err
		}
		dup := cfg(r, "x", "", T0)
		dup.ID = a.ID
		if err := conflict("same id", w.CreateConfiguration(ctx, dup)); err != nil {
			return err
		}
		got, err := w.GetConfiguration(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("get other realm", second(w.GetConfiguration(ctx, other, a.ID))); err != nil {
			return err
		}
		got, err = w.GetConfigurationByConfigurationID(ctx, r, "member")
		if err != nil || !reflect.DeepEqual(got, b) {
			return fmt.Errorf("by configuration id = %+v, %v", got, err)
		}
		if err := notFound("by configuration id case", second(w.GetConfigurationByConfigurationID(ctx, r, "Member"))); err != nil {
			return err
		}
		list, err := w.ListConfigurations(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.VCICredentialConfiguration{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		up := a
		up.ConfigurationID, up.Scope, up.Config = "employee2", "", []byte(`{}`)
		up.UpdatedAt, up.CreatedAt = T0.Add(time.Hour), T0.Add(2*time.Hour)
		if err := w.UpdateConfiguration(ctx, up); err != nil {
			return err
		}
		up.CreatedAt = a.CreatedAt
		if got, err := w.GetConfiguration(ctx, r, a.ID); err != nil || !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v, %v", got, err)
		}
		clash := up
		clash.ConfigurationID = "member"
		if err := conflict("update to an existing configuration id", w.UpdateConfiguration(ctx, clash)); err != nil {
			return err
		}
		missing := up
		missing.ID = id.NewExternal(id.VCIConfiguration)
		if err := notFound("update missing", w.UpdateConfiguration(ctx, missing)); err != nil {
			return err
		}
		if err := notFound("delete other realm", w.DeleteConfiguration(ctx, other, a.ID)); err != nil {
			return err
		}
		if err := w.DeleteConfiguration(ctx, r, a.ID); err != nil {
			return err
		}
		return notFound("delete twice", w.DeleteConfiguration(ctx, r, a.ID))
	})

	user, user2 := id.New(id.User), id.New(id.User)
	cred := func(realm, userID string, idx int, issued, expires time.Time) port.VCIIssuedCredential {
		return port.VCIIssuedCredential{ID: id.NewExternal(id.VCICredential), RealmID: realm, UserID: userID, ConfigurationID: "member",
			StatusIndex: idx, HolderJKT: "jkt-" + fmt.Sprint(idx), IssuedAt: issued, ExpiresAt: expires}
	}
	c1 := cred(r, user, 7, T0, T0.Add(24*time.Hour))
	c2 := cred(r, user, 99, T0.Add(time.Minute), T0.Add(48*time.Hour))
	c3 := cred(r, user2, 3, T0, T0.Add(time.Hour)) // 先に期限が来る
	c4 := cred(other, user, 7, T0, T0.Add(24*time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.VCI()
		for _, x := range []port.VCIIssuedCredential{c1, c2, c3, c4} {
			if err := w.CreateCredential(ctx, x); err != nil {
				return fmt.Errorf("create credential %d: %w", x.StatusIndex, err)
			}
		}
		if err := conflict("same status index", w.CreateCredential(ctx, cred(r, user2, 7, T0, T0.Add(time.Hour)))); err != nil {
			return err
		}
		got, err := w.GetCredential(ctx, r, c1.ID)
		if err != nil || !reflect.DeepEqual(got, c1) {
			return fmt.Errorf("get credential = %+v, %v", got, err)
		}
		if err := notFound("get credential other realm", second(w.GetCredential(ctx, other, c1.ID))); err != nil {
			return err
		}
		list, err := w.ListCredentialsByUser(ctx, r, user)
		if err != nil || !reflect.DeepEqual(list, []port.VCIIssuedCredential{c2, c1}) {
			return fmt.Errorf("list by user = %+v, %v", list, err)
		}
		// 失効は1回目の時刻を残す。
		if err := w.RevokeCredential(ctx, r, c1.ID, T0.Add(time.Hour)); err != nil {
			return err
		}
		if err := w.RevokeCredential(ctx, r, c1.ID, T0.Add(2*time.Hour)); err != nil {
			return err
		}
		if got, _ := w.GetCredential(ctx, r, c1.ID); got.RevokedAt == nil || !got.RevokedAt.Equal(T0.Add(time.Hour)) {
			return fmt.Errorf("revoked_at = %v", got.RevokedAt)
		}
		if err := notFound("revoke missing", w.RevokeCredential(ctx, r, id.NewExternal(id.VCICredential), T0)); err != nil {
			return err
		}
		if err := notFound("revoke other realm", w.RevokeCredential(ctx, other, c2.ID, T0)); err != nil {
			return err
		}
		// 本人の分をまとめて失効。失効済みの時刻は変えず、他の本人・realm は触らない。
		if err := w.RevokeCredentialsByUser(ctx, r, user, T0.Add(3*time.Hour)); err != nil {
			return err
		}
		if got, _ := w.GetCredential(ctx, r, c1.ID); !got.RevokedAt.Equal(T0.Add(time.Hour)) {
			return fmt.Errorf("revoke by user changed revoked_at: %v", got.RevokedAt)
		}
		if got, _ := w.GetCredential(ctx, r, c2.ID); got.RevokedAt == nil || !got.RevokedAt.Equal(T0.Add(3*time.Hour)) {
			return fmt.Errorf("revoke by user: %v", got.RevokedAt)
		}
		if got, _ := w.GetCredential(ctx, other, c4.ID); got.RevokedAt != nil {
			return fmt.Errorf("revoke by user touched other realm")
		}
		if err := w.RevokeCredential(ctx, r, c3.ID, T0); err != nil {
			return err
		}
		// 失効させていて期限内のもの。c3 は期限切れ（T0+1h）なので出ない。
		idx, err := w.ListRevokedIndexes(ctx, r, T0.Add(2*time.Hour))
		slices.Sort(idx)
		if err != nil || !reflect.DeepEqual(idx, []int{7, 99}) {
			return fmt.Errorf("revoked indexes = %v, %v", idx, err)
		}
		if idx, err := w.ListRevokedIndexes(ctx, other, T0); err != nil || len(idx) != 0 {
			return fmt.Errorf("revoked indexes other realm = %v, %v", idx, err)
		}
		// 期限切れの記録を消す（期限ちょうどを含む）。
		n, err := w.DeleteExpiredCredentials(ctx, r, T0.Add(24*time.Hour), 10)
		if err != nil || n != 2 {
			return fmt.Errorf("delete expired = %d, %v", n, err)
		}
		if err := notFound("expired deleted", second(w.GetCredential(ctx, r, c3.ID))); err != nil {
			return err
		}
		if _, err := w.GetCredential(ctx, other, c4.ID); err != nil {
			return fmt.Errorf("delete expired touched other realm: %w", err)
		}
		return nil
	})

	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.VCI()
		n, err := w.Count(ctx)
		if err != nil || n != 4 { // 定義 2（b、o）と記録 2（c2、c4）
			return fmt.Errorf("count = %d, %v", n, err)
		}
		got, err := w.Purge(ctx, 3)
		if err != nil || got != 3 {
			return fmt.Errorf("purge = %d, %v", got, err)
		}
		got, err = w.Purge(ctx, 10)
		if err != nil || got != 1 {
			return fmt.Errorf("purge rest = %d, %v", got, err)
		}
		n, err = w.Count(ctx)
		if err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		return nil
	})
}
