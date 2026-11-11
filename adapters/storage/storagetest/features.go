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

// フィーチャーの無効化（design.md 11.12）で使う、データの数え上げと片付けの契約。

var featureDataTests = []struct {
	name string
	fn   func(*testing.T, Harness)
}{
	{"FeatureDataCountPurge", testFeatureDataCountPurge},
	{"ExchangedGrantsCountPurge", testExchangedGrantsCountPurge},
	{"OfflineGrants", testOfflineGrants},
	{"OrgList", testOrgList},
	{"SenderConstrainedTokens", testSenderConstrainedTokens},
}

func testFeatureDataCountPurge(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, r := range []string{r1, r2, r2} {
			o := newOrg(r, port.OrgShared, "")
			if err := tx.Orgs().Create(ctx, o); err != nil {
				return err
			}
			if err := tx.QuotaGrants().Create(ctx, newQuotaGrant(r, o.ID, port.QuotaBase, 5)); err != nil {
				return err
			}
			if err := tx.OrgDomains().Create(ctx, newOrgDomain(r, o.ID, "example.com")); err != nil {
				return err
			}
		}
		return nil
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if n, err := tx.QuotaGrants().Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("quotaGrants.Count = %d, %v", n, err)
		}
		if n, err := tx.QuotaGrants().Purge(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("quotaGrants.Purge(2) = %d, %v", n, err)
		}
		if n, err := tx.QuotaGrants().Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("quotaGrants.Purge = %d, %v", n, err)
		}
		if n, err := tx.OrgDomains().Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("orgDomains.Count = %d, %v", n, err)
		}
		if n, err := tx.OrgDomains().Purge(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("orgDomains.Purge(2) = %d, %v", n, err)
		}
		if n, err := tx.OrgDomains().Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("orgDomains.Purge = %d, %v", n, err)
		}
		if n, err := tx.OrgDomains().Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("orgDomains.Count after purge = %d, %v", n, err)
		}
		if n, err := tx.QuotaGrants().Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("quotaGrants.Count after purge = %d, %v", n, err)
		}
		return nil
	})
}

func testOrgList(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	var ids []string
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for range 3 {
			o := newOrg(r, port.OrgShared, "")
			ids = append(ids, o.ID)
			if err := tx.Orgs().Create(ctx, o); err != nil {
				return err
			}
		}
		return tx.Orgs().Create(ctx, newOrg(id.New(id.Realm), port.OrgShared, ""))
	})
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		first, err := tx.Orgs().List(ctx, r, "", 2)
		if err != nil || len(first) != 2 || first[0].ID >= first[1].ID {
			return fmt.Errorf("orgs.List = %+v, %v", first, err)
		}
		rest, err := tx.Orgs().List(ctx, r, first[1].ID, 2)
		if err != nil || len(rest) != 1 || rest[0].ID <= first[1].ID {
			return fmt.Errorf("orgs.List after = %+v, %v", rest, err)
		}
		return nil
	})
}

// testExchangedGrantsCountPurge は交換の認可の数え上げと片付け（フィーチャー token_exchange・impersonation。ADR 0099）。
func testExchangedGrantsCountPurge(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	mk := func(r, exchange string) (port.Grant, port.OIDCToken) {
		g := port.Grant{ID: id.New(id.Grant), RealmID: r, ClientID: id.New(id.Client), UserID: id.New(id.User), SID: "ses_x", Scopes: []string{"openid"},
			AuthMethods: []string{"pwd"}, AuthTime: T0, CreatedAt: T0, ExpiresAt: T0.Add(time.Hour), Exchange: exchange}
		return g, port.OIDCToken{ID: id.NewExternal(id.AccessToken), RealmID: r, GrantID: g.ID, Kind: port.TokenAccess, Hash: []byte{1},
			CreatedAt: T0, ExpiresAt: T0.Add(time.Minute)}
	}
	var plain port.Grant
	var plainTok, firstTok port.OIDCToken
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for i, c := range []struct{ r, ex string }{{r1, port.ExchangeDelegation}, {r2, port.ExchangeDelegation}, {r2, port.ExchangeDelegation},
			{r1, port.ExchangeImpersonation}, {r1, ""}} {
			g, tok := mk(c.r, c.ex)
			if c.ex == "" {
				plain, plainTok = g, tok
			}
			if i == 0 {
				firstTok = tok
			}
			if err := tx.Grants().Create(ctx, g); err != nil {
				return err
			}
			if err := tx.OIDCTokens().Create(ctx, tok); err != nil {
				return err
			}
		}
		if n, err := tx.Grants().CountExchanged(ctx, port.ExchangeDelegation); err != nil || n != 3 {
			return fmt.Errorf("count delegation = %d, %v", n, err)
		}
		if n, err := tx.Grants().CountExchanged(ctx, port.ExchangeImpersonation); err != nil || n != 1 {
			return fmt.Errorf("count impersonation = %d, %v", n, err)
		}
		if n, err := tx.Grants().PurgeExchanged(ctx, port.ExchangeDelegation, 2); err != nil || n != 2 {
			return fmt.Errorf("purge 2 = %d, %v", n, err)
		}
		if n, err := tx.Grants().PurgeExchanged(ctx, port.ExchangeDelegation, 10); err != nil || n != 1 {
			return fmt.Errorf("purge rest = %d, %v", n, err)
		}
		if n, err := tx.Grants().CountExchanged(ctx, port.ExchangeDelegation); err != nil || n != 0 {
			return fmt.Errorf("count after purge = %d, %v", n, err)
		}
		if err := notFound("token of purged grant", func() error { _, err := tx.OIDCTokens().Get(ctx, r1, firstTok.ID); return err }()); err != nil {
			return err
		}
		if n, err := tx.Grants().CountExchanged(ctx, port.ExchangeImpersonation); err != nil || n != 1 {
			return fmt.Errorf("impersonation kept = %d, %v", n, err)
		}
		if _, err := tx.Grants().Get(ctx, r1, plain.ID); err != nil {
			return fmt.Errorf("plain grant: %w", err)
		}
		_, err := tx.OIDCTokens().Get(ctx, r1, plainTok.ID)
		return err
	})
}

// testOfflineGrants は Offline の認可（offline_access。ADR 0126）の保存・本人ごとの一覧・数え上げと片付け。
func testOfflineGrants(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	alice, bob := id.New(id.User), id.New(id.User)
	mk := func(user string, offline bool, at time.Time) (port.Grant, port.OIDCToken) {
		g := port.Grant{ID: id.New(id.Grant), RealmID: r, ClientID: id.New(id.Client), UserID: user, SID: "ses_x", Scopes: []string{"openid", "offline_access"},
			AuthMethods: []string{"pwd"}, AuthTime: at, CreatedAt: at, ExpiresAt: at.Add(time.Hour), Offline: offline}
		if offline {
			g.AuthCredentialIDs = []string{"crd_1", "crd_2"}
		}
		return g, port.OIDCToken{ID: id.NewExternal(id.RefreshToken), RealmID: r, GrantID: g.ID, Kind: port.TokenRefresh, Hash: []byte{1},
			CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
	}
	a2, a2t := mk(alice, true, T0.Add(time.Second))
	a1, a1t := mk(alice, true, T0)
	a3, a3t := mk(alice, false, T0)
	b1, b1t := mk(bob, true, T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, p := range []struct {
			g   port.Grant
			tok port.OIDCToken
		}{{a2, a2t}, {a1, a1t}, {a3, a3t}, {b1, b1t}} {
			if err := tx.Grants().Create(ctx, p.g); err != nil {
				return err
			}
			if err := tx.OIDCTokens().Create(ctx, p.tok); err != nil {
				return err
			}
		}
		if got, err := tx.Grants().Get(ctx, r, a1.ID); err != nil || !got.Offline || !reflect.DeepEqual(got.AuthCredentialIDs, a1.AuthCredentialIDs) {
			return fmt.Errorf("get offline = %+v, %v", got, err)
		}
		if got, err := tx.Grants().Get(ctx, r, a3.ID); err != nil || got.Offline || len(got.AuthCredentialIDs) != 0 {
			return fmt.Errorf("get plain = %+v, %v", got, err)
		}
		list, err := tx.Grants().ListOfflineByUser(ctx, r, alice)
		if err != nil || len(list) != 2 || list[0].ID != a1.ID || list[1].ID != a2.ID {
			return fmt.Errorf("ListOfflineByUser = %+v, %v", list, err)
		}
		if n, err := tx.Grants().CountOffline(ctx); err != nil || n != 3 {
			return fmt.Errorf("CountOffline = %d, %v", n, err)
		}
		if n, err := tx.Grants().PurgeOffline(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("PurgeOffline 2 = %d, %v", n, err)
		}
		if n, err := tx.Grants().PurgeOffline(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("PurgeOffline rest = %d, %v", n, err)
		}
		if n, err := tx.Grants().CountOffline(ctx); err != nil || n != 0 {
			return fmt.Errorf("CountOffline after purge = %d, %v", n, err)
		}
		if err := notFound("token of purged grant", func() error { _, err := tx.OIDCTokens().Get(ctx, r, a1t.ID); return err }()); err != nil {
			return err
		}
		if _, err := tx.Grants().Get(ctx, r, a3.ID); err != nil {
			return fmt.Errorf("plain grant: %w", err)
		}
		_, err = tx.OIDCTokens().Get(ctx, r, a3t.ID)
		return err
	})
}
