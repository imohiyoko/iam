package storagetest

import (
	"context"
	"fmt"
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
	{"OrgList", testOrgList},
}

func testFeatureDataCountPurge(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		for _, r := range []string{r1, r2, r2} {
			if err := tx.Passwords().Create(ctx, newPassword(r, id.New(id.User))); err != nil {
				return err
			}
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
		if n, err := tx.Passwords().Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("passwords.Count = %d, %v", n, err)
		}
		if n, err := tx.QuotaGrants().Count(ctx); err != nil || n != 3 {
			return fmt.Errorf("quotaGrants.Count = %d, %v", n, err)
		}
		if n, err := tx.Passwords().Purge(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("passwords.Purge(2) = %d, %v", n, err)
		}
		if n, err := tx.QuotaGrants().Purge(ctx, 2); err != nil || n != 2 {
			return fmt.Errorf("quotaGrants.Purge(2) = %d, %v", n, err)
		}
		if n, err := tx.Passwords().Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("passwords.Purge = %d, %v", n, err)
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
		if n, err := tx.Passwords().Count(ctx); err != nil || n != 0 {
			return fmt.Errorf("passwords.Count after purge = %d, %v", n, err)
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
