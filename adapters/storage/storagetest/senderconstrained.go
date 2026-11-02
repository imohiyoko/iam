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

// 送信者制約トークン（DPoP・mTLS。ADR 0113）の契約：連携先の設定と、トークンの結び付けの往復、結び付けたトークンの数え上げと片付け。

func testSenderConstrainedTokens(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2 := id.New(id.Realm), id.New(id.Realm)
	c := port.Client{ID: id.New(id.Client), PublicID: id.NewExternal(id.Client), RealmID: r1, Name: "mtls", TrustLevel: port.TrustFirstParty,
		RedirectURIs: []string{"https://a.example.com/cb"}, PostLogoutRedirectURIs: []string{}, AuthMethod: port.ClientAuthTLS,
		IDTokenAlg: port.AlgES256, DPoPBoundAccessTokens: true, TLSBoundAccessTokens: true, TLSAuthField: port.TLSAuthSubjectDN,
		TLSAuthValue: "CN=client,O=Example", CreatedAt: T0, UpdatedAt: T0}
	tok := func(r, jkt, x5t string) port.OIDCToken {
		return port.OIDCToken{ID: id.NewExternal(id.AccessToken), RealmID: r, GrantID: "grt_x", Kind: port.TokenAccess, Hash: []byte{7},
			CreatedAt: T0, ExpiresAt: T0.Add(time.Minute), JKT: jkt, X5T: x5t}
	}
	dpop1, dpop2, both, mtls, plain := tok(r1, "jkt-a", ""), tok(r2, "jkt-b", ""), tok(r1, "jkt-c", "x5t-c"), tok(r2, "", "x5t-d"), tok(r1, "", "")
	sat := func(jkt string) port.ServiceAccountToken {
		return port.ServiceAccountToken{ID: id.New(id.SAToken), RealmID: r1, ServiceAccountID: "sva_x", CredentialID: "sac_x", Hash: []byte("h"),
			CreatedAt: T0, ExpiresAt: T0.Add(time.Hour), JKT: jkt}
	}
	sa1, sa2, sa3 := sat("jkt-a"), sat("jkt-b"), sat("")
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Clients().Create(ctx, c); err != nil {
			return err
		}
		if got, err := tx.Clients().Get(ctx, r1, c.ID); err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("client get = %+v, %v", got, err)
		}
		c.DPoPBoundAccessTokens, c.TLSBoundAccessTokens, c.TLSAuthField, c.TLSAuthValue = false, false, port.TLSAuthSANDNS, "client.example.com"
		if err := tx.Clients().Update(ctx, c); err != nil {
			return err
		}
		if got, err := tx.Clients().Get(ctx, r1, c.ID); err != nil || !reflect.DeepEqual(got, c) {
			return fmt.Errorf("client after update = %+v, %v", got, err)
		}
		toks := tx.OIDCTokens()
		for _, x := range []port.OIDCToken{dpop1, dpop2, both, mtls, plain} {
			if err := toks.Create(ctx, x); err != nil {
				return err
			}
		}
		if got, err := toks.Get(ctx, r1, both.ID); err != nil || !reflect.DeepEqual(got, both) {
			return fmt.Errorf("token get = %+v, %v", got, err)
		}
		for _, x := range []port.ServiceAccountToken{sa1, sa2, sa3} {
			if err := tx.ServiceAccounts().CreateToken(ctx, x); err != nil {
				return err
			}
		}
		if got, err := tx.ServiceAccounts().GetToken(ctx, r1, sa1.ID); err != nil || got.JKT != "jkt-a" {
			return fmt.Errorf("sa token get = %+v, %v", got, err)
		}
		return nil
	})
	count := func(binding string) int {
		var n int
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			var err error
			n, err = tx.OIDCTokens().CountBound(ctx, binding)
			return err
		})
		return n
	}
	purge := func(binding string, limit int) int {
		var n int
		tx(t, s, func(ctx context.Context, tx port.Tx) error {
			var err error
			n, err = tx.OIDCTokens().PurgeBound(ctx, binding, limit)
			return err
		})
		return n
	}
	if d, m, x := count(port.BindingDPoP), count(port.BindingMTLS), count("other"); d != 3 || m != 2 || x != 0 {
		t.Fatalf("CountBound = %d, %d, %d", d, m, x)
	}
	if n := purge(port.BindingDPoP, 2); n != 2 {
		t.Fatalf("PurgeBound dpop (limit 2) = %d", n)
	}
	if n := purge(port.BindingDPoP, 10); n != 1 {
		t.Fatalf("PurgeBound dpop = %d", n)
	}
	if d, m := count(port.BindingDPoP), count(port.BindingMTLS); d != 0 || m != 1 {
		// both は DPoP の片付けで消える（同じトークン）。
		t.Fatalf("after dpop purge = %d, %d", d, m)
	}
	if n := purge(port.BindingMTLS, 10); n != 1 || count(port.BindingMTLS) != 0 {
		t.Fatalf("PurgeBound mtls = %d", n)
	}
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		// 結び付けの無いトークンは残る。
		if _, err := tx.OIDCTokens().Get(ctx, r1, plain.ID); err != nil {
			return err
		}
		sa := tx.ServiceAccounts()
		if n, err := sa.CountBoundTokens(ctx); err != nil || n != 2 {
			return fmt.Errorf("CountBoundTokens = %d, %v", n, err)
		}
		if n, err := sa.PurgeBoundTokens(ctx, 1); err != nil || n != 1 {
			return fmt.Errorf("PurgeBoundTokens = %d, %v", n, err)
		}
		if n, err := sa.PurgeBoundTokens(ctx, 5); err != nil || n != 1 {
			return fmt.Errorf("PurgeBoundTokens again = %d, %v", n, err)
		}
		if _, err := sa.GetToken(ctx, r1, sa3.ID); err != nil {
			return err
		}
		return nil
	})
}
