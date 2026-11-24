package sessionbinding

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/pii"
)

func TestProfileAddAndLimits(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pc := ProfileConfig{MaxNetworks: 2, MaxBrowsers: 2, Retention: 24 * time.Hour}
	var p Profile
	v := func(net string, asn uint32, fam string) Visit {
		return Visit{Network: net, ASN: asn, Country: "JP", Family: fam, UserAgent: fam + "/1"}
	}
	p.add(v("192.0.2.0/24", 64500, "a"), t0, pc)
	p.add(v("192.0.2.0/24", 64500, "a"), t0.Add(time.Minute), pc)
	if len(p.Networks) != 1 || p.Networks[0].Count != 2 || p.Networks[0].Browsers[0].Count != 2 || p.Observations() != 2 {
		t.Fatalf("after 2 visits = %+v", p)
	}
	// 同じ ASN の別の CIDR は、知っているネットワーク（モバイル回線の IP の変化）。
	if !p.knowsNetwork(v("198.51.100.0/24", 64500, "a")) || p.knowsNetwork(v("198.51.100.0/24", 64501, "a")) || p.knowsNetwork(v("198.51.100.0/24", 0, "a")) {
		t.Fatal("knowsNetwork")
	}
	if !p.knowsBrowser("a") || p.knowsBrowser("b") {
		t.Fatal("knowsBrowser")
	}
	// ブラウザの数の上限（最後に見た時刻の古いものから捨てる）。
	p.add(v("192.0.2.0/24", 64500, "b"), t0.Add(2*time.Minute), pc)
	p.add(v("192.0.2.0/24", 64500, "c"), t0.Add(3*time.Minute), pc)
	if bs := p.Networks[0].Browsers; len(bs) != 2 || bs[0].Family != "c" || bs[1].Family != "b" {
		t.Fatalf("browsers = %+v", bs)
	}
	// ネットワークの数の上限。
	p.add(v("198.51.100.0/24", 64501, "a"), t0.Add(4*time.Minute), pc)
	p.add(v("203.0.113.0/24", 64502, "a"), t0.Add(5*time.Minute), pc)
	if len(p.Networks) != 2 || p.Networks[0].CIDR != "203.0.113.0/24" || p.Networks[1].CIDR != "198.51.100.0/24" {
		t.Fatalf("networks = %+v", p.Networks)
	}
	// 古いものを捨てる。
	p.add(v("192.0.2.0/24", 0, "a"), t0.Add(30*time.Hour), pc)
	p.prune(t0.Add(30*time.Hour), pc.Retention)
	if len(p.Networks) != 1 || p.Networks[0].CIDR != "192.0.2.0/24" || p.Networks[0].ASN != 0 {
		t.Fatalf("after prune = %+v", p.Networks)
	}
}

func TestCIDR(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.77": "192.0.2.0/24", "2001:db8:1:2:3::9": "2001:db8:1:2::/64"} {
		if got := cidr(netip.MustParseAddr(in)); got != want {
			t.Errorf("cidr(%s) = %s, want %s", in, got, want)
		}
	}
}

// 一覧に足せる（Confirm）まで、同じネットワークからの要求でも Visit を返す（記録のトランザクションが失敗したときの再試行）。
func TestVisitPendingUntilConfirmed(t *testing.T) {
	g, clk, _ := newGuard(t)
	g.Crypter, g.Config.Profile = &pii.Crypter{}, ProfileConfig{Enabled: true}
	ctx := context.Background()
	in := Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "a"}
	first, _ := g.Observe(ctx, in)
	clk.Advance(time.Second)
	again, _ := g.Observe(ctx, in)
	if first.Visit == nil || again.Visit == nil || again.Visit.Network != "192.0.2.0/24" {
		t.Fatalf("visits before confirm: %+v %+v", first.Visit, again.Visit)
	}
	g.Confirm(ctx, "r", "s", nil, again.Visit)
	if after, _ := g.Observe(ctx, in); after.Visit != nil {
		t.Fatalf("visit after confirm: %+v", after.Visit)
	}
	// 別のネットワークに移れば、また Visit を返す。足せないまま（B）さらに移り（C を足し）、B に戻っても比べ直す。
	b := Request{RealmID: "r", SID: "s", IP: "198.51.100.1", UserAgent: "a"}
	if moved, _ := g.Observe(ctx, b); moved.Visit == nil {
		t.Fatal("no visit after moving")
	}
	c, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "203.0.113.1", UserAgent: "a"})
	g.Confirm(ctx, "r", "s", nil, c.Visit)
	if back, _ := g.Observe(ctx, b); back.Visit == nil || back.Visit.Network != "198.51.100.0/24" {
		t.Fatalf("no visit back on the pending network: %+v", back.Visit)
	}
	// 比べられなかった（Confirm に nil）なら、まだ返す。
	g.Confirm(ctx, "r", "s", nil, nil)
	if again, _ := g.Observe(ctx, b); again.Visit == nil {
		t.Fatal("visit dropped without learning")
	}
	// 一覧を作らない設定なら返さない。
	g.Config.Profile.Enabled = false
	if off, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s2", IP: "192.0.2.1", UserAgent: "a"}); off.Visit != nil {
		t.Fatal("visit with profiles off")
	}
}
