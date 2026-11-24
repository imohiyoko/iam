package sessionbinding

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
)

// mem は期限を見ない EphemeralStore のテスト用の実装（authn/ からは adapters/ を import しない）。
type mem struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *mem) Get(_ context.Context, k string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *mem) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}
func (s *mem) Delete(_ context.Context, k string) error                   { delete(s.m, k); return nil }
func (s *mem) Take(context.Context, string) ([]byte, bool, error)         { return nil, false, nil }
func (s *mem) Incr(context.Context, string, time.Duration) (int64, error) { return 0, nil }
func (s *mem) Shared() bool                                               { return false }

func newGuard(t *testing.T) (*Guard, *clock.Fake, *mem) {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC))
	st := &mem{m: map[string][]byte{}}
	rules := map[Signal]Rule{}
	for _, s := range Signals {
		rules[s] = Rule{Enabled: true, Score: 50, Actions: []Action{ActionRisk}}
	}
	return &Guard{Cache: st, Clock: clk, Config: Config{Window: 10 * time.Minute, MaxNetworks: 3, Rules: rules, TTL: time.Hour}}, clk, st
}

func signals(xs []Anomaly) []Signal {
	var out []Signal
	for _, x := range xs {
		out = append(out, x.Signal)
	}
	return out
}

func TestUAFamily(t *testing.T) {
	a := uaFamily("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.6778.86 Safari/537.36")
	b := uaFamily("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/132.0.6834.110 Safari/537.36")
	c := uaFamily("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0")
	if a != b || a == c {
		t.Fatalf("families: %q %q %q", a, b, c)
	}
}

// IPv6 は /64 で数える。同じ /64 の中の変化（プライバシー拡張のアドレス）は数えない。
func TestIPv6Prefix(t *testing.T) {
	g, _, _ := newGuard(t)
	ctx := context.Background()
	for _, ip := range []string{"2001:db8:1:1::1", "2001:db8:1:1::2", "2001:db8:1:1:aaaa::9", "2001:db8:1:2::1"} {
		found, err := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: ip, UserAgent: "ua"})
		if err != nil || len(found) != 0 {
			t.Fatalf("%s: %v %v", ip, signals(found), err)
		}
	}
	found, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "2001:db8:1:3::1", UserAgent: "ua"})
	if len(found) != 1 || found[0].Signal != SignalFlapping {
		t.Fatalf("third /64: %v", signals(found))
	}
}

// Bearer（別のドメインのアプリ）の要求は端末の Cookie を比べない。止めた兆候は返さない。Unreport でもう一度見つける。
func TestBearerDisabledUnreport(t *testing.T) {
	g, _, _ := newGuard(t)
	ctx := context.Background()
	if found, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "a", Device: "d1", ViaCookie: true}); len(found) != 0 {
		t.Fatalf("first: %v", signals(found))
	}
	if found, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "a"}); len(found) != 0 {
		t.Fatalf("bearer: %v", signals(found))
	}
	r := g.Config.Rules[SignalUserAgent]
	r.Enabled = false
	g.Config.Rules[SignalUserAgent] = r
	found, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "b", Device: "d2", ViaCookie: true})
	if len(found) != 1 || found[0].Signal != SignalDevice {
		t.Fatalf("device: %v", signals(found))
	}
	if again, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "b", Device: "d2", ViaCookie: true}); len(again) != 0 {
		t.Fatalf("reported twice: %v", signals(again))
	}
	g.Unreport(ctx, "r", "s", found)
	if again, _ := g.Observe(ctx, Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "b", Device: "d2", ViaCookie: true}); len(again) != 1 {
		t.Fatalf("after unreport: %v", signals(again))
	}
}

// 同じネットワークに居続けるあいだは、window の 1/4 ごとにしか書かない。
func TestFewWrites(t *testing.T) {
	g, clk, st := newGuard(t)
	ctx := context.Background()
	in := Request{RealmID: "r", SID: "s", IP: "192.0.2.1", UserAgent: "a"}
	_, _ = g.Observe(ctx, in)
	first := string(st.m[key("r", "s")])
	clk.Advance(time.Minute)
	_, _ = g.Observe(ctx, in)
	if string(st.m[key("r", "s")]) != first {
		t.Fatal("wrote within window/4")
	}
	clk.Advance(2 * time.Minute)
	_, _ = g.Observe(ctx, in)
	if string(st.m[key("r", "s")]) == first {
		t.Fatal("did not refresh after window/4")
	}
}
