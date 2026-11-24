package sessionbinding

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ユーザーが普段使う接続元の一覧（ADR 0128）。
//
// ログインの系列が新しいネットワークから使われるたび（ログインの後の最初の要求を含む）に、接続元の CIDR（IPv4 は /24、
// IPv6 は /64）・ASN・国と、そこで使ったブラウザの種類を数える。ユーザーごとに 1 行で、ユーザーのデータ鍵で暗号化して置く
// （ユーザーを消せば読めなくなる）。一覧が育ったら（profile.min_observations）、一覧に無いネットワーク・ブラウザの種類を
// 兆候 unfamiliar_network・unfamiliar_browser にする。

// ProfileConfig は一覧の設定。
type ProfileConfig struct {
	// Enabled が偽なら一覧を作らない（unfamiliar_* も見ない）。
	Enabled bool
	// MinObservations は一覧の回数の合計がこれに届いてから unfamiliar_* を見る（育つ前は何でも知らないものになる）。
	MinObservations int
	// MaxNetworks はユーザーごとに覚えるネットワークの数。超えれば最後に見た時刻の古いものから捨てる。
	MaxNetworks int
	// MaxBrowsers はネットワークごとに覚えるブラウザの種類の数。
	MaxBrowsers int
	// Retention はこれより長く見ていないネットワーク・ブラウザを捨てる。
	Retention time.Duration
}

// Visit は系列が新しいネットワークから使われたこと（Observe が返し、Learn に渡す）。
type Visit struct {
	// Network は接続元の CIDR（IPv4 は /24、IPv6 は /64）。
	Network string
	ASN     uint32
	Country string
	// Family は User-Agent の種類（版の数字を除いたもの）、UserAgent はそのままの値。
	Family    string
	UserAgent string
	// Reported は Observe のときに系列で知らせ済みだった兆候。
	Reported []Signal
}

// Profile は一覧（暗号化して置く中身）。
type Profile struct {
	Networks []Network `json:"networks"`
}

// Network は覚えたネットワーク。
type Network struct {
	CIDR      string    `json:"cidr"`
	ASN       uint32    `json:"asn,omitempty"`
	Country   string    `json:"country,omitempty"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Browsers  []Browser `json:"browsers"`
}

// Browser はネットワークで使われたブラウザの種類。
type Browser struct {
	Family string `json:"family"`
	// UserAgent は最後に見た User-Agent。
	UserAgent string    `json:"user_agent"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Observations は一覧の回数の合計。
func (p Profile) Observations() int {
	n := 0
	for _, x := range p.Networks {
		n += x.Count
	}
	return n
}

func (p Profile) knowsNetwork(v Visit) bool {
	return slices.ContainsFunc(p.Networks, func(n Network) bool { return n.CIDR == v.Network || (v.ASN != 0 && n.ASN == v.ASN) })
}

func (p Profile) knowsBrowser(family string) bool {
	return slices.ContainsFunc(p.Networks, func(n Network) bool {
		return slices.ContainsFunc(n.Browsers, func(b Browser) bool { return b.Family == family })
	})
}

// cidr は接続元のネットワークの CIDR（IPv4 は /24、IPv6 は /64）。
func cidr(ip netip.Addr) string {
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

func profileAAD(userID string) string { return "authn.network_profile." + userID }

// ProfilesEnabled は普段の接続元の一覧を作るか。
func (g *Guard) ProfilesEnabled() bool { return g.Crypter != nil && g.Config.Profile.Enabled }

// Established は一覧が育ったか（unfamiliar_* を見るか）。
func (g *Guard) Established(p Profile) bool {
	return p.Observations() >= max(g.Config.Profile.MinObservations, 1)
}

// LoadProfile はユーザーの一覧を返す（無ければ空。retention より長く見ていないものは除く）。
func (g *Guard) LoadProfile(ctx context.Context, tx port.Tx, realmID, userID string) (Profile, error) {
	row, err := tx.NetworkProfiles().Get(ctx, realmID, userID)
	if errors.Is(err, errs.NotFound) {
		return Profile{}, nil
	}
	if err != nil {
		return Profile{}, err
	}
	pt, err := g.Crypter.Decrypt(ctx, tx.DataKeys(), userID, row.Data, profileAAD(userID))
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(pt, &p); err != nil {
		return Profile{}, err
	}
	p.prune(g.Clock.Now(), g.Config.Profile.Retention)
	return p, nil
}

// Learn は v を一覧と比べて兆候を返し、一覧に足す。呼び出し側のトランザクション（兆候の記録と同じ）で呼ぶ。
func (g *Guard) Learn(ctx context.Context, tx port.Tx, realmID, userID string, v Visit) ([]Anomaly, error) {
	if !g.ProfilesEnabled() {
		return nil, nil
	}
	p, err := g.LoadProfile(ctx, tx, realmID, userID)
	if err != nil {
		return nil, err
	}
	now := g.Clock.Now()
	pc := g.Config.Profile

	var found []Anomaly
	if n := p.Observations(); g.Established(p) {
		report := func(s Signal, details map[string]any) {
			if r, ok := g.Config.Rules[s]; ok && r.Enabled && !slices.Contains(v.Reported, s) {
				found = append(found, Anomaly{Signal: s, Score: r.Score, Actions: slices.Clone(r.Actions), Details: details})
			}
		}
		if !p.knowsNetwork(v) {
			d := map[string]any{"network": v.Network, "known_networks": len(p.Networks), "observations": n}
			if v.ASN != 0 {
				d["asn"] = v.ASN
			}
			if v.Country != "" {
				d["country"] = v.Country
			}
			report(SignalUnfamiliarNetwork, d)
		}
		if !p.knowsBrowser(v.Family) {
			report(SignalUnfamiliarBrowser, map[string]any{"network": v.Network, "observations": n})
		}
	}

	p.add(v, now, pc)
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	ct, err := g.Crypter.Encrypt(ctx, tx.DataKeys(), userID, b, profileAAD(userID))
	if err != nil {
		return nil, err
	}
	if err := tx.NetworkProfiles().Put(ctx, port.NetworkProfile{RealmID: realmID, UserID: userID, Data: ct, UpdatedAt: now}); err != nil {
		return nil, err
	}
	return found, nil
}

// prune は retention より長く見ていないネットワーク・ブラウザを捨てる。
func (p *Profile) prune(now time.Time, retention time.Duration) {
	if retention <= 0 {
		return
	}
	old := func(t time.Time) bool { return now.Sub(t) > retention }
	p.Networks = slices.DeleteFunc(p.Networks, func(n Network) bool { return old(n.LastSeen) })
	for i := range p.Networks {
		p.Networks[i].Browsers = slices.DeleteFunc(p.Networks[i].Browsers, func(b Browser) bool { return old(b.LastSeen) })
	}
}

// add は v を数える。数の上限を超えれば、最後に見た時刻の古いものから捨てる（今回のものは残る）。
func (p *Profile) add(v Visit, now time.Time, pc ProfileConfig) {
	i := slices.IndexFunc(p.Networks, func(n Network) bool { return n.CIDR == v.Network })
	if i < 0 {
		p.Networks = append(p.Networks, Network{CIDR: v.Network, FirstSeen: now, Browsers: []Browser{}})
		i = len(p.Networks) - 1
	}
	n := &p.Networks[i]
	n.Count++
	n.LastSeen = now
	if v.ASN != 0 {
		n.ASN = v.ASN
	}
	if v.Country != "" {
		n.Country = v.Country
	}
	j := slices.IndexFunc(n.Browsers, func(b Browser) bool { return b.Family == v.Family })
	if j < 0 {
		n.Browsers = append(n.Browsers, Browser{Family: v.Family, FirstSeen: now})
		j = len(n.Browsers) - 1
	}
	n.Browsers[j].Count++
	n.Browsers[j].LastSeen = now
	n.Browsers[j].UserAgent = v.UserAgent
	n.Browsers = newest(n.Browsers, pc.MaxBrowsers, func(b Browser) time.Time { return b.LastSeen })
	p.Networks = newest(p.Networks, pc.MaxNetworks, func(n Network) time.Time { return n.LastSeen })
}

// newest は最後に見た時刻の新しい順に並べ、limit 件まで残す（limit が 0 以下なら捨てない）。
func newest[T any](xs []T, limit int, at func(T) time.Time) []T {
	slices.SortStableFunc(xs, func(a, b T) int { return cmp.Compare(at(b).UnixNano(), at(a).UnixNano()) })
	if limit > 0 && len(xs) > limit {
		xs = xs[:limit]
	}
	return xs
}
