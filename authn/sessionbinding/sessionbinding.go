// Package sessionbinding はログインの後のセッションの使われ方を見て、同じセッションが別の端末・別の接続元から使われる兆候を
// 見つける（フィーチャー session_binding。ADR 0128）。
//
// ログインのときのリスク（login_risk。ADR 0105）はログインの瞬間しか見ない。ここではセッションの検証のたびに、ログインの系列
// （sid）ごとに最初に見た端末の Cookie・User-Agent の種類・接続元を覚え、その後の要求と比べる。見つけた兆候は呼び出し側
// （server）が監査ログに残し、設定に従ってセッションのリスクを上げる・系列を失効させる・本人に知らせる。
//
// 系列の状態は EphemeralStore に置き、接続元などが変わったときだけ書く（判定のホットパスで Storage に書かない）。状態が消えれば
// （再起動など）次の要求を新しい起点として覚え直す。守りが一時的に緩むだけで、セッションは使える。
//
// あわせて、系列が新しいネットワークから使われるたびに、ユーザーが普段使う接続元の一覧（Storage。profile.go）と比べて育てる。
package sessionbinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// Feature はセッションの接続元の監視（既定オフ）。端末の Cookie は device_recognition が動いていれば使い、動いていなければ
// User-Agent と接続元だけを見る。
var Feature = feature.Feature{Name: feature.SessionBinding, DataVersion: 1}

// EventAnomaly は兆候を見つけたことの監査ログ。
const EventAnomaly = "session.anomaly_detected"

// TypeSuspiciousSession は本人への通知（ID だけ。ADR 0031）。
const TypeSuspiciousSession = "suspicious_session"

// Signal は兆候の種類。
type Signal string

const (
	// SignalDevice は Cookie のセッションが、最初と違う端末の Cookie で（または端末の Cookie 無しで）送られたこと。
	SignalDevice Signal = "device_changed"
	// SignalUserAgent は User-Agent の種類（版の数字を除いたもの）が変わったこと。
	SignalUserAgent Signal = "user_agent_changed"
	// SignalASN は接続元の ASN が最初と変わったこと（国は同じ）。GeoIP が要る。
	SignalASN Signal = "asn_changed"
	// SignalCountry は接続元の国が最初と変わったこと。GeoIP が要る。
	SignalCountry Signal = "country_changed"
	// SignalFlapping は window の内に max_networks 以上の別々のネットワークから使われたこと。
	SignalFlapping Signal = "network_flapping"
	// SignalUnfamiliarNetwork はユーザーが普段使わないネットワーク（CIDR も ASN も一覧に無い）から使われたこと。
	// 一覧が育ってから（profile.min_observations）だけ見る。
	SignalUnfamiliarNetwork Signal = "unfamiliar_network"
	// SignalUnfamiliarBrowser はユーザーが普段使わないブラウザの種類（版の数字を除いた User-Agent）で使われたこと。
	SignalUnfamiliarBrowser Signal = "unfamiliar_browser"
)

// Signals は兆候の一覧（評価と監査ログの順）。
var Signals = []Signal{SignalDevice, SignalUserAgent, SignalCountry, SignalASN, SignalFlapping, SignalUnfamiliarNetwork, SignalUnfamiliarBrowser}

// RiskType は兆候が上げるリスクの種類（ADR 0084 の組み込みの種類）。
func (s Signal) RiskType() string {
	switch s {
	case SignalDevice, SignalUserAgent, SignalUnfamiliarBrowser:
		return risk.TypeDevice
	default:
		return risk.TypeIP
	}
}

// Action は兆候を見つけたときにすること。監査ログにはいつも残す。
type Action string

const (
	// ActionRisk はログインの系列のリスクの点数を、兆候の点数まで上げる（下げない）。
	ActionRisk Action = "risk"
	// ActionRevoke はログインの系列を失効させる。
	ActionRevoke Action = "revoke"
	// ActionNotify は本人に知らせる（通知 suspicious_session）。
	ActionNotify Action = "notify"
)

// KnownActions はアクションの名前。
var KnownActions = []Action{ActionRisk, ActionRevoke, ActionNotify}

// Rule は兆候ごとの設定。
type Rule struct {
	Enabled bool
	// Score は ActionRisk で上げる点数（0〜100）。
	Score   int
	Actions []Action
}

// Config は監視の設定。
type Config struct {
	// Window は別々のネットワークを数える時間。
	Window time.Duration
	// MaxNetworks は window の内にこの数以上の別々のネットワークから使われたら SignalFlapping とする。
	MaxNetworks int
	// IgnoreNetworks の接続元は、接続元の比較と数え上げから外す（会社の出口・自前の VPN など）。
	IgnoreNetworks []netip.Prefix
	Rules          map[Signal]Rule
	// TTL は状態を覚えておく長さ（セッションの寿命の上限）。
	TTL time.Duration
	// Profile はユーザーが普段使う接続元の一覧。
	Profile ProfileConfig
}

// Guard は監視。
type Guard struct {
	Cache port.EphemeralStore
	// GeoIP が nil なら国・ASN を見ない（ネットワークは /24・/64 で数える）。
	GeoIP  port.GeoIP
	Clock  clock.Clock
	Config Config
	// Notify と Accounts は ActionNotify の宛先を決める。Notify が nil なら知らせない。
	Notify   *notify.Service
	Accounts *account.Service
	// Crypter は普段の接続元の一覧をユーザーのデータ鍵で暗号化する。nil なら一覧を作らない。
	Crypter *pii.Crypter
	Log     *slog.Logger
}

// Request はセッションで来た要求の接続元。
type Request struct {
	RealmID string
	// SID はログインの系列の ID（ID を入れ替えても変わらない）。
	SID       string
	IP        string
	UserAgent string
	// Device は端末の Cookie の値（無ければ空）。ViaCookie のときだけ比べる。
	Device string
	// ViaCookie はセッションを Cookie で受けたか。Bearer（別のドメインのアプリ）では端末の Cookie が届かないので比べない。
	ViaCookie bool
}

// Anomaly は見つけた兆候。
type Anomaly struct {
	Signal  Signal
	Score   int
	Actions []Action
	// Details は監査ログに足す内容（国のコード・数えたネットワークの数など。IP は監査ログの接続元に入る）。
	Details map[string]any
}

// Observation は Observe の結果。
type Observation struct {
	// Found はまだ知らせていない兆候。
	Found []Anomaly
	// Visit は系列が新しいネットワークから使われたこと（ログインの後の最初の要求を含む）。nil でなければ、呼び出し側は
	// Learn で普段の接続元の一覧に足す。
	Visit *Visit
}

// Has は兆候のアクションに a があるか。
func (x Anomaly) Has(a Action) bool { return slices.Contains(x.Actions, a) }

// seen は覚えているネットワーク。
type seen struct {
	ID string    `json:"i"`
	At time.Time `json:"t"`
}

// state はログインの系列ごとの状態（EphemeralStore の値）。秘密も IP そのものも置かない（ハッシュとネットワークの ID だけ）。
type state struct {
	// Device は最初の端末の Cookie のハッシュ。HasDevice が偽なら、まだ Cookie で見ていない。
	HasDevice bool   `json:"hd,omitempty"`
	Device    []byte `json:"d,omitempty"`
	// UA は最初の User-Agent の種類のハッシュ。
	UA []byte `json:"u,omitempty"`
	// Located は最初の場所（国・ASN）を引けたか。
	Located bool   `json:"l,omitempty"`
	Country string `json:"c,omitempty"`
	ASN     uint32 `json:"a,omitempty"`
	Nets    []seen `json:"n,omitempty"`
	// Reported は知らせ済みの兆候（系列ごとに 1 回だけ記録し、アクションを取る）。
	Reported []Signal `json:"r,omitempty"`
	// Pending は普段の接続元の一覧にまだ足せていないネットワークの ID。足せる（記録のトランザクションがコミットする）まで、
	// 同じネットワークからの要求でも Visit を返す。
	Pending string `json:"p,omitempty"`
}

func key(realmID, sid string) string { return "sesbind:v1:" + realmID + ":" + sid }

func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// uaFamily は User-Agent から版の数字を除く（ブラウザ・OS の更新では変わらず、別のブラウザ・OS なら変わる）。
func uaFamily(ua string) string {
	return strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || r == '.' || r == '_' {
			return -1
		}
		return r
	}, ua)
}

// network は接続元のネットワークの ID と、引けた場所。ASN が引ければ ASN（同じ事業者の中の IP の変化は数えない。
// モバイル回線・CGNAT）、引けなければ IPv4 は /24、IPv6 は /64。
func (g *Guard) network(ctx context.Context, ip netip.Addr) (string, port.GeoLocation, bool) {
	var loc port.GeoLocation
	located := false
	if g.GeoIP != nil {
		l, ok, err := g.GeoIP.Lookup(ctx, ip.String())
		if err != nil {
			g.logger().WarnContext(ctx, "geoip lookup failed", "error", err)
		} else if ok {
			loc, located = l, true
		}
	}
	if located && loc.ASN != 0 {
		return "as" + strconv.FormatUint(uint64(loc.ASN), 10), loc, true
	}
	return cidr(ip), loc, located
}

func (g *Guard) ignored(ip netip.Addr) bool {
	for _, p := range g.Config.IgnoreNetworks {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *Guard) logger() *slog.Logger {
	if g.Log == nil {
		return slog.Default()
	}
	return g.Log
}

// Observe は要求 in を系列の状態と比べ、まだ知らせていない兆候を返す。状態は変わったときだけ書く。返した兆候は、呼び出し側が
// アクションを記録した後に Confirm で知らせ済みにする。
// 状態を読めない・書けないときはエラーを返す（呼び出し側は要求を止めない）。
func (g *Guard) Observe(ctx context.Context, in Request) (Observation, error) {
	if in.SID == "" {
		return Observation{}, nil
	}
	now := g.Clock.Now()
	k := key(in.RealmID, in.SID)
	var st state
	b, hit, err := g.Cache.Get(ctx, k)
	if err != nil {
		return Observation{}, err
	}
	fresh := !hit
	if hit && json.Unmarshal(b, &st) != nil {
		st, fresh = state{}, true
	}
	dirty := fresh
	var found []Anomaly
	var visit *Visit
	report := func(s Signal, details map[string]any) {
		r, ok := g.Config.Rules[s]
		if !ok || !r.Enabled || slices.Contains(st.Reported, s) {
			return
		}
		// 知らせ済みにするのは、呼び出し側がアクションを記録できた後（Confirm）。記録できなければ次の要求でもう一度見つかる。
		found = append(found, Anomaly{Signal: s, Score: r.Score, Actions: slices.Clone(r.Actions), Details: details})
	}

	// 端末の Cookie（Cookie のセッションだけ）。
	if in.ViaCookie {
		switch {
		case !st.HasDevice && in.Device != "":
			// 最初の要求か、後から端末の Cookie が付いた（フィーチャーを有効にした後など）。これを起点にする。
			st.HasDevice, st.Device, dirty = true, digest(in.Device), true
		case st.HasDevice && (in.Device == "" || !bytes.Equal(st.Device, digest(in.Device))):
			report(SignalDevice, map[string]any{"device_cookie": in.Device != ""})
		}
	}

	// User-Agent の種類。
	if ua := digest(uaFamily(in.UserAgent)); st.UA == nil {
		st.UA, dirty = ua, true
	} else if !bytes.Equal(st.UA, ua) {
		report(SignalUserAgent, nil)
	}

	// 接続元。
	if ip, err := netip.ParseAddr(in.IP); err == nil && !g.ignored(ip.Unmap()) {
		ip = ip.Unmap()
		id, loc, located := g.network(ctx, ip)
		switch {
		case located && !st.Located:
			st.Located, st.Country, st.ASN, dirty = true, loc.Country, loc.ASN, true
		case located && loc.Country != "" && st.Country != "" && loc.Country != st.Country:
			report(SignalCountry, map[string]any{"from_country": st.Country, "to_country": loc.Country})
		case located && loc.ASN != 0 && st.ASN != 0 && loc.ASN != st.ASN:
			report(SignalASN, map[string]any{"from_asn": st.ASN, "to_asn": loc.ASN})
		}
		changed, added := g.touch(&st, id, now)
		dirty = changed || dirty
		if added && g.ProfilesEnabled() && st.Pending != id {
			st.Pending, dirty = id, true
		}
		if st.Pending == id && g.ProfilesEnabled() {
			visit = &Visit{Network: cidr(ip), ASN: loc.ASN, Country: loc.Country, Family: uaFamily(in.UserAgent), UserAgent: in.UserAgent,
				Reported: slices.Clone(st.Reported), net: id}
		}
		if n := g.distinct(st, now); g.Config.MaxNetworks > 0 && n >= g.Config.MaxNetworks {
			report(SignalFlapping, map[string]any{"networks": n, "window_seconds": int(g.Config.Window / time.Second)})
		}
	}

	if dirty {
		b, err := json.Marshal(st)
		if err != nil {
			return Observation{}, err
		}
		if err := g.Cache.Set(ctx, k, b, g.Config.TTL); err != nil {
			// 系列の状態を書けなければ、次の要求でも新しいネットワークに見えるので、一覧には足さない（数え過ぎない）。
			return Observation{Found: found}, err
		}
	}
	return Observation{Found: found, Visit: visit}, nil
}

// live は覚えたネットワークの時刻 at が数える範囲にあるか。同じネットワークの時刻は window の 1/4 ごとにしか更新しないので、
// 最後に見た時刻より最大で window/4 古い。数え落とさないよう、その分だけ広く見る（数える範囲は window から window の 1.25 倍）。
func (g *Guard) live(at, now time.Time) bool { return now.Sub(at) <= g.Config.Window+g.Config.Window/4 }

// touch はネットワーク id を見たことを覚える。書き込みを減らすため、同じネットワークの時刻は window の 1/4 より古くなったら
// 更新する。変えたら changed、覚えていないネットワーク（数える範囲を過ぎて捨てたものを含む）なら added を真にする。
func (g *Guard) touch(st *state, id string, now time.Time) (changed, added bool) {
	i := slices.IndexFunc(st.Nets, func(s seen) bool { return s.ID == id })
	if i >= 0 {
		if now.Sub(st.Nets[i].At) < g.Config.Window/4 {
			return false, false
		}
		st.Nets[i].At = now
		return true, false
	}
	st.Nets = append(st.Nets, seen{ID: id, At: now})
	// 数える範囲を過ぎたものを捨て、数を抑える（数えるのに要るのは max_networks まで）。
	st.Nets = slices.DeleteFunc(st.Nets, func(s seen) bool { return !g.live(s.At, now) })
	if limit := max(g.Config.MaxNetworks, 1) * 2; len(st.Nets) > limit {
		st.Nets = st.Nets[len(st.Nets)-limit:]
	}
	return true, true
}

// distinct は window の内に見た別々のネットワークの数。少し前に見たネットワークに戻るだけ（2 つの回線の行き来）は増えない。
func (g *Guard) distinct(st state, now time.Time) int {
	n := 0
	for _, s := range st.Nets {
		if g.live(s.At, now) {
			n++
		}
	}
	return n
}

// Confirm は found を知らせ済みにし、visit を一覧に足し終えたことにする（アクションと一覧を記録できた後に呼ぶ）。書けなければ
// 次の要求でもう一度見つかる（記録とアクションが重なり、一覧の回数が 1 つ多くなるだけで、リスクの引き上げと失効は同じ結果になる）。
func (g *Guard) Confirm(ctx context.Context, realmID, sid string, found []Anomaly, visit *Visit) {
	if len(found) == 0 && visit == nil {
		return
	}
	k := key(realmID, sid)
	var st state
	b, hit, err := g.Cache.Get(ctx, k)
	if err != nil {
		g.logger().WarnContext(ctx, "session binding state read failed", "error", err)
		return
	}
	if hit && json.Unmarshal(b, &st) != nil {
		st = state{}
	}
	for _, x := range found {
		if !slices.Contains(st.Reported, x.Signal) {
			st.Reported = append(st.Reported, x.Signal)
		}
	}
	if visit != nil && st.Pending == visit.net {
		st.Pending = ""
	}
	if b, err := json.Marshal(st); err == nil {
		if err := g.Cache.Set(ctx, k, b, g.Config.TTL); err != nil {
			g.logger().WarnContext(ctx, "session binding state write failed", "error", err)
		}
	}
}

// Forget は系列の状態を消す（ログアウトなど。消さなくても TTL で消える）。
func (g *Guard) Forget(ctx context.Context, realmID, sid string) {
	if err := g.Cache.Delete(ctx, key(realmID, sid)); err != nil {
		g.logger().WarnContext(ctx, "session binding state delete failed", "error", err)
	}
}

// NotifyUser は本人に、セッションが別の端末・接続元から使われた兆候を知らせる（確認済みの全メールへ。宛先は claim で取り出させる。
// アドレスを保存しない構成のメールがあれば、宛先なしの通知を 1 件出し、外部が user_id から宛先を解決する。new_device_login と同じ形）。
func (g *Guard) NotifyUser(ctx context.Context, tx port.Tx, realmID, userID, userPublicID string) error {
	if g.Notify == nil {
		return nil
	}
	es, err := tx.Emails().ListByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	n := port.Notification{Type: TypeSuspiciousSession, RealmID: realmID, UserID: userPublicID}
	unresolved, sent := false, false
	for _, e := range es {
		if e.VerifiedAt == nil {
			continue
		}
		if g.Accounts == nil || g.Accounts.IndexOnly || len(e.Ciphertext) == 0 {
			unresolved = true
			continue
		}
		addr, err := g.Accounts.EmailAddress(ctx, tx, e)
		if err != nil {
			return err
		}
		if _, err := g.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: addr, ExpiresAt: g.Clock.Now().Add(24 * time.Hour)}); err != nil {
			return err
		}
		sent = true
	}
	if unresolved || !sent {
		_, err = g.Notify.Enqueue(ctx, tx, n, nil)
	}
	return err
}
