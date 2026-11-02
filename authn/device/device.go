// Package device は本人がログインした端末を覚え（フィーチャー device_recognition）、ログインのリスクの点数を出す
// （フィーチャー login_risk）。ADR 0105。
//
// 端末はブラウザの Cookie の 256 bit の乱数で見分け、Storage には乱数のブラインドインデックスだけを置く。端末の詳細
// （User-Agent・IP・場所・強い認証で確かめたか）はユーザーのデータ鍵で暗号化する。記録は本人確認を終えたログイン
// （制限の無いセッションの発行）のときだけ行う。
package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// Feature は端末の記憶（既定オフ）。
var Feature = feature.Feature{Name: feature.DeviceRecognition, DataVersion: 1}

// RiskFeature はログインのリスクの点数（既定オフ）。端末の記録を材料にするので device_recognition に依存する。
var RiskFeature = feature.Feature{Name: feature.LoginRisk, DataVersion: 1, Requires: []string{feature.DeviceRecognition}}

// TypeNewDeviceLogin は新しい端末からのログインの通知（ID だけ。ADR 0031）。
const TypeNewDeviceLogin = "new_device_login"

// 監査ログの種類。
const (
	EventAdded     = "device.added"
	EventForgotten = "device.forgotten"
)

// tokenBytes は Cookie の乱数の大きさ。
const tokenBytes = 32

// lookupPurpose はブラインドインデックスの用途。
const lookupPurpose = "authn.device"

// dataAAD は詳細の暗号文の AAD。端末の ID に結び付ける。
func dataAAD(deviceID string) string { return "authn.device." + deviceID }

// NewToken は Cookie に置く新しい乱数を返す。
func NewToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidToken は Cookie の値が NewToken の形かを返す（形の違う値は無いものとして扱う）。
func ValidToken(s string) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == tokenBytes
}

// Data は端末の詳細（暗号化して置く）。
type Data struct {
	UserAgent string `json:"ua,omitempty"`
	IP        string `json:"ip,omitempty"`
	Country   string `json:"country,omitempty"`
	ASN       uint32 `json:"asn,omitempty"`
	// HasCoordinates は Lat・Lon があるか。
	HasCoordinates bool    `json:"coords,omitempty"`
	Lat            float64 `json:"lat,omitempty"`
	Lon            float64 `json:"lon,omitempty"`
	// Confirmed は強い認証（AAL2 以上）のログインに使われたか。
	Confirmed bool `json:"confirmed,omitempty"`
}

// Config は端末の記憶の設定。
type Config struct {
	// MaxPerUser はユーザーごとの端末の上限。超えれば最後に使った時刻の古いものから消す。0 以下なら 50。
	MaxPerUser int
	// Notify は新しい端末からのログインを本人に知らせるか。
	Notify bool
}

// RiskConfig はログインのリスクの点数（フィーチャー login_risk）。
type RiskConfig struct {
	NewDeviceScore, UnconfirmedDeviceScore              int
	NewCountryScore, NewASNScore, ImpossibleTravelScore int
	// MaxSpeedKmh はこれより速く動かないと来られなければ impossible travel とする。
	MaxSpeedKmh float64
}

// Service は端末の記憶。
type Service struct {
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Notify   *notify.Service
	Config   Config
	// Risk は nil ならリスクの点数を出さない（フィーチャー login_risk が動いていない）。
	Risk *RiskConfig
	// GeoIP は nil なら ip の点数を出さない。
	GeoIP port.GeoIP
	Log   *slog.Logger
}

// Input はログインの内容。
type Input struct {
	RealmID, UserID, UserPublicID string
	// Token は送られてきた Cookie の値（無い・形が違えば空）。
	Token string
	// AAL はこのログインの強さ（ADR 0093）。
	AAL                      int
	IP, UserAgent, RequestID string
}

// Observation は Observe の結果。
type Observation struct {
	// Token は Cookie に置き直す値（送られてきた値か新しい値）。
	Token string
	// New は前に端末を持っていたユーザーの、知らない端末か（警告 new_device。通知もこのときだけ）。
	New bool
	// Risk はリスクの点数（login_risk が動いていなければ nil）。
	Risk map[string]int
}

func (s *Service) maxPerUser() int {
	if s.Config.MaxPerUser <= 0 {
		return 50
	}
	return s.Config.MaxPerUser
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

type known struct {
	port.KnownDevice
	data Data
}

func (s *Service) open(ctx context.Context, tx port.Tx, d port.KnownDevice) (Data, error) {
	pt, err := s.Crypter.Decrypt(ctx, tx.DataKeys(), d.UserID, d.Data, dataAAD(d.ID))
	if err != nil {
		return Data{}, err
	}
	var out Data
	return out, json.Unmarshal(pt, &out)
}

func (s *Service) seal(ctx context.Context, tx port.Tx, userID, deviceID string, d Data) ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return s.Crypter.Encrypt(ctx, tx.DataKeys(), userID, b, dataAAD(deviceID))
}

func (s *Service) list(ctx context.Context, tx port.Tx, realmID, userID string) ([]known, error) {
	ds, err := tx.KnownDevices().ListByUser(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]known, 0, len(ds))
	for _, d := range ds {
		data, err := s.open(ctx, tx, d)
		if err != nil {
			return nil, err
		}
		out = append(out, known{d, data})
	}
	return out, nil
}

func (s *Service) lookup(ctx context.Context, token string) ([]byte, error) {
	ix, err := s.Crypter.Index(ctx, lookupPurpose, token)
	if err != nil {
		return nil, err
	}
	return ix.Value, nil
}

// Observe はログインした端末を記録する。呼び出し側（セッションの発行）のトランザクションで呼ぶ。
func (s *Service) Observe(ctx context.Context, tx port.Tx, in Input) (Observation, error) {
	now := s.Clock.Now()
	out := Observation{Token: in.Token}
	if !ValidToken(out.Token) {
		t, err := NewToken()
		if err != nil {
			return Observation{}, err
		}
		out.Token = t
	}
	lk, err := s.lookup(ctx, out.Token)
	if err != nil {
		return Observation{}, err
	}
	devices, err := s.list(ctx, tx, in.RealmID, in.UserID)
	if err != nil {
		return Observation{}, err
	}
	cur := slices.IndexFunc(devices, func(d known) bool { return bytes.Equal(d.Lookup, lk) })
	data := Data{UserAgent: in.UserAgent, IP: in.IP}
	var loc port.GeoLocation
	var located bool
	if s.Risk != nil && s.GeoIP != nil && in.IP != "" {
		if loc, located, err = s.GeoIP.Lookup(ctx, in.IP); err != nil {
			// 引けなければ ip を評価しない（ログインは止めない）。
			s.logger().WarnContext(ctx, "geoip lookup failed", "error", err)
			located = false
		}
		if located {
			data.Country, data.ASN, data.HasCoordinates, data.Lat, data.Lon = loc.Country, loc.ASN, loc.HasCoordinates, loc.Latitude, loc.Longitude
		}
	}
	if s.Risk != nil {
		out.Risk = s.score(devices, cur, located, loc, now)
	}
	strong := in.AAL >= 2
	if cur >= 0 {
		d := devices[cur]
		data.Confirmed = d.data.Confirmed || strong
		if !located {
			// 場所が分からなければ前の場所を残す（impossible travel の基準）。
			data.Country, data.ASN, data.HasCoordinates, data.Lat, data.Lon = d.data.Country, d.data.ASN, d.data.HasCoordinates, d.data.Lat, d.data.Lon
		}
		ct, err := s.seal(ctx, tx, in.UserID, d.ID, data)
		if err != nil {
			return Observation{}, err
		}
		return out, tx.KnownDevices().Seen(ctx, in.RealmID, d.ID, ct, now)
	}
	data.Confirmed = strong
	out.New = len(devices) > 0
	// 上限を超えるなら、最後に使った時刻の古いものから消す。
	if over := len(devices) + 1 - s.maxPerUser(); over > 0 {
		old := slices.Clone(devices)
		slices.SortStableFunc(old, func(a, b known) int { return a.LastSeenAt.Compare(b.LastSeenAt) })
		for _, d := range old[:over] {
			if err := tx.KnownDevices().Delete(ctx, in.RealmID, d.ID); err != nil {
				return Observation{}, err
			}
		}
	}
	d := port.KnownDevice{ID: id.New(id.KnownDevice), PublicID: id.NewExternal(id.KnownDevice), RealmID: in.RealmID, UserID: in.UserID,
		Lookup: lk, CreatedAt: now, LastSeenAt: now}
	if d.Data, err = s.seal(ctx, tx, in.UserID, d.ID, data); err != nil {
		return Observation{}, err
	}
	if err := tx.KnownDevices().Create(ctx, d); err != nil {
		return Observation{}, err
	}
	actor := audit.Actor{Type: "user", ID: in.UserPublicID}
	if _, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventAdded, Result: audit.ResultSuccess, RealmID: in.RealmID, Actor: actor,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID, Details: map[string]any{"device_id": d.PublicID, "new": out.New}}); err != nil {
		return Observation{}, err
	}
	if out.New && s.Config.Notify && s.Notify != nil {
		if err := s.notify(ctx, tx, in, d.PublicID, now); err != nil {
			return Observation{}, err
		}
	}
	return out, nil
}

// score はログインの前の状態からリスクの点数を出す（ADR 0105）。
func (s *Service) score(devices []known, cur int, located bool, loc port.GeoLocation, now time.Time) map[string]int {
	r := s.Risk
	out := map[string]int{}
	switch {
	case cur >= 0 && devices[cur].data.Confirmed:
		out[risk.TypeDevice] = 0
	case cur >= 0:
		out[risk.TypeDevice] = r.UnconfirmedDeviceScore
	default:
		out[risk.TypeDevice] = r.NewDeviceScore
	}
	if !located {
		return out
	}
	ip := 0
	var countries []string
	var asns []uint32
	var last *known
	for i := range devices {
		d := &devices[i]
		if d.data.Country != "" {
			countries = append(countries, d.data.Country)
		}
		if d.data.ASN != 0 {
			asns = append(asns, d.data.ASN)
		}
		if d.data.HasCoordinates && (last == nil || d.LastSeenAt.After(last.LastSeenAt)) {
			last = d
		}
	}
	if loc.Country != "" && len(countries) > 0 && !slices.Contains(countries, loc.Country) {
		ip = max(ip, r.NewCountryScore)
	}
	if loc.ASN != 0 && len(asns) > 0 && !slices.Contains(asns, loc.ASN) {
		ip = max(ip, r.NewASNScore)
	}
	if loc.HasCoordinates && last != nil && r.MaxSpeedKmh > 0 {
		km := Distance(last.data.Lat, last.data.Lon, loc.Latitude, loc.Longitude)
		hours := now.Sub(last.LastSeenAt).Hours()
		// 同じ時刻（時計の粒度の内）で離れた場所は、どの速さでも来られない。
		if km > 0 && (hours <= 0 || km/hours > r.MaxSpeedKmh) {
			ip = max(ip, r.ImpossibleTravelScore)
		}
	}
	out[risk.TypeIP] = min(max(ip, risk.MinScore), risk.MaxScore)
	return out
}

// Distance は 2 点の大円距離（km。haversine）。
func Distance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthKm = 6371.0
	rad := math.Pi / 180
	dlat, dlon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * earthKm * math.Asin(math.Min(1, math.Sqrt(a)))
}

// notify は本人に新しい端末からのログインを知らせる（確認済みの全メールへ。宛先は claim で取り出させる。復旧の完了と同じ形。
// アドレスを保存しない構成のメールがあれば、宛先なしの通知を1件出し、外部が user_id から宛先を解決する）。
func (s *Service) notify(ctx context.Context, tx port.Tx, in Input, deviceID string, now time.Time) error {
	es, err := tx.Emails().ListByUser(ctx, in.RealmID, in.UserID)
	if err != nil {
		return err
	}
	n := port.Notification{Type: TypeNewDeviceLogin, RealmID: in.RealmID, UserID: in.UserPublicID, DeviceID: deviceID}
	unresolved, sent := false, false
	for _, e := range es {
		if e.VerifiedAt == nil {
			continue
		}
		if s.Accounts == nil || s.Accounts.IndexOnly || len(e.Ciphertext) == 0 {
			unresolved = true
			continue
		}
		addr, err := s.Accounts.EmailAddress(ctx, tx, e)
		if err != nil {
			return err
		}
		if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: addr, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			return err
		}
		sent = true
	}
	if unresolved || !sent {
		_, err = s.Notify.Enqueue(ctx, tx, n, nil)
	}
	return err
}

// View は本人に見せる端末。
type View struct {
	PublicID   string
	CreatedAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	Country    string
	Confirmed  bool
	// Current は今のリクエストの端末か。
	Current bool
}

// List は本人の端末を、最後に使った時刻の新しい順に返す。token は今のリクエストの Cookie の値。
func (s *Service) List(ctx context.Context, tx port.Tx, realmID, userID, token string) ([]View, error) {
	devices, err := s.list(ctx, tx, realmID, userID)
	if err != nil {
		return nil, err
	}
	var lk []byte
	if ValidToken(token) {
		if lk, err = s.lookup(ctx, token); err != nil {
			return nil, err
		}
	}
	out := make([]View, 0, len(devices))
	for _, d := range devices {
		out = append(out, View{PublicID: d.PublicID, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt, UserAgent: d.data.UserAgent,
			Country: d.data.Country, Confirmed: d.data.Confirmed, Current: lk != nil && bytes.Equal(lk, d.Lookup)})
	}
	slices.SortStableFunc(out, func(a, b View) int { return b.LastSeenAt.Compare(a.LastSeenAt) })
	return out, nil
}

// ErrNotFound は本人の端末に無いこと。
var ErrNotFound = errs.WithCode(errs.KindNotFound, "not_found", "device not found")

// Forget は本人の端末を忘れる。
func (s *Service) Forget(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, ip, userAgent, requestID string) error {
	if !id.Valid(id.KnownDevice, publicID) {
		return ErrNotFound
	}
	ds, err := tx.KnownDevices().ListByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ds, func(d port.KnownDevice) bool { return d.PublicID == publicID })
	if i < 0 {
		return ErrNotFound
	}
	if err := tx.KnownDevices().Delete(ctx, realmID, ds[i].ID); err != nil {
		return err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventForgotten, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor,
		IP: ip, UserAgent: userAgent, RequestID: requestID, Details: map[string]any{"device_id": publicID}})
	return err
}
