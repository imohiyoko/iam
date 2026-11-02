package provider

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Device Authorization Grant（RFC 8628、ADR 0095）。入力の限られた端末（テレビ・CLI など）が device_code を受け取り、本人は
// 別の端末のブラウザで user_code を入れて承認する。端末は token エンドポイントを device_code でポーリングし、承認の後は
// 認可コードフローと同じトークン（ログインの系列に結び付く。ADR 0066）を受け取る。
//
// 状態は認可コードと同じく EphemeralStore に封をして置く（短命で、1回だけ取り出す）。キーは秘密の値の SHA-256。
//
//	oidc:device:v1:<device_code>           端末の要求（連携先・スコープ・期限）。期限の後もしばらく残し、expired_token を返す
//	oidc:device:user:v1:<user_code>        user_code から端末の要求へ。承認か拒否で1回だけ取り出す
//	oidc:device:decision:v1:<device_code>  本人の承認・拒否。ポーリングで1回だけ取り出す
//	oidc:device:poll:v1:<device_code>      最後のポーリングの時刻と間隔（slow_down）

// DeviceFeature は Device Authorization Grant のフィーチャー（既定オフ）。
var DeviceFeature = feature.Feature{Name: feature.DeviceFlow, DataVersion: 1}

// 既定の期限と間隔。
const (
	DefaultDeviceTTL      = 10 * time.Minute
	DefaultDeviceInterval = 5 * time.Second
	// slowDownStep は slow_down のたびに間隔を延ばす幅（RFC 8628 3.5）。
	slowDownStep = 5 * time.Second
	// maxDeviceInterval は延ばした間隔の上限。
	maxDeviceInterval = time.Minute
)

// user_code は母音を含まない子音 20 文字の 8 桁（RFC 8628 6.1 の例。約 34.5 bit）。見せるときは 4 桁ずつハイフンでつなぐ。
const (
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLength   = 8
)

// GrantTypeDeviceCode は device_code の grant_type（RFC 8628 3.4）。
const GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

var (
	// ErrDevicePending は本人がまだ承認も拒否もしていない（authorization_pending）。
	ErrDevicePending = errs.WithCode(errs.KindInvalid, "authorization_pending", "authorization pending")
	// ErrDeviceSlowDown は間隔より速いポーリング（slow_down）。間隔を延ばした。
	ErrDeviceSlowDown = errs.WithCode(errs.KindInvalid, "slow_down", "slow down")
	// ErrDeviceDenied は本人が拒否した（access_denied）。
	ErrDeviceDenied = errs.WithCode(errs.KindPermissionDenied, "access_denied", "access denied")
	// ErrDeviceExpired は device_code の期限切れ（expired_token）。
	ErrDeviceExpired = errs.WithCode(errs.KindInvalid, "expired_token", "device code expired")
	// ErrUserCode は user_code が使えない（形が違う・知らない・期限切れ・使用済み。理由は返さない）。
	ErrUserCode = errs.WithCode(errs.KindNotFound, "invalid_user_code", "invalid user code")
)

// Device は端末の要求と本人の承認を預かる。
type Device struct {
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	// TTL は device_code と user_code の期限（既定 10 分）。Interval はポーリングの最短の間隔（既定 5 秒）。
	TTL      time.Duration
	Interval time.Duration
}

// DeviceRequest は端末の要求。
type DeviceRequest struct {
	RealmID string `json:"realm_id"`
	// ClientID は client_id（外部 ID）。
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DeviceStart は device_authorization エンドポイントの応答の中身。
type DeviceStart struct {
	DeviceCode string
	// UserCode は見せる形（XXXX-XXXX）。
	UserCode  string
	ExpiresIn time.Duration
	Interval  time.Duration
}

type deviceUser struct {
	DeviceRequest
	// Device は端末の要求のキー（device_code の SHA-256）。
	Device string `json:"device"`
}

type deviceDecision struct {
	Approved bool  `json:"approved"`
	Code     *Code `json:"code,omitempty"`
}

type devicePoll struct {
	Last     time.Time     `json:"last"`
	Interval time.Duration `json:"interval"`
}

const (
	deviceRequestPurpose  = "flow.oidc_device"
	deviceUserPurpose     = "flow.oidc_device_user"
	deviceDecisionPurpose = "flow.oidc_device_decision"
	devicePrefix          = "oidc:device:v1:"
	deviceUserPrefix      = "oidc:device:user:v1:"
	deviceDecisionPrefix  = "oidc:device:decision:v1:"
	devicePollPrefix      = "oidc:device:poll:v1:"
)

func (d *Device) ttl() time.Duration      { return ttlOr(d.TTL, DefaultDeviceTTL) }
func (d *Device) interval() time.Duration { return ttlOr(d.Interval, DefaultDeviceInterval) }

// keep は端末の要求を残す長さ。期限の後も同じ長さだけ残し、その間のポーリングには expired_token を返す。
func (d *Device) keep() time.Duration { return 2 * d.ttl() }

func (d *Device) put(ctx context.Context, key, purpose string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := d.Crypter.Seal(ctx, purpose, b)
	if err != nil {
		return err
	}
	return d.Cache.Set(ctx, key, sealed, ttl)
}

func (d *Device) open(ctx context.Context, purpose string, sealed []byte, v any) error {
	b, err := d.Crypter.Open(ctx, purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// newUserCode は偏りのない user_code（正規化した形）を作る。
func newUserCode() (string, error) {
	out := make([]byte, 0, userCodeLength)
	buf := make([]byte, 16)
	// 256 を 20 で割り切れる 240 未満の値だけを使う（剰余の偏りを避ける）。
	limit := byte(256 - 256%len(userCodeAlphabet))
	for len(out) < userCodeLength {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < limit && len(out) < userCodeLength {
				out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
			}
		}
	}
	return string(out), nil
}

// NormalizeUserCode は入力された user_code を正規化する（大文字にし、ハイフンと空白を除く）。形が違えば false。
func NormalizeUserCode(s string) (string, bool) {
	if len(s) > 4*userCodeLength {
		return "", false
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case r < 0x80 && strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	if b.Len() != userCodeLength {
		return "", false
	}
	return b.String(), true
}

// FormatUserCode は正規化した user_code を見せる形（XXXX-XXXX）にする。
func FormatUserCode(s string) string {
	if len(s) != userCodeLength {
		return s
	}
	return s[:userCodeLength/2] + "-" + s[userCodeLength/2:]
}

// Start は端末の要求を預かり、device_code と user_code を発行する（RFC 8628 3.2）。
func (d *Device) Start(ctx context.Context, r DeviceRequest) (DeviceStart, error) {
	deviceCode, err := randomString()
	if err != nil {
		return DeviceStart{}, err
	}
	ttl := d.ttl()
	r.ExpiresAt = d.Clock.Now().Add(ttl)
	dkey := digestKey(devicePrefix, deviceCode)
	// user_code は短いので、使われているものと重なれば作り直す。
	var userCode, ukey string
	for range 5 {
		if userCode, err = newUserCode(); err != nil {
			return DeviceStart{}, err
		}
		ukey = digestKey(deviceUserPrefix, userCode)
		_, taken, err := d.Cache.Get(ctx, ukey)
		if err != nil {
			return DeviceStart{}, err
		}
		if !taken {
			break
		}
		ukey = ""
	}
	if ukey == "" {
		return DeviceStart{}, errors.New("provider: could not allocate a user code")
	}
	if err := d.put(ctx, dkey, deviceRequestPurpose, r, d.keep()); err != nil {
		return DeviceStart{}, err
	}
	if err := d.put(ctx, ukey, deviceUserPurpose, deviceUser{DeviceRequest: r, Device: dkey}, ttl); err != nil {
		return DeviceStart{}, err
	}
	return DeviceStart{DeviceCode: deviceCode, UserCode: FormatUserCode(userCode), ExpiresIn: ttl, Interval: d.interval()}, nil
}

func (d *Device) user(ctx context.Context, realmID, userCode string, take bool) (deviceUser, error) {
	code, ok := NormalizeUserCode(userCode)
	if !ok {
		return deviceUser{}, ErrUserCode
	}
	key := digestKey(deviceUserPrefix, code)
	var (
		b   []byte
		err error
	)
	if take {
		b, ok, err = d.Cache.Take(ctx, key)
	} else {
		b, ok, err = d.Cache.Get(ctx, key)
	}
	if err != nil {
		return deviceUser{}, err
	}
	var u deviceUser
	if !ok || d.open(ctx, deviceUserPurpose, b, &u) != nil || u.RealmID != realmID || !d.Clock.Now().Before(u.ExpiresAt) {
		return deviceUser{}, ErrUserCode
	}
	return u, nil
}

// Lookup は user_code の端末の要求を返す（消さない。確認の画面に使う）。使えなければ ErrUserCode。
func (d *Device) Lookup(ctx context.Context, realmID, userCode string) (DeviceRequest, error) {
	u, err := d.user(ctx, realmID, userCode, false)
	return u.DeviceRequest, err
}

// Decide は本人の承認（c が nil でない）か拒否を記録する。user_code は1回だけ使える（承認でも拒否でも、もう使えない）。
// c には本人とログインの系列を入れる（連携先・スコープは端末の要求のものにする）。
func (d *Device) Decide(ctx context.Context, realmID, userCode string, c *Code) (DeviceRequest, error) {
	u, err := d.user(ctx, realmID, userCode, true)
	if err != nil {
		return DeviceRequest{}, err
	}
	dec := deviceDecision{Approved: c != nil}
	if c != nil {
		cc := *c
		cc.AuthRequest = AuthRequest{RealmID: u.RealmID, ClientID: u.ClientID, Scopes: u.Scopes, ExpiresAt: u.ExpiresAt}
		cc.GrantType = GrantTypeDeviceCode
		dec.Code = &cc
	}
	// 端末の要求と同じだけ残す（期限の後は Poll が expired_token を返すので、使われない）。
	ttl := u.ExpiresAt.Add(d.ttl()).Sub(d.Clock.Now())
	return u.DeviceRequest, d.put(ctx, digestKey(deviceDecisionPrefix, u.Device), deviceDecisionPurpose, dec, ttl)
}

// Poll は端末のポーリングに答える（RFC 8628 3.4、3.5）。承認されていれば、トークンの発行に使う内容を1回だけ返す。
// 知らない・別の連携先の device_code は ErrInvalidGrant、期限切れは ErrDeviceExpired、間隔より速ければ ErrDeviceSlowDown
// （間隔を 5 秒延ばす）、未決なら ErrDevicePending、拒否なら ErrDeviceDenied。
func (d *Device) Poll(ctx context.Context, realmID, clientID, deviceCode string) (Code, error) {
	if deviceCode == "" {
		return Code{}, ErrInvalidGrant
	}
	dkey := digestKey(devicePrefix, deviceCode)
	b, ok, err := d.Cache.Get(ctx, dkey)
	if err != nil {
		return Code{}, err
	}
	var r DeviceRequest
	if !ok || d.open(ctx, deviceRequestPurpose, b, &r) != nil || r.RealmID != realmID || r.ClientID != clientID {
		return Code{}, ErrInvalidGrant
	}
	now := d.Clock.Now()
	if !now.Before(r.ExpiresAt) {
		return Code{}, ErrDeviceExpired
	}
	if err := d.pace(ctx, dkey, r, now); err != nil {
		return Code{}, err
	}
	b, ok, err = d.Cache.Take(ctx, digestKey(deviceDecisionPrefix, dkey))
	if err != nil {
		return Code{}, err
	}
	if !ok {
		return Code{}, ErrDevicePending
	}
	// 決まった要求はもう使えない（承認でも拒否でも1回だけ答える）。
	if err := d.Cache.Delete(ctx, dkey); err != nil {
		return Code{}, err
	}
	_ = d.Cache.Delete(ctx, digestKey(devicePollPrefix, dkey))
	var dec deviceDecision
	if d.open(ctx, deviceDecisionPurpose, b, &dec) != nil {
		return Code{}, ErrInvalidGrant
	}
	if !dec.Approved || dec.Code == nil {
		return Code{}, ErrDeviceDenied
	}
	if dec.Code.RealmID != realmID || dec.Code.ClientID != clientID {
		return Code{}, ErrInvalidGrant
	}
	return *dec.Code, nil
}

// pace は前のポーリングから間隔が空いているかを確かめる。速すぎれば間隔を延ばして ErrDeviceSlowDown を返す。
func (d *Device) pace(ctx context.Context, dkey string, r DeviceRequest, now time.Time) error {
	return pacePoll(ctx, d.Cache, digestKey(devicePollPrefix, dkey), d.interval(), now, r.ExpiresAt)
}

// pacePoll はポーリングの間隔を確かめる（RFC 8628 3.5。CIBA も同じ。ADR 0095、0114）。key に最後の時刻と間隔を置き、
// 間隔（base より短くしない）より速ければ間隔を slowDownStep 延ばして（maxDeviceInterval まで）ErrDeviceSlowDown を返す。
// 時刻と間隔は秘密でないので封をしない。並行のポーリングでは数え漏れがありうる（間隔の目安に使うだけ）。
func pacePoll(ctx context.Context, cache port.EphemeralStore, key string, base time.Duration, now, until time.Time) error {
	p := devicePoll{Interval: base}
	b, ok, err := cache.Get(ctx, key)
	if err != nil {
		return err
	}
	if ok {
		_ = json.Unmarshal(b, &p)
		p.Interval = max(p.Interval, base)
	}
	fast := !p.Last.IsZero() && now.Sub(p.Last) < p.Interval
	if fast {
		p.Interval = min(p.Interval+slowDownStep, maxDeviceInterval)
	}
	p.Last = now
	nb, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := cache.Set(ctx, key, nb, until.Sub(now)); err != nil {
		return err
	}
	if fast {
		return ErrDeviceSlowDown
	}
	return nil
}
