package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// OpenID Connect Client-Initiated Backchannel Authentication（CIBA Core 1.0、ADR 0114）。機密の連携先が本人の手がかりを付けて
// 要求し、本人は自分の端末（プッシュの承認）か本人の API で承認する。連携先は token エンドポイントを auth_req_id でポーリングする
// （ping なら通知を受けてから）。承認の後は認可コードフローと同じトークン（ログインの系列に結び付く。ADR 0066）。
//
// 状態は Device Authorization Grant（ADR 0095）と同じく EphemeralStore に封をして置く。キーは秘密の値の SHA-256。
//
//	oidc:ciba:v1:<auth_req_id>                    要求。期限の後もしばらく残し、expired_token を返す
//	oidc:ciba:id:v1:<公開 ID>                     本人の API の ID から要求のキーへ
//	oidc:ciba:ref:v1:<方式>:<チャレンジの参照>      本人の端末へのチャレンジから要求のキーへ
//	oidc:ciba:decided:v1:<要求のキー>              判断の印（Incr で最初の1回だけを通す）
//	oidc:ciba:decision:v1:<要求のキー>             本人の承認・拒否。ポーリングで1回だけ取り出す
//	oidc:ciba:poll:v1:<要求のキー>                 最後のポーリングの時刻と間隔（slow_down）
//	oidc:ciba:seq:v1:<realm>:<本人>                本人の枠の番号
//	oidc:ciba:slot:v1:<realm>:<本人>:<0〜15>        本人の枠（公開 ID）。本人の API の一覧はこれだけを読む

// CIBAFeature は CIBA のフィーチャー（既定オフ）。
var CIBAFeature = feature.Feature{Name: feature.CIBA, DataVersion: 1}

// GrantTypeCIBA は CIBA の grant_type（CIBA Core 10.1）。
const GrantTypeCIBA = "urn:openid:params:grant-type:ciba"

// 既定の期限と間隔、上限。
const (
	DefaultCIBATTL      = 5 * time.Minute
	MaxCIBATTL          = 10 * time.Minute
	DefaultCIBAInterval = 5 * time.Second
	// MaxBindingMessage は binding_message の文字数の上限（端末の通知に収まる長さ）。
	MaxBindingMessage = 64
	// MaxNotificationToken は client_notification_token の長さの上限（CIBA Core 7.1 は 1024 文字以上を受けることを勧める）。
	MaxNotificationToken = 1024
	// CIBASlots は本人ごとの未決の要求の上限（本人の API の一覧の枠）。
	CIBASlots = 16
)

var (
	// ErrBackchannelRequest は、本人の API で指した要求が使えない（知らない・別人宛て・期限切れ・判断済み。理由は返さない）。
	ErrBackchannelRequest = errs.WithCode(errs.KindNotFound, "invalid_request", "unknown backchannel authentication request")
	// ErrInvalidBindingMessage は binding_message の形が違う（CIBA Core 13）。
	ErrInvalidBindingMessage = errs.WithCode(errs.KindInvalid, "invalid_binding_message", "invalid binding message")
)

// Backchannel は CIBA の要求と本人の判断を預かる。
type Backchannel struct {
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	// TTL は auth_req_id の期限の上限（既定 5 分）。Interval はポーリングの最短の間隔（既定 5 秒）。
	TTL      time.Duration
	Interval time.Duration
}

// BackchannelRequest は CIBA の要求。
type BackchannelRequest struct {
	// ID は本人の API で使う公開 ID（auth_req_id とは別の乱数）。Start が決める。
	ID      string `json:"id"`
	RealmID string `json:"realm_id"`
	// ClientID は client_id（外部 ID）。UserID は本人の内部 ID。
	ClientID       string   `json:"client_id"`
	UserID         string   `json:"user_id"`
	Scopes         []string `json:"scopes"`
	BindingMessage string   `json:"binding_message,omitempty"`
	// ACR は要求された acr（フィーチャー acr。ADR 0093）。
	ACR []string `json:"acr,omitempty"`
	// Mode は CIBA のモード（port.CIBAPoll か port.CIBAPing）。NotificationToken は ping の Bearer トークン。
	Mode              string `json:"mode"`
	NotificationToken string `json:"notification_token,omitempty"`
	// AuthReqID は ping の通知に載せる auth_req_id（ping のときだけ。要求ごと封をする）。
	AuthReqID string    `json:"auth_req_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	// Channel は本人の端末へのチャレンジ（無ければ nil。方式の状態は秘密を含みうるので、要求ごと封をする）。
	Channel *BackchannelChannel `json:"channel,omitempty"`
}

// BackchannelChannel は本人の端末へのチャレンジ（authn/credential の Backchannel と同じ中身）。
type BackchannelChannel struct {
	Method string `json:"method"`
	Ref    string `json:"ref"`
	State  []byte `json:"state"`
}

// BackchannelStart は backchannel authentication エンドポイントの応答の中身。
type BackchannelStart struct {
	AuthReqID string
	ExpiresIn time.Duration
	Interval  time.Duration
	Request   BackchannelRequest
}

type backchannelDecision struct {
	Approved bool  `json:"approved"`
	Code     *Code `json:"code,omitempty"`
}

const (
	cibaRequestPurpose  = "flow.oidc_ciba"
	cibaDecisionPurpose = "flow.oidc_ciba_decision"
	cibaPrefix          = "oidc:ciba:v1:"
	cibaIDPrefix        = "oidc:ciba:id:v1:"
	cibaRefPrefix       = "oidc:ciba:ref:v1:"
	cibaDecidedPrefix   = "oidc:ciba:decided:v1:"
	cibaDecisionPrefix  = "oidc:ciba:decision:v1:"
	cibaPollPrefix      = "oidc:ciba:poll:v1:"
	cibaSeqPrefix       = "oidc:ciba:seq:v1:"
	cibaSlotPrefix      = "oidc:ciba:slot:v1:"
)

func (b *Backchannel) ttl() time.Duration      { return min(ttlOr(b.TTL, DefaultCIBATTL), MaxCIBATTL) }
func (b *Backchannel) interval() time.Duration { return ttlOr(b.Interval, DefaultCIBAInterval) }

// ValidBindingMessage は binding_message に使えるか（MaxBindingMessage 文字まで、制御文字なし、空でない）を返す。
func ValidBindingMessage(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxBindingMessage {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidNotificationToken は client_notification_token に使えるか（RFC 6750 の b64token の文字で MaxNotificationToken 文字まで）を返す。
func ValidNotificationToken(s string) bool {
	if s == "" || len(s) > MaxNotificationToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func (b *Backchannel) put(ctx context.Context, key, purpose string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := b.Crypter.Seal(ctx, purpose, raw)
	if err != nil {
		return err
	}
	return b.Cache.Set(ctx, key, sealed, ttl)
}

func (b *Backchannel) open(ctx context.Context, purpose string, sealed []byte, v any) error {
	raw, err := b.Crypter.Open(ctx, purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// load は要求のキー（auth_req_id の SHA-256）の要求を読む。無い・読めなければ ok は偽。
func (b *Backchannel) load(ctx context.Context, key string) (BackchannelRequest, bool, error) {
	raw, ok, err := b.Cache.Get(ctx, key)
	if err != nil || !ok {
		return BackchannelRequest{}, false, err
	}
	var r BackchannelRequest
	if b.open(ctx, cibaRequestPurpose, raw, &r) != nil {
		return BackchannelRequest{}, false, nil
	}
	return r, true, nil
}

// pending は要求がまだ判断も期限切れもしていないか。
func (b *Backchannel) pending(ctx context.Context, key string, r BackchannelRequest) (bool, error) {
	if !b.Clock.Now().Before(r.ExpiresAt) {
		return false, nil
	}
	_, decided, err := b.Cache.Get(ctx, cibaDecidedPrefix+key)
	return !decided, err
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Start は要求を預かり、auth_req_id を発行する（CIBA Core 7.3）。r.ExpiresAt が零か期限の上限より後なら上限にする。
// 本人宛ての未決の要求が CIBASlots 件あれば *ratelimit.ExceededError。
func (b *Backchannel) Start(ctx context.Context, r BackchannelRequest) (BackchannelStart, error) {
	authReqID, err := randomString()
	if err != nil {
		return BackchannelStart{}, err
	}
	if r.ID, err = randomID(); err != nil {
		return BackchannelStart{}, err
	}
	now := b.Clock.Now()
	ttl := b.ttl()
	if r.ExpiresAt.IsZero() || r.ExpiresAt.After(now.Add(ttl)) {
		r.ExpiresAt = now.Add(ttl)
	}
	if !r.ExpiresAt.After(now) {
		return BackchannelStart{}, errs.WithCode(errs.KindInvalid, "invalid_request", "requested_expiry")
	}
	r.CreatedAt = now
	if r.Mode == port.CIBAPing {
		r.AuthReqID = authReqID
	}
	key := digestKey(cibaPrefix, authReqID)
	keep := 2 * ttl
	if err := b.claimSlot(ctx, r, keep); err != nil {
		return BackchannelStart{}, err
	}
	if err := b.put(ctx, key, cibaRequestPurpose, r, keep); err != nil {
		return BackchannelStart{}, err
	}
	if err := b.Cache.Set(ctx, digestKey(cibaIDPrefix, r.ID), []byte(key), keep); err != nil {
		return BackchannelStart{}, err
	}
	return BackchannelStart{AuthReqID: authReqID, ExpiresIn: r.ExpiresAt.Sub(now), Interval: b.interval(), Request: r}, nil
}

func slotKey(realmID, userID string, i int64) string {
	return cibaSlotPrefix + realmID + ":" + userID + ":" + strconv.FormatInt(i, 10)
}

// claimSlot は本人の枠のうち空いているもの（無い・期限切れ・判断済みの要求を指す）を1つ取り、要求の公開 ID を置く。番号は Incr で
// 進めるので、同時の要求は別の枠を取る。
func (b *Backchannel) claimSlot(ctx context.Context, r BackchannelRequest, keep time.Duration) error {
	for range CIBASlots {
		n, err := b.Cache.Incr(ctx, cibaSeqPrefix+r.RealmID+":"+r.UserID, 24*time.Hour)
		if err != nil {
			return err
		}
		slot := slotKey(r.RealmID, r.UserID, n%CIBASlots)
		raw, ok, err := b.Cache.Get(ctx, slot)
		if err != nil {
			return err
		}
		if ok {
			if _, _, live, err := b.byID(ctx, string(raw)); err != nil {
				return err
			} else if live {
				continue
			}
		}
		return b.Cache.Set(ctx, slot, []byte(r.ID), keep)
	}
	return &ratelimit.ExceededError{RetryAfter: b.ttl()}
}

// byID は公開 ID の要求と、そのキー、まだ未決かを返す。
func (b *Backchannel) byID(ctx context.Context, id string) (BackchannelRequest, string, bool, error) {
	if id == "" || len(id) > 64 {
		return BackchannelRequest{}, "", false, nil
	}
	raw, ok, err := b.Cache.Get(ctx, digestKey(cibaIDPrefix, id))
	if err != nil || !ok {
		return BackchannelRequest{}, "", false, err
	}
	key := string(raw)
	r, ok, err := b.load(ctx, key)
	if err != nil || !ok || r.ID != id {
		return BackchannelRequest{}, "", false, err
	}
	live, err := b.pending(ctx, key, r)
	return r, key, live, err
}

// Attach は要求に本人の端末へのチャレンジを結び付ける（端末の応答から要求を引けるようにする）。
func (b *Backchannel) Attach(ctx context.Context, authReqID string, ch BackchannelChannel) error {
	key := digestKey(cibaPrefix, authReqID)
	r, ok, err := b.load(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBackchannelRequest
	}
	r.Channel = &ch
	keep := r.ExpiresAt.Add(b.ttl()).Sub(b.Clock.Now())
	if err := b.put(ctx, key, cibaRequestPurpose, r, keep); err != nil {
		return err
	}
	return b.Cache.Set(ctx, digestKey(cibaRefPrefix+ch.Method+":", ch.Ref), []byte(key), keep)
}

// ByRef は本人の端末へのチャレンジ（方式と参照）の、未決の要求を返す。無い・判断済み・期限切れなら ErrBackchannelRequest。
func (b *Backchannel) ByRef(ctx context.Context, realmID, method, ref string) (BackchannelRequest, error) {
	raw, ok, err := b.Cache.Get(ctx, digestKey(cibaRefPrefix+method+":", ref))
	if err != nil {
		return BackchannelRequest{}, err
	}
	if !ok {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	r, ok, err := b.load(ctx, string(raw))
	if err != nil {
		return BackchannelRequest{}, err
	}
	if !ok || r.RealmID != realmID || r.Channel == nil || r.Channel.Method != method || r.Channel.Ref != ref {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	live, err := b.pending(ctx, string(raw), r)
	if err != nil {
		return BackchannelRequest{}, err
	}
	if !live {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	return r, nil
}

// Pending は本人（userID は内部 ID）宛ての未決の要求を、新しい順に返す。
func (b *Backchannel) Pending(ctx context.Context, realmID, userID string) ([]BackchannelRequest, error) {
	var out []BackchannelRequest
	for i := range int64(CIBASlots) {
		raw, ok, err := b.Cache.Get(ctx, slotKey(realmID, userID, i))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		r, _, live, err := b.byID(ctx, string(raw))
		if err != nil {
			return nil, err
		}
		if live && r.RealmID == realmID && r.UserID == userID {
			out = append(out, r)
		}
	}
	// 新しい順（同じ時刻は ID の順）。
	slices.SortFunc(out, func(x, y BackchannelRequest) int {
		if c := y.CreatedAt.Compare(x.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(x.ID, y.ID)
	})
	return out, nil
}

// Get は本人宛ての未決の要求を公開 ID で返す。使えなければ ErrBackchannelRequest。
func (b *Backchannel) Get(ctx context.Context, realmID, userID, id string) (BackchannelRequest, error) {
	r, _, live, err := b.byID(ctx, id)
	if err != nil {
		return BackchannelRequest{}, err
	}
	if !live || r.RealmID != realmID || r.UserID != userID {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	return r, nil
}

// Decide は本人の承認（c が nil でない）か拒否を、公開 ID の要求に記録する。判断は要求ごとに最初の1回だけで、2回目からは
// ErrBackchannelRequest（本人の API と端末が同時に答えても1回）。c には本人とログインの系列を入れる（連携先・スコープは要求の
// ものにする）。c の本人が要求の本人でなければ ErrBackchannelRequest。
func (b *Backchannel) Decide(ctx context.Context, realmID, id string, c *Code) (BackchannelRequest, error) {
	r, key, live, err := b.byID(ctx, id)
	if err != nil {
		return BackchannelRequest{}, err
	}
	if !live || r.RealmID != realmID || (c != nil && c.UserID != r.UserID) {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	keep := r.ExpiresAt.Add(b.ttl()).Sub(b.Clock.Now())
	n, err := b.Cache.Incr(ctx, cibaDecidedPrefix+key, keep)
	if err != nil {
		return BackchannelRequest{}, err
	}
	if n != 1 {
		return BackchannelRequest{}, ErrBackchannelRequest
	}
	dec := backchannelDecision{Approved: c != nil}
	if c != nil {
		cc := *c
		cc.AuthRequest = AuthRequest{RealmID: r.RealmID, ClientID: r.ClientID, Scopes: r.Scopes, ExpiresAt: r.ExpiresAt}
		cc.GrantType = GrantTypeCIBA
		dec.Code = &cc
	}
	return r, b.put(ctx, cibaDecisionPrefix+key, cibaDecisionPurpose, dec, keep)
}

// Poll は連携先のポーリングに答える（CIBA Core 10、11）。承認されていれば、トークンの発行に使う内容を1回だけ返す。
// 知らない・別の連携先の auth_req_id は ErrInvalidGrant、期限切れは ErrDeviceExpired（expired_token）、間隔より速ければ
// ErrDeviceSlowDown（間隔を 5 秒延ばす）、未決なら ErrDevicePending（authorization_pending）、拒否なら ErrDeviceDenied
// （access_denied）。返す要求は、未決のときに端末の応答を確かめ直すのに使う。
func (b *Backchannel) Poll(ctx context.Context, realmID, clientID, authReqID string) (Code, BackchannelRequest, error) {
	if authReqID == "" || len(authReqID) > 256 {
		return Code{}, BackchannelRequest{}, ErrInvalidGrant
	}
	key := digestKey(cibaPrefix, authReqID)
	r, ok, err := b.load(ctx, key)
	if err != nil {
		return Code{}, BackchannelRequest{}, err
	}
	if !ok || r.RealmID != realmID || r.ClientID != clientID {
		return Code{}, BackchannelRequest{}, ErrInvalidGrant
	}
	now := b.Clock.Now()
	if !now.Before(r.ExpiresAt) {
		return Code{}, r, ErrDeviceExpired
	}
	if err := pacePoll(ctx, b.Cache, cibaPollPrefix+key, b.interval(), now, r.ExpiresAt); err != nil {
		return Code{}, r, err
	}
	return b.take(ctx, key, r)
}

// Retake は、Poll が未決を返した後に（端末の応答を記録してから）判断をもう一度確かめる。間隔は数えない。
func (b *Backchannel) Retake(ctx context.Context, realmID, clientID, authReqID string) (Code, error) {
	key := digestKey(cibaPrefix, authReqID)
	r, ok, err := b.load(ctx, key)
	if err != nil {
		return Code{}, err
	}
	if !ok || r.RealmID != realmID || r.ClientID != clientID {
		return Code{}, ErrInvalidGrant
	}
	c, _, err := b.take(ctx, key, r)
	return c, err
}

func (b *Backchannel) take(ctx context.Context, key string, r BackchannelRequest) (Code, BackchannelRequest, error) {
	raw, ok, err := b.Cache.Take(ctx, cibaDecisionPrefix+key)
	if err != nil {
		return Code{}, r, err
	}
	if !ok {
		return Code{}, r, ErrDevicePending
	}
	// 決まった要求はもう使えない（承認でも拒否でも1回だけ答える）。判断の印は期限まで残し、2回目の判断を拒む。
	if err := b.Cache.Delete(ctx, key); err != nil {
		return Code{}, r, err
	}
	_ = b.Cache.Delete(ctx, digestKey(cibaIDPrefix, r.ID))
	_ = b.Cache.Delete(ctx, cibaPollPrefix+key)
	if r.Channel != nil {
		_ = b.Cache.Delete(ctx, digestKey(cibaRefPrefix+r.Channel.Method+":", r.Channel.Ref))
	}
	var dec backchannelDecision
	if b.open(ctx, cibaDecisionPurpose, raw, &dec) != nil {
		return Code{}, r, ErrInvalidGrant
	}
	if !dec.Approved || dec.Code == nil {
		return Code{}, r, ErrDeviceDenied
	}
	if dec.Code.RealmID != r.RealmID || dec.Code.ClientID != r.ClientID || dec.Code.UserID != r.UserID {
		return Code{}, r, ErrInvalidGrant
	}
	return *dec.Code, r, nil
}

// ErrInvalidHint は id_token_hint が使えない（署名・発行者・連携先が違う、形が違う。理由は返さない）。
var ErrInvalidHint = errs.WithCode(errs.KindInvalid, "unknown_user_id", "invalid id_token_hint")

// HintSubject は id_token_hint の sub（ユーザーの公開 ID）を返す（CIBA Core 7.1）。この realm が clientID の連携先に発行した
// ID トークンだけを受け、期限は見ない（RP-Initiated Logout と同じ確かめ方。ADR 0094）。使えなければ ErrInvalidHint。
func (t *Tokens) HintSubject(ctx context.Context, tx port.Tx, realmID, clientID, hint string) (string, error) {
	if hint == "" || len(hint) > MaxIDTokenHint {
		return "", ErrInvalidHint
	}
	c, err := t.verifyHint(ctx, tx, realmID, hint)
	if errors.Is(err, ErrInvalidLogoutRequest) {
		return "", ErrInvalidHint
	}
	if err != nil {
		return "", err
	}
	if c.client != clientID {
		return "", ErrInvalidHint
	}
	return c.Sub, nil
}
