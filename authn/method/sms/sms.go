// Package sms は SMS・音声の OTP の認証方式（port.Authenticator。ADR 0104）。
//
// 番号にコードを送り、コードで確かめる。2要素目だけで、SP 800-63B の制限付きの認証器（restricted authenticator）として扱う
// （amr は sms か tel。AAL の上限 2）。送信は port.SMSSender（設定の sms_sender）が行い、コアがトランザクションの確定の後に呼ぶ。
//
// セキュリティ上重要なコード（13.2）。コードは crypto/rand で作り、フローの状態にはフローごとの鍵の HMAC だけを置く。比べるのは
// 定数時間。ユーザーと番号ごとに最後に送ったコードだけを有効にし、使ったら消す。送信はユーザー・番号・接続元ごとに数える。
package sms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Name は方式の名前。
const Name = "sms"

// 送る経路。
const (
	ChannelSMS   = "sms"
	ChannelVoice = "voice"
)

// Feature はフィーチャー sms_otp の宣言（既定オフ。ADR 0089、0104）。features/sms を import すると登録される。
var Feature = feature.Feature{Name: feature.SMSOTP, DataVersion: 1}

// MaxCredentials はユーザーごとの有効な番号の上限。
const MaxCredentials = 3

var (
	// e164RE は E.164 の番号（+ と、先頭が 0 でない 7〜15 桁）。
	e164RE    = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	countryRE = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)
)

// ErrLimit は有効な番号が上限に達しているか、同じ番号を登録済みであること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many sms credentials or the number is already enrolled")

// errInvalidNumber は番号の形の誤りか、許していない国番号・経路。
var errInvalidNumber = errs.WithCode(errs.KindInvalid, "invalid_phone_number", "sms: invalid phone number or channel")

// errNotConfigured は設定（Setup）を経ていない方式。fail-closed にする。
var errNotConfigured = errors.New("sms: method is not configured")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "sms: "+reason)
}

// Method は SMS・音声の OTP の port.Authenticator。ゼロ値は設定を経ていないので、使うと失敗する（fail-closed）。
type Method struct {
	rt *runtime
}

type runtime struct {
	opts   options
	sender port.SMSSender
	store  port.EphemeralStore
	blind  func(ctx context.Context, value string) (string, error)
	clock  clock.Clock
	user   *ratelimit.Limiter
	number *ratelimit.Limiter
	ip     *ratelimit.Limiter
}

var (
	_ port.Authenticator             = Method{}
	_ port.ConfigurableAuthenticator = Method{}
)

// Info は方式の宣言。所持の要素で、2要素目として AAL2 に届く（制限付きの認証器。SP 800-63B）。
func (Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.SMSOTP, Kind: port.FactorPossession, AMR: []string{"sms"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageSecondFactor}, DataVersion: 1}
}

// Setup は設定（methods.sms）と送信のポートを受け取る。sms_sender が無ければエラー（起動を止める）。
func (Method) Setup(_ context.Context, s port.MethodSetup) (port.Authenticator, error) {
	m, err := s.StringOptions()
	if err != nil {
		return nil, fmt.Errorf("options: %w", err)
	}
	o, err := parseOptions(m)
	if err != nil {
		return nil, err
	}
	if s.SMS == nil {
		return nil, errors.New("the sms_otp feature needs an sms_sender adapter")
	}
	if s.Ephemeral == nil || s.Blind == nil || s.Clock == nil {
		return nil, errors.New("sms: setup is incomplete")
	}
	lim := func(n int64) *ratelimit.Limiter {
		return &ratelimit.Limiter{Cache: s.Ephemeral, Clock: s.Clock, Window: o.Window, Limit: n}
	}
	return Method{rt: &runtime{opts: o, sender: s.SMS, store: s.Ephemeral, blind: s.Blind, clock: s.Clock,
		user: lim(o.PerUser), number: lim(o.PerNumber), ip: lim(o.PerIP)}}, nil
}

// data は方式固有のデータ（コアが暗号化して置く）。
type data struct {
	Phone   string `json:"phone"`
	Channel string `json:"channel"`
}

// state はフローの状態（コアが封をして置く）。コードは HMAC だけを持つ。
type state struct {
	// Nonce はこのコードの ID（最後に送ったコードかを確かめる）。
	Nonce string `json:"nonce"`
	Key   []byte `json:"key"`
	MAC   []byte `json:"mac"`
	// CredentialID はログインのときの認証情報（内部 ID）。登録では空で、Phone と Channel を持つ。
	CredentialID string    `json:"credential_id,omitempty"`
	Phone        string    `json:"phone,omitempty"`
	Channel      string    `json:"channel"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// challengeOutput は begin・enroll-begin の応答。番号は末尾の 2 桁だけを見せる。
type challengeOutput struct {
	Phone      string    `json:"phone"`
	Channel    string    `json:"channel"`
	Digits     int       `json:"digits"`
	ExpiresAt  time.Time `json:"expires_at"`
	Restricted bool      `json:"restricted"`
}

type beginInput struct {
	CredentialID string `json:"credential_id,omitempty"`
	Channel      string `json:"channel,omitempty"`
}

type enrollInput struct {
	PhoneNumber string `json:"phone_number"`
	Channel     string `json:"channel,omitempty"`
}

type codeInput struct {
	Code string `json:"code"`
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, errs.WithCode(errs.KindInvalid, "invalid_request", "sms: invalid payload")
	}
	return v, nil
}

// NormalizeNumber は番号から空白・ハイフン・括弧を除き、E.164 の形かを確かめる。
func NormalizeNumber(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '(', ')', '.':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	return s, e164RE.MatchString(s)
}

// Mask は番号の末尾の 2 桁だけを残す。
func Mask(phone string) string {
	if len(phone) < 4 {
		return "***"
	}
	return "+" + strings.Repeat("*", len(phone)-3) + phone[len(phone)-2:]
}

func (r *runtime) countryAllowed(phone string) bool {
	if len(r.opts.Countries) == 0 {
		return true
	}
	return slices.ContainsFunc(r.opts.Countries, func(c string) bool { return strings.HasPrefix(phone[1:], c) })
}

// channel は使う経路を決める。want（要求）があれば許したものに限り、無ければ preferred（登録の時の経路）、それも止めて
// いれば許した最初の経路。
func (r *runtime) channel(want, preferred string) (string, error) {
	if want != "" {
		if !slices.Contains(r.opts.Channels, want) {
			return "", errInvalidNumber
		}
		return want, nil
	}
	if slices.Contains(r.opts.Channels, preferred) {
		return preferred, nil
	}
	return r.opts.Channels[0], nil
}

// allowSend は送信の回数を数える：送り直しの間隔（ユーザーごと）、ユーザー・番号・接続元ごとの窓の中の数。
func (r *runtime) allowSend(ctx context.Context, userID, phone, ip string) error {
	n, err := r.store.Incr(ctx, "resend:"+userID, r.opts.ResendInterval)
	if err != nil {
		return err
	}
	if n > 1 {
		return &ratelimit.ExceededError{RetryAfter: r.opts.ResendInterval, First: n == 2}
	}
	if err := r.user.Allow(ctx, "send:user:"+userID); err != nil {
		return err
	}
	key, err := r.blind(ctx, phone)
	if err != nil {
		return err
	}
	if err := r.number.Allow(ctx, "send:number:"+key); err != nil {
		return err
	}
	return r.ip.Allow(ctx, "send:ip:"+ratelimit.Bucket(ip))
}

// newCode はコードと、状態に置く HMAC を作る。
func (r *runtime) newCode() (code string, st state, err error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(r.opts.Digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", st, err
	}
	code = fmt.Sprintf("%0*d", r.opts.Digits, n)
	nonce := make([]byte, 16)
	st.Key = make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", st, err
	}
	if _, err := rand.Read(st.Key); err != nil {
		return "", st, err
	}
	st.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	st.MAC = mac(st.Key, code)
	return code, st, nil
}

func mac(key []byte, code string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(code))
	return m.Sum(nil)
}

// latestKey は、ユーザーと番号（ログインは認証情報、登録は "enroll"）ごとの最後に送ったコードのキー。
func latestKey(userID, target string) string { return "latest:" + userID + ":" + target }

// challenge は送信の準備をして、応答・状態・送信を返す。
func (r *runtime) challenge(ctx context.Context, env port.MethodEnv, st state, target, phone, credentialPublicID string) (port.MethodChallenge, error) {
	if err := r.allowSend(ctx, env.UserID, phone, env.ClientIP); err != nil {
		return port.MethodChallenge{}, err
	}
	code, cs, err := r.newCode()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	cs.CredentialID, cs.Phone, cs.Channel = st.CredentialID, st.Phone, st.Channel
	cs.ExpiresAt = env.Now.Add(r.opts.CodeTTL)
	raw, err := json.Marshal(cs) // #nosec G117 -- 状態はコアが封をしてから置く（コードは HMAC だけ）
	if err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(challengeOutput{Phone: Mask(phone), Channel: cs.Channel, Digits: r.opts.Digits, ExpiresAt: cs.ExpiresAt,
		Restricted: true})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	key := latestKey(env.UserID, target)
	msg := port.SMSMessage{To: phone, Channel: cs.Channel, Code: code, ExpiresAt: cs.ExpiresAt}
	details := map[string]any{"channel": cs.Channel}
	if credentialPublicID != "" {
		details["credential_id"] = credentialPublicID
	} else {
		details["purpose"] = "enroll"
	}
	return port.MethodChallenge{Payload: out, State: raw,
		Deliver: func(ctx context.Context) error {
			// 送る前に「最後のコード」を替える（前に送ったコードは、このコードを送った時点で通らない）。
			if err := r.store.Set(ctx, key, []byte(cs.Nonce), r.opts.CodeTTL); err != nil {
				return err
			}
			return r.sender.Send(ctx, msg)
		},
		Events: []port.MethodEvent{{Type: "code_sent", UserID: env.UserID, Details: details}},
	}, nil
}

// verify はコードを確かめ、最後に送ったコードなら消費する（1 回限り）。
func (r *runtime) verify(ctx context.Context, env port.MethodEnv, st state, target string, in json.RawMessage) error {
	req, err := decode[codeInput](in)
	if err != nil {
		return rejected("invalid payload")
	}
	if len(st.MAC) == 0 || len(st.Key) == 0 || st.Nonce == "" {
		return errors.New("sms: invalid flow state")
	}
	if !env.Now.Before(st.ExpiresAt) {
		return rejected("code expired")
	}
	code := strings.TrimSpace(req.Code)
	ok := len(code) == r.opts.Digits && subtle.ConstantTimeCompare(mac(st.Key, code), st.MAC) == 1
	if !ok {
		return rejected("code mismatch")
	}
	key := latestKey(env.UserID, target)
	cur, found, err := r.store.Get(ctx, key)
	if err != nil {
		return err
	}
	if !found || subtle.ConstantTimeCompare(cur, []byte(st.Nonce)) != 1 {
		return rejected("code superseded or used")
	}
	// 取り出して消す（同時の照合でも1つしか通らない）。
	taken, found, err := r.store.Take(ctx, key)
	if err != nil {
		return err
	}
	if !found || subtle.ConstantTimeCompare(taken, []byte(st.Nonce)) != 1 {
		return rejected("code superseded or used")
	}
	return nil
}

func (m Method) runtime() (*runtime, error) {
	if m.rt == nil {
		return nil, errNotConfigured
	}
	return m.rt, nil
}

func readData(c port.MethodCredential) (data, error) {
	var d data
	if err := json.Unmarshal(c.Data, &d); err != nil || d.Phone == "" {
		return d, fmt.Errorf("sms: credential data: %v", err)
	}
	return d, nil
}

// Begin は2要素目のコードを送る。payload の credential_id（crd_…）で番号を選べる（無ければ最初の番号）。
func (m Method) Begin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if env.UserID == "" {
		return port.MethodChallenge{}, rejected("first factor is not supported")
	}
	req, err := decode[beginInput](in.Payload)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	i := 0
	if req.CredentialID != "" {
		i = slices.IndexFunc(cs, func(c port.MethodCredential) bool { return c.PublicID == req.CredentialID })
	}
	if len(cs) == 0 || i < 0 {
		return port.MethodChallenge{}, errs.New(errs.KindNotFound, "sms")
	}
	c := cs[i]
	d, err := readData(c)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	ch, err := r.channel(req.Channel, d.Channel)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if !r.countryAllowed(d.Phone) {
		// 許可リストを後から狭めた番号には送らない。
		return port.MethodChallenge{}, errInvalidNumber
	}
	return r.challenge(ctx, env, state{CredentialID: c.ID, Channel: ch}, c.ID, d.Phone, c.PublicID)
}

// Complete はコードを確かめる。amr は経路で決まる（SMS は sms、音声は tel）。
func (m Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodResult{}, err
	}
	if env.UserID == "" {
		return port.MethodResult{}, rejected("first factor is not supported")
	}
	var st state
	if err := json.Unmarshal(in.State, &st); err != nil || st.CredentialID == "" {
		return port.MethodResult{}, fmt.Errorf("sms: flow state: %v", err)
	}
	if err := r.verify(ctx, env, st, st.CredentialID, in.Payload); err != nil {
		return port.MethodResult{}, err
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodResult{}, err
	}
	i := slices.IndexFunc(cs, func(c port.MethodCredential) bool { return c.ID == st.CredentialID })
	if i < 0 {
		return port.MethodResult{}, rejected("credential revoked")
	}
	return port.MethodResult{Credential: cs[i], AMR: []string{amrOf(st.Channel)}}, nil
}

func amrOf(channel string) string {
	if channel == ChannelVoice {
		return "tel"
	}
	return "sms"
}

// EnrollBegin は番号を受け取り、確認のコードを送る。
func (m Method) EnrollBegin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	req, err := decode[enrollInput](in.Payload)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	phone, ok := NormalizeNumber(req.PhoneNumber)
	if !ok || !r.countryAllowed(phone) {
		return port.MethodChallenge{}, errInvalidNumber
	}
	ch, err := r.channel(req.Channel, "")
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if err := checkLimit(ctx, env, phone); err != nil {
		return port.MethodChallenge{}, err
	}
	return r.challenge(ctx, env, state{Phone: phone, Channel: ch}, "enroll", phone, "")
}

// EnrollComplete はコードで番号を確かめて登録する。
func (m Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	var st state
	if err := json.Unmarshal(in.State, &st); err != nil || st.Phone == "" {
		return port.MethodEnrollment{}, fmt.Errorf("sms: enrollment state: %v", err)
	}
	if err := r.verify(ctx, env, st, "enroll", in.Payload); err != nil {
		return port.MethodEnrollment{}, err
	}
	if err := checkLimit(ctx, env, st.Phone); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := json.Marshal(data{Phone: st.Phone, Channel: st.Channel})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, "", raw)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	out, err := json.Marshal(map[string]any{"phone": Mask(st.Phone), "channel": st.Channel, "restricted": true})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	return port.MethodEnrollment{Credential: c, Payload: out}, nil
}

// Revoke は方式の外に片付けるものが無いので何もしない。
func (Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

// checkLimit は番号の数の上限と、同じ番号の重複を確かめる。
func checkLimit(ctx context.Context, env port.MethodEnv, phone string) error {
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return err
	}
	if len(cs) >= MaxCredentials {
		return ErrLimit
	}
	for _, c := range cs {
		d, err := readData(c)
		if err != nil {
			return err
		}
		if d.Phone == phone {
			return ErrLimit
		}
	}
	return nil
}
