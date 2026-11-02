// Package push はプッシュ通知の承認（番号の照合付き）の認証方式（port.Authenticator。ADR 0104）。
//
// 本人の端末は自分で作った鍵の組（ECDSA P-256 か Ed25519）の公開鍵を登録する。ログインの2要素目では、IAM が 2 桁の番号を
// ブラウザにだけ返し、端末にはチャレンジの ID だけをプッシュで送る。端末は利用者が入れた番号と承認・拒否に署名して
// POST /v1/login/methods/push:callback に送り、ブラウザは complete を呼び直して結果を受け取る（届くまで 202）。
//
// CIBA（ADR 0114）では、番号の代わりに連携先の名前と binding_message を持つチャレンジを送る（BeginBackchannel）。端末は
// context で中身を取り、承認は番号 "00" に署名する（ログインのチャレンジの番号は 10〜99 なので通らない）。
//
// セキュリティ上重要なコード（13.2）。チャレンジは1回だけ応答でき、本人の・送った端末の署名だけを受ける。番号が違えば拒否として
// 扱う。チャレンジの数と拒否の数をユーザーごとに数え、プッシュ疲れ（MFA fatigue）による誤承認を防ぐ。
package push

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Name は方式の名前。
const Name = "push"

// Feature はフィーチャー push_auth の宣言（既定オフ。ADR 0089、0104）。features/push を import すると登録される。
var Feature = feature.Feature{Name: feature.PushAuth, DataVersion: 1}

// MaxCredentials はユーザーごとの有効な端末の上限。
const MaxCredentials = 5

// PollInterval は、ブラウザが complete を呼び直すまでの秒数の目安。
const PollInterval = 2

// tokenSkew は宛先の更新の時刻の許容幅。
const tokenSkew = 5 * time.Minute

// 応答の結果。
const (
	resultApproved       = "approved"
	resultDenied         = "denied"
	resultNumberMismatch = "number_mismatch"
)

var (
	platformRE = regexp.MustCompile(`^[a-z0-9_]{0,16}$`)
	deviceRE   = regexp.MustCompile(`^dev_[A-Za-z0-9_-]{22}$`)
	numberRE   = regexp.MustCompile(`^[1-9][0-9]$`)
)

// ErrLimit は有効な端末が上限に達していること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many push devices")

var errInvalid = errs.WithCode(errs.KindInvalid, "invalid_request", "push: invalid request")

var errNotConfigured = errors.New("push: method is not configured")

func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "push: "+reason)
}

// Method はプッシュの承認の port.Authenticator。ゼロ値は設定を経ていないので、使うと失敗する（fail-closed）。
type Method struct {
	rt *runtime
}

type runtime struct {
	opts   options
	sender port.PushSender
	store  port.EphemeralStore
	clock  clock.Clock
	user   *ratelimit.Limiter
	ip     *ratelimit.Limiter
}

var (
	_ port.Authenticator             = Method{}
	_ port.ConfigurableAuthenticator = Method{}
	_ port.CallbackAuthenticator     = Method{}
	_ port.BackchannelAuthenticator  = Method{}
)

// Info は方式の宣言。所持の要素（端末の鍵。ハードウェアにあるかは確かめないので swk）で、2要素目として AAL2 に届く。
// 応答は端末から届く（OutOfBand）。
func (Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.PushAuth, Kind: port.FactorPossession, AMR: []string{"swk"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageSecondFactor}, DataVersion: 1, OutOfBand: true}
}

// Setup は設定（methods.push）と送信のポートを受け取る。push_sender が無ければエラー（起動を止める）。
func (Method) Setup(_ context.Context, s port.MethodSetup) (port.Authenticator, error) {
	m, err := s.StringOptions()
	if err != nil {
		return nil, fmt.Errorf("options: %w", err)
	}
	o, err := parseOptions(m)
	if err != nil {
		return nil, err
	}
	if s.Push == nil {
		return nil, errors.New("the push_auth feature needs a push_sender adapter")
	}
	if s.Ephemeral == nil || s.Clock == nil {
		return nil, errors.New("push: setup is incomplete")
	}
	lim := func(n int64) *ratelimit.Limiter {
		return &ratelimit.Limiter{Cache: s.Ephemeral, Clock: s.Clock, Window: o.Window, Limit: n}
	}
	return Method{rt: &runtime{opts: o, sender: s.Push, store: s.Ephemeral, clock: s.Clock, user: lim(o.PerUser), ip: lim(o.PerIP)}}, nil
}

func (m Method) runtime() (*runtime, error) {
	if m.rt == nil {
		return nil, errNotConfigured
	}
	return m.rt, nil
}

// data は方式固有のデータ（コアが暗号化して置く）。宛先（Token）も暗号化する。
type data struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Alg       string `json:"alg"`
	Token     string `json:"token"`
	Platform  string `json:"platform,omitempty"`
	Name      string `json:"name,omitempty"`
	// TokenTime は最後に宛先を変えた要求の時刻（UNIX 秒）。これより古い要求は受けない。
	TokenTime int64 `json:"token_time,omitempty"`
}

// challenge は方式の EphemeralStore に置くチャレンジ（番号の照合と、応答できる端末）。
type challenge struct {
	UserID    string    `json:"user_id"`
	Devices   []string  `json:"devices"` // 認証情報の内部 ID
	Number    string    `json:"number"`
	ExpiresAt time.Time `json:"expires_at"`
	// Backchannel は CIBA の要求のチャレンジ（ADR 0114）。番号の照合は無く（Number は空）、端末に見せる中身を持つ。
	Backchannel *backchannel `json:"backchannel,omitempty"`
}

// backchannel は CIBA の要求のうち、端末に見せるもの（context で返す）。
type backchannel struct {
	Client         string   `json:"client"`
	BindingMessage string   `json:"binding_message,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

// backchannelNumber は、CIBA のチャレンジの承認で署名する番号（ログインのチャレンジの番号は 10〜99 なので、これでは通らない）。
const backchannelNumber = "00"

// response は端末の応答（complete が取り出す）。
type response struct {
	UserID       string `json:"user_id"`
	Result       string `json:"result"`
	CredentialID string `json:"credential_id"`
}

// loginState と enrollState はフローの状態（コアが封をして置く）。
type loginState struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type enrollState struct {
	Nonce string `json:"nonce"`
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, errInvalid
	}
	return v, nil
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readData(c port.MethodCredential) (data, error) {
	var d data
	if err := json.Unmarshal(c.Data, &d); err != nil || d.DeviceID == "" || d.PublicKey == "" {
		return d, fmt.Errorf("push: credential data: %v", err)
	}
	return d, nil
}

// Begin は本人の全端末にチャレンジを送り、照合する番号をブラウザにだけ返す。
func (m Method) Begin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return port.MethodChallenge{}, err
	}
	ch := challenge{Number: strconv.FormatInt(n.Int64()+10, 10), ExpiresAt: env.Now.Add(r.opts.ChallengeTTL)}
	return r.begin(ctx, env, ch, true)
}

// BeginBackchannel は CIBA の要求のチャレンジを本人の全端末に送る（ADR 0114）。番号の照合の代わりに、連携先の名前と
// binding_message を端末が context で取って見せる。期限は要求の期限（ただし 10 分まで）。接続元は連携先のサーバーなので、
// 接続元ごとの数は数えない（ユーザーごとの数と、拒否が続いたときの停止は数える）。
func (m Method) BeginBackchannel(ctx context.Context, env port.MethodEnv, req port.BackchannelRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	exp := req.ExpiresAt
	if limit := env.Now.Add(maxBackchannelTTL); exp.After(limit) {
		exp = limit
	}
	if !exp.After(env.Now) || !validName(req.ClientName) || !validName(req.BindingMessage) {
		return port.MethodChallenge{}, errInvalid
	}
	ch := challenge{ExpiresAt: exp, Backchannel: &backchannel{Client: req.ClientName, BindingMessage: req.BindingMessage, Scopes: slices.Clone(req.Scopes)}}
	return r.begin(ctx, env, ch, false)
}

// maxBackchannelTTL は CIBA のチャレンジの期限の上限。
const maxBackchannelTTL = 10 * time.Minute

// begin は本人の全端末にチャレンジ ch を送るチャレンジを作る。perIP なら接続元ごとにも数える。
func (r *runtime) begin(ctx context.Context, env port.MethodEnv, ch challenge, perIP bool) (port.MethodChallenge, error) {
	if env.UserID == "" {
		return port.MethodChallenge{}, rejected("first factor is not supported")
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if len(cs) == 0 {
		return port.MethodChallenge{}, errs.New(errs.KindNotFound, "push")
	}
	// 拒否が続いた後はしばらく送らない（プッシュ疲れへの備え）。
	if b, ok, err := r.store.Get(ctx, denyKey(env.UserID)); err != nil {
		return port.MethodChallenge{}, err
	} else if ok {
		if n, _ := strconv.ParseInt(string(b), 10, 64); n >= r.opts.DenyLimit {
			return port.MethodChallenge{}, &ratelimit.ExceededError{RetryAfter: r.opts.DenyWindow}
		}
	}
	if err := r.user.Allow(ctx, "challenge:user:"+env.UserID); err != nil {
		return port.MethodChallenge{}, err
	}
	if perIP {
		if err := r.ip.Allow(ctx, "challenge:ip:"+ratelimit.Bucket(env.ClientIP)); err != nil {
			return port.MethodChallenge{}, err
		}
	}
	id, err := random(16)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	ch.UserID = env.UserID
	msgs := make([]port.PushMessage, 0, len(cs))
	for _, c := range cs {
		d, err := readData(c)
		if err != nil {
			return port.MethodChallenge{}, err
		}
		ch.Devices = append(ch.Devices, c.ID)
		msgs = append(msgs, port.PushMessage{Token: d.Token, Platform: d.Platform, ChallengeID: id, DeviceID: d.DeviceID, ExpiresAt: ch.ExpiresAt})
	}
	raw, err := json.Marshal(ch)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	state, err := json.Marshal(loginState{ChallengeID: id, ExpiresAt: ch.ExpiresAt})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	payload := map[string]any{"expires_at": ch.ExpiresAt, "interval": PollInterval, "devices": len(msgs)}
	var ref string
	if ch.Backchannel == nil {
		payload["number"] = ch.Number
	} else {
		ref = id
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	ttl := ch.ExpiresAt.Sub(env.Now)
	return port.MethodChallenge{Payload: out, State: state, Ref: ref,
		Deliver: func(ctx context.Context) error {
			if err := r.store.Set(ctx, "chal:"+id, raw, ttl); err != nil {
				return err
			}
			// 1 台でも届けばよい（ほかの端末の失敗はログに残さない。宛先が古いことはよくある）。
			var errsAll []error
			for _, msg := range msgs {
				if err := r.sender.Send(ctx, msg); err != nil {
					errsAll = append(errsAll, err)
				}
			}
			if len(errsAll) == len(msgs) {
				_ = r.store.Delete(ctx, "chal:"+id)
				return errors.Join(errsAll...)
			}
			return nil
		},
		Events: []port.MethodEvent{{Type: "challenge_sent", UserID: env.UserID, Details: map[string]any{"devices": len(msgs), "kind": ch.kind()}}},
	}, nil
}

// kind はチャレンジの種類（login か backchannel）。
func (ch challenge) kind() string {
	if ch.Backchannel != nil {
		return "backchannel"
	}
	return "login"
}

func denyKey(userID string) string { return "deny:" + userID }

// Complete は端末の応答を取り出す。届いていなければ port.ErrMethodPending（期限の後は失敗）。
func (m Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodResult{}, err
	}
	if env.UserID == "" {
		return port.MethodResult{}, rejected("first factor is not supported")
	}
	var st loginState
	if err := json.Unmarshal(in.State, &st); err != nil || st.ChallengeID == "" {
		return port.MethodResult{}, fmt.Errorf("push: flow state: %v", err)
	}
	b, ok, err := r.store.Take(ctx, "resp:"+st.ChallengeID)
	if err != nil {
		return port.MethodResult{}, err
	}
	if !ok {
		if env.Now.Before(st.ExpiresAt) {
			return port.MethodResult{}, port.ErrMethodPending
		}
		return port.MethodResult{}, rejected("challenge expired")
	}
	var resp response
	if err := json.Unmarshal(b, &resp); err != nil {
		return port.MethodResult{}, err
	}
	if resp.UserID != env.UserID || resp.Result != resultApproved {
		return port.MethodResult{}, rejected("challenge " + resp.Result)
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodResult{}, err
	}
	i := slices.IndexFunc(cs, func(c port.MethodCredential) bool { return c.ID == resp.CredentialID })
	if i < 0 {
		return port.MethodResult{}, rejected("device revoked")
	}
	return port.MethodResult{Credential: cs[i]}, nil
}

// EnrollBegin は鍵を持つことの証明に署名させる値を返す。
func (m Method) EnrollBegin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if _, err := m.runtime(); err != nil {
		return port.MethodChallenge{}, err
	}
	if err := checkLimit(ctx, env); err != nil {
		return port.MethodChallenge{}, err
	}
	nonce, err := random(32)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	state, err := json.Marshal(enrollState{Nonce: nonce})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(map[string]any{"challenge": nonce, "algorithms": []string{AlgES256, AlgEd25519}})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return port.MethodChallenge{Payload: out, State: state}, nil
}

type enrollInput struct {
	PublicKey string `json:"public_key"`
	PushToken string `json:"push_token"`
	Platform  string `json:"platform,omitempty"`
	Name      string `json:"name,omitempty"`
	Signature string `json:"signature"`
}

// validToken は端末の宛先の形（印字できる ASCII で 4096 文字まで）。
func validToken(t string) bool {
	if t == "" || len(t) > 4096 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

func validName(n string) bool {
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) > 64 {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// EnrollComplete は公開鍵と、登録の値への署名を確かめて端末を登録する。
func (m Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	if _, err := m.runtime(); err != nil {
		return port.MethodEnrollment{}, err
	}
	var st enrollState
	if err := json.Unmarshal(in.State, &st); err != nil || st.Nonce == "" {
		return port.MethodEnrollment{}, fmt.Errorf("push: enrollment state: %v", err)
	}
	req, err := decode[enrollInput](in.Payload)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	if !validToken(req.PushToken) || !platformRE.MatchString(req.Platform) || !validName(req.Name) {
		return port.MethodEnrollment{}, errInvalid
	}
	key, alg, err := ParsePublicKey(req.PublicKey)
	if err != nil {
		return port.MethodEnrollment{}, errInvalid
	}
	msg, ok := Message("enroll", st.Nonce, req.PublicKey, TokenHash(req.PushToken))
	if !ok || !Verify(key, msg, req.Signature) {
		return port.MethodEnrollment{}, rejected("enrollment signature")
	}
	if err := checkLimit(ctx, env); err != nil {
		return port.MethodEnrollment{}, err
	}
	rnd, err := random(16)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	d := data{DeviceID: "dev_" + rnd, PublicKey: req.PublicKey, Alg: alg, Token: req.PushToken, Platform: req.Platform, Name: req.Name,
		TokenTime: env.Now.Unix()}
	raw, err := json.Marshal(d)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, d.DeviceID, raw)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	out, err := json.Marshal(map[string]any{"device_id": d.DeviceID})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	return port.MethodEnrollment{Credential: c, Payload: out}, nil
}

// Revoke は方式の外に片付けるものが無いので何もしない（端末の鍵は端末が消す）。
func (Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

func checkLimit(ctx context.Context, env port.MethodEnv) error {
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return err
	}
	if len(cs) >= MaxCredentials {
		return ErrLimit
	}
	return nil
}

// callbackInput は端末からの要求。Action が respond なら応答、token なら宛先の更新。
type callbackInput struct {
	Action      string `json:"action"`
	DeviceID    string `json:"device_id"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Decision    string `json:"decision,omitempty"`
	Number      string `json:"number,omitempty"`
	PushToken   string `json:"push_token,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
	Signature   string `json:"signature"`
}

// Callback は端末の署名を確かめ、チャレンジへの応答か宛先の更新を受ける。
func (m Method) Callback(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodCallbackResult, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	req, err := decode[callbackInput](in.Payload)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	if !deviceRE.MatchString(req.DeviceID) {
		return port.MethodCallbackResult{}, errInvalid
	}
	switch req.Action {
	case "respond":
		return r.respond(ctx, env, req)
	case "token":
		return r.updateToken(ctx, env, req)
	case "context":
		return r.context(ctx, env, req)
	}
	return port.MethodCallbackResult{}, errInvalid
}

// device は端末の ID で認証情報を引き、署名を確かめる。
func device(ctx context.Context, env port.MethodEnv, deviceID, msg, sig string) (port.MethodCredential, data, error) {
	c, err := env.Credentials.FindByLookup(ctx, deviceID)
	if err != nil {
		return c, data{}, err
	}
	d, err := readData(c)
	if err != nil {
		return c, d, err
	}
	key, _, err := ParsePublicKey(d.PublicKey)
	if err != nil {
		return c, d, err
	}
	if d.DeviceID != deviceID || !Verify(key, msg, sig) {
		return c, d, rejected("signature")
	}
	return c, d, nil
}

func (r *runtime) respond(ctx context.Context, env port.MethodEnv, req callbackInput) (port.MethodCallbackResult, error) {
	if req.Decision != "approve" && req.Decision != "deny" {
		return port.MethodCallbackResult{}, errInvalid
	}
	// 拒否には番号が要らない。無ければ "00" に署名する（署名する文字列の形を保つ）。
	number := req.Number
	if req.Decision == "deny" && number == "" {
		number = "00"
	}
	// "00" は拒否と、CIBA のチャレンジの承認（ADR 0114）。ログインのチャレンジの承認では番号の違いになる。
	if !numberRE.MatchString(number) && number != backchannelNumber {
		return port.MethodCallbackResult{}, errInvalid
	}
	msg, ok := Message("respond", req.ChallengeID, req.DeviceID, req.Decision, number)
	if !ok {
		return port.MethodCallbackResult{}, errInvalid
	}
	c, _, err := device(ctx, env, req.DeviceID, msg, req.Signature)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	// 本人の・送った端末か確かめてから取り出す（他人の端末でチャレンジを消させない）。
	b, ok, err := r.store.Get(ctx, "chal:"+req.ChallengeID)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	if !ok {
		return port.MethodCallbackResult{}, rejected("unknown or answered challenge")
	}
	var ch challenge
	if err := json.Unmarshal(b, &ch); err != nil {
		return port.MethodCallbackResult{}, err
	}
	if ch.UserID != c.UserID || !slices.Contains(ch.Devices, c.ID) || !env.Now.Before(ch.ExpiresAt) {
		return port.MethodCallbackResult{}, rejected("challenge for another user or device, or expired")
	}
	if _, ok, err := r.store.Take(ctx, "chal:"+req.ChallengeID); err != nil {
		return port.MethodCallbackResult{}, err
	} else if !ok {
		return port.MethodCallbackResult{}, rejected("challenge already answered")
	}
	result := resultDenied
	if req.Decision == "approve" {
		result = resultApproved
		want := ch.Number
		if ch.Backchannel != nil {
			want = backchannelNumber
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(number), []byte(want)) != 1 {
			result = resultNumberMismatch
		}
	}
	raw, err := json.Marshal(response{UserID: ch.UserID, Result: result, CredentialID: c.ID})
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	// 結果はブラウザの complete が取り出すまで、チャレンジの期限の後も少し残す。
	if err := r.store.Set(ctx, "resp:"+req.ChallengeID, raw, ch.ExpiresAt.Sub(env.Now)+time.Minute); err != nil {
		return port.MethodCallbackResult{}, err
	}
	ev := port.MethodEvent{Type: "approved", UserID: ch.UserID, Details: map[string]any{"credential_id": c.PublicID}}
	if result != resultApproved {
		if _, err := r.store.Incr(ctx, denyKey(ch.UserID), r.opts.DenyWindow); err != nil {
			return port.MethodCallbackResult{}, err
		}
		ev = port.MethodEvent{Type: "denied", UserID: ch.UserID, Failure: true, Details: map[string]any{"credential_id": c.PublicID, "reason": result}}
	}
	status := resultApproved
	if result != resultApproved {
		status = resultDenied
	}
	out, err := json.Marshal(map[string]any{"result": status})
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	res := port.MethodCallbackResult{Payload: out, Events: []port.MethodEvent{ev}}
	if ch.Backchannel != nil {
		res.Ref = req.ChallengeID
	}
	return res, nil
}

// context は、本人の・送った端末に、チャレンジの中身（種類と期限、CIBA なら連携先の名前・binding_message・スコープ）を返す
// （ADR 0114）。消さない。ログインのチャレンジの番号は返さない（端末に番号を見せると照合の意味が無い）。
func (r *runtime) context(ctx context.Context, env port.MethodEnv, req callbackInput) (port.MethodCallbackResult, error) {
	msg, ok := Message("context", req.ChallengeID, req.DeviceID)
	if !ok {
		return port.MethodCallbackResult{}, errInvalid
	}
	c, _, err := device(ctx, env, req.DeviceID, msg, req.Signature)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	b, ok, err := r.store.Get(ctx, "chal:"+req.ChallengeID)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	if !ok {
		return port.MethodCallbackResult{}, rejected("unknown or answered challenge")
	}
	var ch challenge
	if err := json.Unmarshal(b, &ch); err != nil {
		return port.MethodCallbackResult{}, err
	}
	if ch.UserID != c.UserID || !slices.Contains(ch.Devices, c.ID) || !env.Now.Before(ch.ExpiresAt) {
		return port.MethodCallbackResult{}, rejected("challenge for another user or device, or expired")
	}
	v := map[string]any{"kind": ch.kind(), "expires_at": ch.ExpiresAt}
	if bc := ch.Backchannel; bc != nil {
		v["client"] = bc.Client
		v["scopes"] = bc.Scopes
		if bc.BindingMessage != "" {
			v["binding_message"] = bc.BindingMessage
		}
	}
	out, err := json.Marshal(v)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	return port.MethodCallbackResult{Payload: out}, nil
}

func (r *runtime) updateToken(ctx context.Context, env port.MethodEnv, req callbackInput) (port.MethodCallbackResult, error) {
	if !validToken(req.PushToken) || req.Timestamp <= 0 {
		return port.MethodCallbackResult{}, errInvalid
	}
	msg, ok := Message("token", req.DeviceID, TokenHash(req.PushToken), strconv.FormatInt(req.Timestamp, 10))
	if !ok {
		return port.MethodCallbackResult{}, errInvalid
	}
	c, d, err := device(ctx, env, req.DeviceID, msg, req.Signature)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	at := time.Unix(req.Timestamp, 0)
	if req.Timestamp <= d.TokenTime || at.Before(env.Now.Add(-tokenSkew)) || at.After(env.Now.Add(tokenSkew)) {
		return port.MethodCallbackResult{}, rejected("stale token update")
	}
	d.Token, d.TokenTime = req.PushToken, req.Timestamp
	raw, err := json.Marshal(d)
	if err != nil {
		return port.MethodCallbackResult{}, err
	}
	if _, err := env.Credentials.Update(ctx, c, raw); err != nil {
		if errors.Is(err, errs.Conflict) {
			return port.MethodCallbackResult{}, rejected("concurrent update")
		}
		return port.MethodCallbackResult{}, err
	}
	return port.MethodCallbackResult{Payload: json.RawMessage(`{"result":"updated"}`),
		Events: []port.MethodEvent{{Type: "token_updated", UserID: c.UserID, Details: map[string]any{"credential_id": c.PublicID}}}}, nil
}
