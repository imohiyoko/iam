package hotp

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = "hotp"

// Feature はフィーチャー hotp の宣言（既定オフ。ADR 0089）。features/hotp を import すると登録される。
var Feature = feature.Feature{Name: feature.HOTP, DataVersion: 1}

// MaxCredentials はユーザーごとの有効な HOTP の上限（照合で試す数を抑える）。
const MaxCredentials = 5

// ErrLimit は有効な HOTP が上限に達していること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many hotp credentials")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "hotp: "+reason)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Method は HOTP の port.Authenticator。
type Method struct{}

var _ port.Authenticator = Method{}

// Info は方式の宣言。所持の要素で、2要素目として AAL2 に届く（SP 800-63B の単要素 OTP デバイス）。
func (Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.HOTP, Kind: port.FactorPossession, AMR: []string{"otp"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageSecondFactor}, DataVersion: 1}
}

// data は方式固有のデータ（コアが暗号化して置く）。
type data struct {
	Secret []byte `json:"secret"`
	// Counter は次に期待するカウンター。これより前のカウンターのコードは拒否する。
	Counter uint64 `json:"counter"`
	Digits  int    `json:"digits"`
}

// codeInput はログインと登録の確認の入力。NextCode があれば再同期として扱う。
type codeInput struct {
	Code     string `json:"code"`
	NextCode string `json:"next_code,omitempty"`
}

func normalize(code string) string { return strings.ReplaceAll(strings.TrimSpace(code), " ", "") }

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, rejected("invalid payload")
	}
	return v, nil
}

// Begin は2要素目の確認を始める。HOTP はチャレンジを持たないので、有効な HOTP があることだけを確かめる。
func (Method) Begin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if env.UserID == "" {
		return port.MethodChallenge{}, rejected("first factor is not supported")
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if len(cs) == 0 {
		return port.MethodChallenge{}, errs.New(errs.KindNotFound, "hotp")
	}
	return port.MethodChallenge{}, nil
}

// Complete はコードを確かめ、受け入れたカウンターの次を記録する。同じコードを同時に使っても、記録の比較で1つしか通らない。
func (Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	if env.UserID == "" {
		return port.MethodResult{}, rejected("first factor is not supported")
	}
	req, err := decode[codeInput](in.Payload)
	if err != nil {
		return port.MethodResult{}, err
	}
	code, next := normalize(req.Code), normalize(req.NextCode)
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodResult{}, err
	}
	for _, c := range cs {
		var d data
		if err := json.Unmarshal(c.Data, &d); err != nil {
			return port.MethodResult{}, fmt.Errorf("hotp: data: %w", err)
		}
		var used uint64
		var ok bool
		if next != "" {
			used, ok = Resync(d.Secret, code, next, d.Counter, ResyncWindow, d.Digits)
		} else {
			used, ok = Verify(d.Secret, code, d.Counter, LookAhead, d.Digits)
		}
		if !ok {
			continue
		}
		d.Counter = used + 1
		raw, err := json.Marshal(d) // #nosec G117 -- 方式のデータはコアがユーザーのデータ鍵で暗号化して置く
		if err != nil {
			return port.MethodResult{}, err
		}
		updated, err := env.Credentials.Update(ctx, c, raw)
		if errors.Is(err, errs.Conflict) {
			return port.MethodResult{}, rejected("counter already used")
		}
		if err != nil {
			return port.MethodResult{}, err
		}
		return port.MethodResult{Credential: updated}, nil
	}
	return port.MethodResult{}, rejected("no hotp matched")
}

// enrollInput は登録の開始の入力。Secret（Base32）を渡すと、その秘密（ハードウェアトークンの種）を取り込む。
type enrollInput struct {
	Secret string `json:"secret,omitempty"`
	Digits int    `json:"digits,omitempty"`
}

// enrollState は登録のフローの状態（コアが封をして置く）。
type enrollState struct {
	Secret []byte `json:"secret"`
	Digits int    `json:"digits"`
}

// enrollOutput は登録の開始の応答。秘密は本人にだけ返す。
type enrollOutput struct {
	Secret  string `json:"secret"`
	URI     string `json:"uri"`
	Digits  int    `json:"digits"`
	Counter uint64 `json:"counter"`
}

// errInvalid は登録の入力の誤り（本人に返してよい）。
var errInvalid = errs.WithCode(errs.KindInvalid, "invalid_request", "hotp: invalid enrollment")

// EnrollBegin は秘密を作り（または取り込み）、認証器に入れる形で返す。登録はコードの確認で完了する。
func (Method) EnrollBegin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	req, err := decode[enrollInput](in.Payload)
	if err != nil {
		return port.MethodChallenge{}, errInvalid
	}
	if err := checkLimit(ctx, env); err != nil {
		return port.MethodChallenge{}, err
	}
	st := enrollState{Digits: req.Digits}
	if st.Digits == 0 {
		st.Digits = 6
	}
	if !ValidDigits(st.Digits) {
		return port.MethodChallenge{}, errInvalid
	}
	if req.Secret != "" {
		s, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(strings.ReplaceAll(req.Secret, " ", ""), "=")))
		if err != nil || len(s) < MinSecretSize || len(s) > MaxSecretSize {
			return port.MethodChallenge{}, errInvalid
		}
		st.Secret = s
	} else {
		st.Secret = make([]byte, SecretSize)
		if _, err := rand.Read(st.Secret); err != nil {
			return port.MethodChallenge{}, err
		}
	}
	state, err := json.Marshal(st) // #nosec G117 -- 秘密はコアが封をしてから置く
	if err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(enrollOutput{Secret: b32.EncodeToString(st.Secret), URI: URI(st.Secret, env.Issuer, env.Account, st.Digits, 0),
		Digits: st.Digits})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return port.MethodChallenge{Payload: out, State: state}, nil
}

// EnrollComplete はコードで秘密を確かめて登録する。カウンターは 0 から先読みの窓の中を探す（取り込んだトークンで先に進んでいれば、
// 続けて出した2つのコードで再同期の窓を探す）。
func (Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	var st enrollState
	if err := json.Unmarshal(in.State, &st); err != nil || len(st.Secret) == 0 || !ValidDigits(st.Digits) {
		return port.MethodEnrollment{}, fmt.Errorf("hotp: enrollment state: %v", err)
	}
	req, err := decode[codeInput](in.Payload)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	code, next := normalize(req.Code), normalize(req.NextCode)
	var used uint64
	var ok bool
	if next != "" {
		used, ok = Resync(st.Secret, code, next, 0, ResyncWindow, st.Digits)
	} else {
		used, ok = Verify(st.Secret, code, 0, LookAhead, st.Digits)
	}
	if !ok {
		return port.MethodEnrollment{}, rejected("code mismatch")
	}
	if err := checkLimit(ctx, env); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := json.Marshal(data{Secret: st.Secret, Counter: used + 1, Digits: st.Digits}) // #nosec G117 -- コアが暗号化して置く
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, "", raw)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	return port.MethodEnrollment{Credential: c}, nil
}

// Revoke は方式の外に片付けるものが無いので何もしない。
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

// URI は認証器に読ませる otpauth://hotp の URI（QR コードの内容）を返す。
func URI(secret []byte, issuer, account string, digits int, counter uint64) string {
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {strconv.Itoa(digits)}, "counter": {strconv.FormatUint(counter, 10)}}
	return (&url.URL{Scheme: "otpauth", Host: "hotp", Path: "/" + issuer + ":" + account, RawQuery: q.Encode()}).String()
}
