package totp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = method.TOTP

// AMR は TOTP の amr（RFC 8176）。
const AMR = "otp"

// ErrTOTPExists は、有効な TOTP を登録済みであること（1人に1つ）。
var ErrTOTPExists = errs.WithCode(errs.KindConflict, "totp_exists", "totp already registered")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "totp: "+reason)
}

// Method は TOTP の port.Authenticator。
type Method struct{}

var _ port.Authenticator = Method{}

// Info は方式の宣言。所持の要素で、2要素目として AAL2 に届く（SP 800-63B の単要素 OTP デバイス）。フィーチャーは無い（コア）。
func (Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Kind: port.FactorPossession, AMR: []string{AMR}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageSecondFactor}, DataVersion: 1}
}

// Data は方式固有のデータ（コアが暗号化して置く）。
type Data struct {
	Secret []byte `json:"secret"`
	// LastStep は最後に受け入れた時間窓。同じか前の窓のコードは拒否する（再利用の防止）。
	LastStep int64 `json:"last_step"`
}

// codeInput はログインと登録の確認の入力。
type codeInput struct {
	Code string `json:"code"`
}

func decodeCode(raw json.RawMessage) (string, error) {
	var in codeInput
	if len(raw) == 0 || string(raw) == "null" {
		return "", rejected("code is required")
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", rejected("invalid payload")
	}
	return in.Code, nil
}

// Begin は2要素目の確認を始める。チャレンジは無いので、有効な TOTP があることだけを確かめる。
func (Method) Begin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if env.UserID == "" {
		return port.MethodChallenge{}, rejected("first factor is not supported")
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if len(cs) == 0 {
		return port.MethodChallenge{}, errs.New(errs.KindNotFound, "totp")
	}
	return port.MethodChallenge{}, nil
}

// Complete は本人の有効な TOTP のどれかでコードを確かめ、使った時間窓を記録する。同じか前の窓のコードは拒否し、同じコードを
// 同時に使っても、記録の比較と交換で1つしか通らない。
func (Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	if env.UserID == "" {
		return port.MethodResult{}, rejected("first factor is not supported")
	}
	code, err := decodeCode(in.Payload)
	if err != nil {
		return port.MethodResult{}, err
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodResult{}, err
	}
	for _, c := range cs {
		var d Data
		if err := json.Unmarshal(c.Data, &d); err != nil {
			return port.MethodResult{}, fmt.Errorf("totp: data: %w", err)
		}
		step, ok := Verify(d.Secret, code, env.Now)
		if !ok {
			continue
		}
		if step <= d.LastStep {
			return port.MethodResult{}, rejected("time step already used")
		}
		d.LastStep = step
		raw, err := json.Marshal(d) // #nosec G117 -- 方式のデータはコアがユーザーのデータ鍵で暗号化して置く
		if err != nil {
			return port.MethodResult{}, err
		}
		updated, err := env.Credentials.Update(ctx, c, raw)
		if errors.Is(err, errs.Conflict) {
			return port.MethodResult{}, rejected("time step already used")
		}
		if err != nil {
			return port.MethodResult{}, err
		}
		return port.MethodResult{Credential: updated}, nil
	}
	return port.MethodResult{}, rejected("no totp matched")
}

// enrollState は登録のフローの状態（コアが封をして置く）。
type enrollState struct {
	Secret []byte `json:"secret"`
}

// enrollOutput は登録の開始の応答。秘密は本人にだけ返す。
type enrollOutput struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func checkNone(ctx context.Context, env port.MethodEnv) error {
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return err
	}
	if len(cs) > 0 {
		return ErrTOTPExists
	}
	return nil
}

// EnrollBegin は秘密を作り、認証器アプリに入れる形で返す。登録はコードの確認で完了する。有効な TOTP があれば ErrTOTPExists。
func (Method) EnrollBegin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if err := checkNone(ctx, env); err != nil {
		return port.MethodChallenge{}, err
	}
	secret, err := NewSecret()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	state, err := json.Marshal(enrollState{Secret: secret}) // #nosec G117 -- 秘密はコアが封をしてから置く
	if err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(enrollOutput{Secret: Encode(secret), URI: URI(secret, env.Issuer, env.Account)})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return port.MethodChallenge{Payload: out, State: state}, nil
}

// EnrollComplete はコードで秘密を確かめて登録する。確かめた時間窓を使ったものとして記録する（同じコードで照合させない）。
func (Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	var st enrollState
	if err := json.Unmarshal(in.State, &st); err != nil || len(st.Secret) == 0 {
		return port.MethodEnrollment{}, fmt.Errorf("totp: enrollment state: %v", err)
	}
	code, err := decodeCode(in.Payload)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	step, ok := Verify(st.Secret, code, env.Now)
	if !ok {
		return port.MethodEnrollment{}, rejected("code mismatch")
	}
	if err := checkNone(ctx, env); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := json.Marshal(Data{Secret: st.Secret, LastStep: step}) // #nosec G117 -- コアが暗号化して置く
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
