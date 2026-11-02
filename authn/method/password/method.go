// Package password はメール + パスワードの認証方式（port.Authenticator。フィーチャー password。design.md 4.1、ADR 0051、0090、
// 0101）。ハッシュは argon2id。漏洩済みのパスワードは設定で拒否し、ログインで警告する。
//
// セキュリティ上重要なコード（13.2）。本人が無い・メールが未確認・パスワードが無いときも同じ重さの照合をしてから失敗し（応答時間から
// 有無を読ませない）、理由は外に返さない（4.9）。ハッシュの計算はコアが直列にしたトランザクションの外で呼ぶ（ログインと登録の始め）。
package password

import (
	"context"
	"crypto/sha1" // #nosec G505 -- 漏洩済みパスワードの k-匿名 API の形式（照合の鍵には使わない）
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = method.Password

// Feature はパスワードの宣言（features/password が登録する）。データは authn_credentials に置く（ADR 0101）。
var Feature = feature.Feature{Name: feature.Password, DataVersion: 1}

// AMR はパスワードの amr（RFC 8176）。
const AMR = "pwd"

// 無効化の理由。
const (
	ReasonChanged = "changed"
	ReasonRemoved = "removed_by_user"
)

var (
	// ErrCurrentPassword は、変更・削除で今のパスワードが違うこと（ログイン済みの本人なので理由を返す）。
	ErrCurrentPassword = errs.WithCode(errs.KindFailedPrecondition, "current_password_mismatch", "current password does not match")
	// ErrReauthRequired は、初めての設定に直近の認証（max_auth_age の内）が要ること。
	ErrReauthRequired = errs.WithCode(errs.KindUnauthenticated, "reauthentication_required", "recent authentication required")
	// ErrChanged は、設定の始めと完了の間に、別の操作でパスワードが変わったこと。
	ErrChanged = errs.WithCode(errs.KindConflict, "password_changed", "password changed during the update")
)

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "password: "+reason)
}

// Method はパスワードの port.Authenticator。設定（ハッシュのパラメータ、最低長、漏洩の確認）は server/app が入れる。
type Method struct {
	// Params は新しく作るハッシュのパラメータ。零値なら DefaultParams。
	Params Params
	// MinLength は最低長。零値なら MinLength（2段階認証が必須なら呼び出し側が MinLengthWithSecondFactor を渡す）。
	MinLength int
	// Breach は漏洩済みパスワードの確認。nil なら確認しない。失敗（外部の障害）では確認を飛ばし、記録する。
	Breach port.BreachChecker
	Log    *slog.Logger

	dummyOnce sync.Once
	dummy     string
}

var _ port.Authenticator = (*Method)(nil)

// Info は方式の宣言。知識の要素で、1要素目だけ（AAL1）。
func (*Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.Password, Kind: port.FactorKnowledge, AMR: []string{AMR}, AAL: 1,
		Usages: []port.MethodUsage{port.UsageFirstFactor}, DataVersion: 1}
}

// Data は方式固有のデータ（コアが暗号化して置く）。
type Data struct {
	// Hash は argon2id の PHC 文字列。
	Hash string `json:"hash"`
}

// HashOf は認証情報のデータのハッシュを返す。
func HashOf(c port.MethodCredential) (string, error) {
	var d Data
	if err := json.Unmarshal(c.Data, &d); err != nil || d.Hash == "" {
		return "", fmt.Errorf("password: data: %v", err)
	}
	return d.Hash, nil
}

func (m *Method) params() Params {
	if m.Params == (Params{}) {
		return DefaultParams
	}
	return m.Params
}

func (m *Method) minLength() int {
	if m.MinLength <= 0 {
		return MinLength
	}
	return m.MinLength
}

func (m *Method) logger() *slog.Logger {
	if m.Log == nil {
		return slog.Default()
	}
	return m.Log
}

// dummyHash は、アカウントが無いときにも同じ重さの照合をするためのハッシュ。
func (m *Method) dummyHash() string {
	m.dummyOnce.Do(func() {
		m.dummy, _ = Hash("not a password", m.params())
	})
	return m.dummy
}

// Breached は漏洩済みかを返す。確認できなければ nil（警告を出さず、ログに残す）。
func (m *Method) Breached(ctx context.Context, normalized string) *bool {
	if m.Breach == nil {
		return nil
	}
	sum := sha1.Sum([]byte(normalized)) // #nosec G401 -- k-匿名 API の形式
	b, err := m.Breach.Breached(ctx, strings.ToUpper(hex.EncodeToString(sum[:])))
	if err != nil {
		m.logger().WarnContext(ctx, "password breach check unavailable", "error", err)
		return nil
	}
	return &b
}

// Matches は今のパスワード current が認証情報 c と合うかを確かめる。合わなければ ErrCurrentPassword。
func (m *Method) Matches(c port.MethodCredential, current string) error {
	h, err := HashOf(c)
	if err != nil {
		return err
	}
	if len(current) > MaxInputBytes {
		return ErrCurrentPassword
	}
	ok, _, err := Verify(Normalize(current), h, m.params())
	if err != nil {
		return err
	}
	if !ok {
		return ErrCurrentPassword
	}
	return nil
}

// loginInput はログインの入力。
type loginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Begin は1要素目のログインを始める。チャレンジは無い。
func (*Method) Begin(_ context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if env.Usage != port.UsageFirstFactor {
		return port.MethodChallenge{}, rejected("only the first factor is supported")
	}
	return port.MethodChallenge{}, nil
}

// Complete はメールアドレスで本人を引き当て、パスワードを照合する。アカウントが無いときも同じ重さの照合をしてから失敗する。
// ハッシュのパラメータが古ければ、作り直して比較と交換で書く。
func (m *Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	if env.Usage != port.UsageFirstFactor || env.Users == nil {
		return port.MethodResult{}, rejected("only the first factor is supported")
	}
	var req loginInput
	if len(in.Payload) == 0 || json.Unmarshal(in.Payload, &req) != nil {
		return port.MethodResult{}, rejected("invalid payload")
	}
	// 回数の上限はログイン ID ごとに引き当てで掛ける（長さで落とす前に数える）。
	userID, err := env.Users.LoginUser(ctx, req.Email)
	switch {
	case errors.Is(err, errs.NotFound):
		userID = ""
	case err != nil:
		return port.MethodResult{}, err
	}
	if len(req.Password) > MaxInputBytes {
		// 長さはアカウントの有無に関わらないので、照合せずに失敗させてよい。
		return port.MethodResult{}, rejected("password too long")
	}
	pw := Normalize(req.Password)
	var cred *port.MethodCredential
	hash := ""
	if userID != "" {
		cs, err := env.Credentials.List(ctx, userID)
		if err != nil {
			return port.MethodResult{}, err
		}
		if len(cs) > 0 {
			if hash, err = HashOf(cs[0]); err != nil {
				return port.MethodResult{}, err
			}
			cred = &cs[0]
		}
	}
	if cred == nil {
		hash = m.dummyHash()
	}
	ok, rehash, err := Verify(pw, hash, m.params())
	switch {
	case cred == nil:
		return port.MethodResult{}, rejected("no account or no password")
	case err != nil:
		return port.MethodResult{}, err
	case !ok:
		return port.MethodResult{}, rejected("password mismatch")
	}
	c := *cred
	if rehash {
		h, err := Hash(pw, m.params())
		if err != nil {
			return port.MethodResult{}, err
		}
		raw, err := json.Marshal(Data{Hash: h})
		if err != nil {
			return port.MethodResult{}, err
		}
		c, err = env.Credentials.Update(ctx, c, raw)
		if errors.Is(err, errs.Conflict) {
			return port.MethodResult{}, rejected("password changed during login")
		}
		if err != nil {
			return port.MethodResult{}, err
		}
	}
	return port.MethodResult{Credential: c, KnowledgeBreached: m.Breached(ctx, pw)}, nil
}

// enrollInput は設定の入力。CurrentPassword は置き換えのときに要る（復旧専用のセッションでは要らない）。
type enrollInput struct {
	Password        string `json:"password"`
	CurrentPassword string `json:"current_password,omitempty"`
}

// enrollState は設定のフローの状態（コアが封をして置く）。Replaces は置き換えるパスワードの ID と、そのときの暗号文。
type enrollState struct {
	Hash           string `json:"hash"`
	Replaces       string `json:"replaces,omitempty"`
	ReplacesSealed []byte `json:"replaces_sealed,omitempty"`
}

// EnrollBegin は新しいパスワードの長さと漏洩を確かめ、置き換えなら今のパスワードを照合し、ハッシュを作る。設定は EnrollComplete で
// 行う。長さと漏洩で拒否すれば ErrTooShort・ErrTooLong・ErrBreached。初めての設定で直近の認証が無ければ ErrReauthRequired。
func (m *Method) EnrollBegin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	var req enrollInput
	if len(in.Payload) == 0 || json.Unmarshal(in.Payload, &req) != nil {
		return port.MethodChallenge{}, errs.WithCode(errs.KindInvalid, "invalid_request", "password: invalid payload")
	}
	if len(req.Password) > MaxInputBytes {
		// 正規化で縮む入力も、ログインで受け取れる大きさに揃える。
		return port.MethodChallenge{}, ErrTooLong
	}
	pw := Normalize(req.Password)
	if err := checkLength(pw, m.minLength()); err != nil {
		return port.MethodChallenge{}, err
	}
	if b := m.Breached(ctx, pw); b != nil && *b {
		return port.MethodChallenge{}, ErrBreached
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	reset := env.Usage == port.UsageRecovery
	var st enrollState
	switch {
	case len(cs) > 0:
		if !reset {
			if err := m.Matches(cs[0], req.CurrentPassword); err != nil {
				return port.MethodChallenge{}, err
			}
		}
		st.Replaces, st.ReplacesSealed = cs[0].ID, cs[0].Sealed
	case !env.RecentAuth && !reset:
		return port.MethodChallenge{}, ErrReauthRequired
	}
	if st.Hash, err = Hash(pw, m.params()); err != nil {
		return port.MethodChallenge{}, err
	}
	state, err := json.Marshal(st)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return port.MethodChallenge{State: state}, nil
}

// EnrollComplete は、始めのときのパスワードを無効化して（変わっていれば ErrChanged）、新しいパスワードを作る。
func (m *Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	var st enrollState
	if err := json.Unmarshal(in.State, &st); err != nil || st.Hash == "" {
		return port.MethodEnrollment{}, fmt.Errorf("password: enrollment state: %v", err)
	}
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	switch {
	case st.Replaces == "" && len(cs) > 0:
		return port.MethodEnrollment{}, ErrChanged
	case st.Replaces != "":
		var old *port.MethodCredential
		for i := range cs {
			if cs[i].ID == st.Replaces {
				old = &cs[i]
			}
		}
		if old == nil || len(cs) != 1 {
			return port.MethodEnrollment{}, ErrChanged
		}
		o := *old
		o.Sealed = st.ReplacesSealed
		if err := env.Credentials.Revoke(ctx, o, ReasonChanged); errors.Is(err, errs.Conflict) {
			return port.MethodEnrollment{}, ErrChanged
		} else if err != nil {
			return port.MethodEnrollment{}, err
		}
	}
	raw, err := json.Marshal(Data{Hash: st.Hash})
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
func (*Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }
