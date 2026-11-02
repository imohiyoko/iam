// Package password は、メール + パスワードの方式専用のパス（`/v1/login/password`、`/v1/me/password:set`・`:remove`）を、
// 汎用の認証方式（authn/method/password。ADR 0101）とコアのサービス（authn/credential）で動かす互換の層（フィーチャー password。
// design.md 4.1、ADR 0051）。照合・設定の規則は方式に、フローとセッションはコアにあり、ここは1回の要求に組み立てるだけにする。
package password

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

var (
	// ErrAuthFailed はログインの失敗。理由は外部に返さない（4.9）。
	ErrAuthFailed = credential.ErrAuthFailed
	// ErrNoPassword はパスワードを設定していないこと。
	ErrNoPassword = errs.WithCode(errs.KindNotFound, "no_password", "no password set")
)

// Service はパスワードの方式専用のパスを扱う。
type Service struct {
	Storage     port.Storage
	Crypter     *pii.Crypter
	Clock       clock.Clock
	Accounts    *account.Service
	Sessions    *session.Manager
	Credentials *credential.Service
	// Method は設定を入れたパスワードの方式（Credentials の方式の組に入っているもの）。
	Method *pwm.Method
	// PerAccount はユーザーごとの、今のパスワードの照合の回数の上限（削除）。nil なら制限しない。
	PerAccount *ratelimit.Limiter
}

// Client は監査ログに残す接続元。
type Client = credential.Client

// Login はログインの入力。
type Login struct {
	Email, Password string
	Client          Client
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン（5.2）。
	ReplaceToken string
}

// Result はログインの結果。
type Result struct {
	Session session.Issued
	UserID  string // 公開のユーザー ID
}

// Login はメールとパスワードで照合し、セッションを発行する（汎用の `/v1/login/methods/password` と同じ処理を、フロー無しの
// 1回の要求で行う）。失敗は ErrAuthFailed（回数の上限を超えれば *ratelimit.ExceededError、警告の deny・停止・有効期間の外なら
// errs.Denial）。基盤の障害はそのまま返す。
func (s *Service) Login(ctx context.Context, realmID string, in Login) (Result, error) {
	p, err := json.Marshal(map[string]string{"email": in.Email, "password": in.Password})
	if err != nil {
		return Result{}, err
	}
	is, uid, err := s.Credentials.LoginOnce(ctx, realmID, pwm.Name, p, in.Client, in.ReplaceToken)
	if err != nil {
		return Result{}, err
	}
	return Result{Session: is, UserID: uid}, nil
}

// Set はユーザー（内部 ID）のパスワードを設定する。既にあれば current と照合して置き換える。初めての設定は
// 直近の認証（recentAuth）を求める。同じトランザクションで keepSession 以外のセッションを失効させる（5.2）。
// 長さと漏洩の確認で拒否すれば pwm.ErrTooShort・ErrTooLong・ErrBreached。
func (s *Service) Set(ctx context.Context, realmID, userID, newPassword, current string, recentAuth bool, keepSession string, actor audit.Actor, requestID string) (port.Credential, error) {
	return s.set(ctx, realmID, userID, map[string]string{"password": newPassword, "current_password": current},
		credential.EnrollOptions{RecentAuth: recentAuth}, keepSession, actor, requestID)
}

// Reset は今のパスワードを求めずに置き換える。アカウントの復旧（復旧専用のセッション。4.12）でだけ使う。
// セッションは失効させない（復旧の完了のときに全セッションを失効させる）。
func (s *Service) Reset(ctx context.Context, realmID, userID, newPassword string, actor audit.Actor, requestID string) (port.Credential, error) {
	return s.set(ctx, realmID, userID, map[string]string{"password": newPassword}, credential.EnrollOptions{Recovery: true, RecentAuth: true}, "", actor, requestID)
}

func (s *Service) set(ctx context.Context, realmID, userID string, in map[string]string, o credential.EnrollOptions, keepSession string, actor audit.Actor, requestID string) (port.Credential, error) {
	p, err := json.Marshal(in)
	if err != nil {
		return port.Credential{}, err
	}
	ch, err := s.Credentials.EnrollBegin(ctx, realmID, userID, pwm.Name, p, o)
	if err != nil {
		return port.Credential{}, err
	}
	var en credential.Enrolled
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		en, err = s.Credentials.EnrollComplete(ctx, tx, credential.EnrollInput{RealmID: realmID, UserID: userID, Method: pwm.Name,
			FlowID: ch.FlowID, Actor: actor, RequestID: requestID, KeepSession: keepSession})
		return err
	})
	if err != nil {
		return port.Credential{}, err
	}
	s.Sessions.ForgetIDs(ctx, realmID, en.RevokedSessions)
	return en.Credential, nil
}

// active はユーザーの有効なパスワードを復号して返す。無ければ ErrNoPassword。
func (s *Service) active(ctx context.Context, tx port.Tx, realmID, userID string) (port.Credential, port.MethodCredential, error) {
	cs, err := tx.Credentials().ListByUser(ctx, realmID, userID, pwm.Name)
	if err != nil {
		return port.Credential{}, port.MethodCredential{}, err
	}
	for _, c := range cs {
		if c.RevokedAt == nil {
			mc, err := method.Open(ctx, tx, s.Crypter, c)
			return c, mc, err
		}
	}
	return port.Credential{}, port.MethodCredential{}, ErrNoPassword
}

// Remove はパスワードを current と照合して無効化する。最後のログインの手段なら account.ErrLastMethod。
// 同じトランザクションで keepSession 以外のセッションを失効させる（5.2）。照合（重い計算）はトランザクションの外で行い、
// その間に変わっていれば pwm.ErrChanged。
func (s *Service) Remove(ctx context.Context, realmID, userID, current, keepSession string, actor audit.Actor, requestID string) error {
	if s.PerAccount != nil {
		if err := s.PerAccount.Allow(ctx, "password-user:"+realmID+":"+userID); err != nil {
			return err
		}
	}
	var mc port.MethodCredential
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		_, mc, err = s.active(ctx, tx, realmID, userID)
		return err
	}); err != nil {
		return err
	}
	if err := s.Method.Matches(mc, current); err != nil {
		return err
	}
	var revoked []string
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		c, cur, err := s.active(ctx, tx, realmID, userID)
		if errors.Is(err, ErrNoPassword) || (err == nil && (cur.ID != mc.ID || !bytes.Equal(cur.Sealed, mc.Sealed))) {
			return pwm.ErrChanged
		}
		if err != nil {
			return err
		}
		if err := s.Accounts.RevokePassword(ctx, tx, realmID, userID, c, pwm.ReasonRemoved, actor, requestID); err != nil {
			return err
		}
		revoked, err = s.Sessions.RevokeAllTx(ctx, tx, realmID, userID, keepSession, session.ReasonCredentialChanged, actor, requestID)
		return err
	})
	if err != nil {
		return err
	}
	s.Sessions.ForgetIDs(ctx, realmID, revoked)
	return nil
}
