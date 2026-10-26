// Package password はメール + パスワードのログインと、パスワードの設定・削除を扱う（フィーチャー password。
// design.md 4.1、ADR 0051）。ハッシュは argon2id。漏洩済みのパスワードは設定で拒否し、ログインで警告する。
package password

import (
	"context"
	"crypto/sha1" // #nosec G505 -- 漏洩済みパスワードの k-匿名 API の形式（照合の鍵には使わない）
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

func init() {
	feature.Register(feature.Feature{Name: feature.Password, DataVersion: 1})
}

// AMR はパスワードの amr（RFC 8176）。
const AMR = "pwd"

// 無効化の理由。
const (
	ReasonChanged = "changed"
	ReasonRemoved = "removed_by_user"
)

var (
	// ErrAuthFailed はログインの失敗。理由は外部に返さない（4.9）。
	ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "password login failed")
	// ErrCurrentPassword は、変更・削除で今のパスワードが違うこと（ログイン済みの本人なので理由を返す）。
	ErrCurrentPassword = errs.WithCode(errs.KindFailedPrecondition, "current_password_mismatch", "current password does not match")
	// ErrReauthRequired は、初めての設定に直近の認証（max_auth_age の内）が要ること。
	ErrReauthRequired = errs.WithCode(errs.KindUnauthenticated, "reauthentication_required", "recent authentication required")
	// ErrNoPassword はパスワードを設定していないこと。
	ErrNoPassword = errs.WithCode(errs.KindNotFound, "no_password", "no password set")
)

// Service はパスワードを扱う。
type Service struct {
	Storage  port.Storage
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	// Breach は漏洩済みパスワードの確認。nil なら確認しない。失敗（外部の障害）では確認を飛ばし、記録する。
	Breach port.BreachChecker
	// Params は新しく作るハッシュのパラメータ。零値なら DefaultParams。
	Params Params
	// MinLength は最低長。零値なら MinLength（2段階認証が必須なら呼び出し側が MinLengthWithSecondFactor を渡す）。
	MinLength int
	// PerAccount はメールアドレス（とユーザー）ごとの照合の回数の上限。nil なら制限しない。
	PerAccount *ratelimit.Limiter
	Log        *slog.Logger

	dummyOnce sync.Once
	dummy     string
}

// Client は監査ログに残す接続元。
type Client struct{ IP, UserAgent, RequestID string }

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

func (s *Service) params() Params {
	if s.Params == (Params{}) {
		return DefaultParams
	}
	return s.Params
}

func (s *Service) minLength() int {
	if s.MinLength <= 0 {
		return MinLength
	}
	return s.MinLength
}

// dummyHash は、アカウントが無いときにも同じ重さの照合をするためのハッシュ（応答時間から有無を読ませない）。
func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() {
		s.dummy, _ = Hash("not a password", s.params())
	})
	return s.dummy
}

// Login はメールとパスワードで照合し、セッションを発行する。失敗は ErrAuthFailed（回数の上限を超えれば
// *ratelimit.ExceededError、警告の deny・停止・有効期間の外なら errs.Denial）。基盤の障害はそのまま返す。
func (s *Service) Login(ctx context.Context, realmID string, in Login) (Result, error) {
	email, err := account.NormalizeEmail(in.Email)
	if err != nil {
		return Result{}, ErrAuthFailed
	}
	if err := s.allow(ctx, realmID, email); err != nil {
		return Result{}, err
	}
	if len(in.Password) > MaxInputBytes {
		// 長さはアカウントの有無に関わらないので、照合せずに失敗させてよい。
		s.recordFailure(ctx, realmID, in.Client, fmt.Errorf("%w: password too long", errRejected))
		return Result{}, ErrAuthFailed
	}
	pw := Normalize(in.Password)
	cred, u, emailID, err := s.check(ctx, realmID, email, pw)
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		if errors.Is(err, errRejected) {
			return Result{}, ErrAuthFailed
		}
		return Result{}, err
	}
	breached := s.breached(ctx, pw)
	var out Result
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		// 照合と発行の間に変更・削除されていれば通さない。
		cur, err := tx.Passwords().GetActive(ctx, realmID, u.ID)
		if errors.Is(err, errs.NotFound) || (err == nil && (cur.ID != cred.ID || cur.Hash != cred.Hash)) {
			return fmt.Errorf("%w: password changed during login", errRejected)
		}
		if err != nil {
			return err
		}
		// 停止と有効期間は照合が通った後に見る（本人確認の後なので理由を返す。4.9）。
		if u, err = tx.Users().Get(ctx, realmID, u.ID); err != nil {
			return err
		}
		now := s.Clock.Now()
		if _, err := account.Check(ctx, tx, u, now, now); err != nil {
			return err
		}
		if cred.rehash {
			h, err := Hash(pw, s.params())
			if err != nil {
				return err
			}
			if err := tx.Passwords().UpdateHash(ctx, realmID, cur.ID, h); err != nil {
				return err
			}
		}
		is, err := s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: []string{AMR}, Credentials: []string{emailID},
			Evidence: evidence(breached),
			IP:       in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, ReplaceToken: in.ReplaceToken,
		})
		if err != nil {
			return err
		}
		out = Result{Session: is, UserID: u.PublicID}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: is.Session.ID, IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID,
			Details: map[string]any{"method": "password"},
		})
		return err
	})
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		if errors.Is(err, errRejected) || errors.Is(err, account.ErrInactive) {
			return Result{}, ErrAuthFailed
		}
		return Result{}, err // errs.Denial と基盤の障害
	}
	s.Sessions.Committed(ctx, realmID, out.Session)
	return out, nil
}

// errRejected は照合の失敗（アカウントが無い・メールが未確認・ログインできない・パスワードが違う）。
// 外には ErrAuthFailed として返す。基盤の障害はこれに含めない。
var errRejected = errors.New("password login rejected")

// errUnusable はメールが未確認か、ユーザーがログインできないこと（理由は外部に返さない）。
var errUnusable = fmt.Errorf("%w: email unverified or user cannot log in", errRejected)

type checked struct {
	port.PasswordCredential
	rehash bool
}

// check はメールのユーザーのパスワードを照合する。アカウントが無い・メールが未確認・パスワードが無いときも、
// 同じ重さの照合をしてから失敗する。
func (s *Service) check(ctx context.Context, realmID, email, pw string) (checked, port.User, string, error) {
	var cred port.PasswordCredential
	var u port.User
	var emailID string
	lookup := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e, err := s.Accounts.FindByEmail(ctx, tx, realmID, email)
		if err != nil {
			return err
		}
		if e.VerifiedAt == nil {
			return errUnusable
		}
		if u, err = tx.Users().Get(ctx, realmID, e.UserID); err != nil {
			return err
		}
		if u.Status != port.UserActive {
			return errUnusable
		}
		emailID = e.ID
		cred, err = tx.Passwords().GetActive(ctx, realmID, e.UserID)
		return err
	})
	if lookup != nil && !errors.Is(lookup, errs.NotFound) && !errors.Is(lookup, errUnusable) {
		return checked{}, port.User{}, "", lookup // ストレージの障害
	}
	hash := cred.Hash
	if lookup != nil {
		hash = s.dummyHash()
	}
	ok, rehash, err := Verify(pw, hash, s.params())
	switch {
	case errors.Is(lookup, errs.NotFound):
		return checked{}, port.User{}, "", fmt.Errorf("%w: %w", errRejected, lookup)
	case lookup != nil:
		return checked{}, port.User{}, "", lookup
	case err != nil:
		return checked{}, port.User{}, "", err
	case !ok:
		return checked{}, port.User{}, "", fmt.Errorf("%w: password mismatch", errRejected)
	}
	return checked{PasswordCredential: cred, rehash: rehash}, u, emailID, nil
}

func (s *Service) allow(ctx context.Context, realmID, key string) error {
	if s.PerAccount == nil {
		return nil
	}
	ix, err := s.Crypter.EmailIndex(ctx, key)
	if err != nil {
		return err
	}
	return s.PerAccount.Allow(ctx, "password:"+realmID+":"+base64.RawURLEncoding.EncodeToString(ix.Value))
}

// breached は漏洩済みかを返す。確認できなければ nil（警告を出さず、ログに残す）。
func (s *Service) breached(ctx context.Context, pw string) *bool {
	if s.Breach == nil {
		return nil
	}
	sum := sha1.Sum([]byte(pw)) // #nosec G401 -- k-匿名 API の形式
	b, err := s.Breach.Breached(ctx, strings.ToUpper(hex.EncodeToString(sum[:])))
	if err != nil {
		s.logger().WarnContext(ctx, "password breach check unavailable", "error", err)
		return nil
	}
	return &b
}

// Set はユーザー（内部 ID）のパスワードを設定する。既にあれば current と照合して置き換える。初めての設定は
// 直近の認証（recentAuth）を求める。同じトランザクションで keepSession 以外のセッションを失効させる（5.2）。
// 長さと漏洩の確認で拒否すれば ErrTooShort・ErrTooLong・ErrBreached。
func (s *Service) Set(ctx context.Context, realmID, userID, newPassword, current string, recentAuth bool, keepSession string, actor audit.Actor, requestID string) (port.PasswordCredential, error) {
	if len(newPassword) > MaxInputBytes {
		// 正規化で縮む入力も、ログインで受け取れる大きさに揃える。
		return port.PasswordCredential{}, ErrTooLong
	}
	pw := Normalize(newPassword)
	if err := checkLength(pw, s.minLength()); err != nil {
		return port.PasswordCredential{}, err
	}
	if b := s.breached(ctx, pw); b != nil && *b {
		return port.PasswordCredential{}, ErrBreached
	}
	h, err := Hash(pw, s.params())
	if err != nil {
		return port.PasswordCredential{}, err
	}
	if err := s.allowUser(ctx, realmID, userID); err != nil {
		return port.PasswordCredential{}, err
	}
	now := s.Clock.Now()
	c := port.PasswordCredential{ID: id.New(id.Password), RealmID: realmID, UserID: userID, Hash: h, CreatedAt: now}
	var revoked []string
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		old, err := tx.Passwords().GetActive(ctx, realmID, userID)
		switch {
		case err == nil:
			if err := s.matches(old, current); err != nil {
				return err
			}
			if err := tx.Passwords().Revoke(ctx, realmID, old.ID, now, ReasonChanged); err != nil {
				return err
			}
		case !errors.Is(err, errs.NotFound):
			return err
		case !recentAuth:
			return ErrReauthRequired
		}
		if err := tx.Passwords().Create(ctx, c); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "password.set", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
			Details: map[string]any{"replaced": old.ID != ""},
		})
		if err != nil {
			return err
		}
		revoked, err = s.Sessions.RevokeAllTx(ctx, tx, realmID, userID, keepSession, session.ReasonCredentialChanged, actor, requestID)
		return err
	})
	if err != nil {
		return port.PasswordCredential{}, err
	}
	s.Sessions.ForgetIDs(ctx, realmID, revoked)
	return c, nil
}

// Remove はパスワードを current と照合して無効化する。最後のログインの手段なら account.ErrLastMethod。
// 同じトランザクションで keepSession 以外のセッションを失効させる（5.2）。
func (s *Service) Remove(ctx context.Context, realmID, userID, current, keepSession string, actor audit.Actor, requestID string) error {
	if err := s.allowUser(ctx, realmID, userID); err != nil {
		return err
	}
	var revoked []string
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		old, err := tx.Passwords().GetActive(ctx, realmID, userID)
		if errors.Is(err, errs.NotFound) {
			return ErrNoPassword
		}
		if err != nil {
			return err
		}
		if err := s.matches(old, current); err != nil {
			return err
		}
		if err := s.Accounts.RevokePassword(ctx, tx, realmID, userID, old, ReasonRemoved, actor, requestID); err != nil {
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

func (s *Service) allowUser(ctx context.Context, realmID, userID string) error {
	if s.PerAccount == nil {
		return nil
	}
	return s.PerAccount.Allow(ctx, "password-user:"+realmID+":"+userID)
}

func (s *Service) matches(c port.PasswordCredential, current string) error {
	ok, _, err := Verify(Normalize(current), c.Hash, s.params())
	if err != nil {
		return err
	}
	if !ok {
		return ErrCurrentPassword
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, realmID string, c Client, cause error) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"method": "password", "reason": cause.Error()},
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record login failure", "error", err)
	}
}

func evidence(breached *bool) warning.Evidence { return warning.Evidence{PasswordBreached: breached} }

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
