// Package loginlink は運営者が発行する1回限りのログイン用リンクを扱う（design.md 2.5、4.11）。
//
// 最初の運営者は CLI で作る。CLI は IAM と別のプロセスで動き、EphemeralStore を共有しないため、
// リンクのトークンは自己完結にする：内容（realm、ユーザーの公開 ID、期限、乱数）をマスター鍵から導いた
// 鍵で封じる（pii.Crypter.Seal）。1回限りは、使うときに乱数を EphemeralStore で数えて保証する。
//
// セキュリティ上重要なコード（13.2）。トークンはログ・監査ログ・エラーに出さない。
package loginlink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 封の目的。ログイン用と復旧用で分け、取り違えて使えないようにする。
const (
	purpose         = "login_link"
	purposeRecovery = "recovery_link"
)

// MaxTTL はリンクの有効期間の上限。
const MaxTTL = 24 * time.Hour

// AMR はリンクでのログインの amr（RFC 8176 に無いため独自の値。要素の数には数えない）。
const AMR = "link"

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "login link failed")

type payload struct {
	RealmID   string    `json:"r"`
	UserID    string    `json:"u"` // 公開 ID
	Nonce     string    `json:"n"`
	ExpiresAt time.Time `json:"e"`
}

// Issue はユーザー（公開 ID）のログイン用リンクのトークンを作る。
func Issue(ctx context.Context, c *pii.Crypter, realmID, publicUserID string, expiresAt time.Time) (string, error) {
	return issue(ctx, c, purpose, realmID, publicUserID, expiresAt)
}

// IssueRecovery は、運営者が IAM の外で本人確認した後に渡す復旧用リンクのトークンを作る（4.12）。
// 使うと復旧専用のセッションになる。
func IssueRecovery(ctx context.Context, c *pii.Crypter, realmID, publicUserID string, expiresAt time.Time) (string, error) {
	return issue(ctx, c, purposeRecovery, realmID, publicUserID, expiresAt)
}

func issue(ctx context.Context, c *pii.Crypter, seal, realmID, publicUserID string, expiresAt time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw, err := json.Marshal(payload{RealmID: realmID, UserID: publicUserID, Nonce: base64.RawURLEncoding.EncodeToString(b), ExpiresAt: expiresAt})
	if err != nil {
		return "", err
	}
	sealed, err := c.Seal(ctx, seal, raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Service はリンクでログインさせる。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Sessions *session.Manager
	Log      *slog.Logger
}

// Client は要求の接続元。
type Client struct {
	IP, UserAgent, RequestID string
}

// Redeem はトークンを確かめてセッションを発行する。失敗は ErrAuthFailed（警告による拒否は理由つき）。
func (s *Service) Redeem(ctx context.Context, realmID, token string, c Client, replaceToken string) (session.Issued, string, error) {
	return s.redeemOrFail(ctx, realmID, token, c, replaceToken, false)
}

// RedeemRecovery は復旧用リンクのトークンを確かめ、復旧専用のセッションを発行する（security_risk の停止は見ない）。
func (s *Service) RedeemRecovery(ctx context.Context, realmID, token string, c Client, replaceToken string) (session.Issued, string, error) {
	return s.redeemOrFail(ctx, realmID, token, c, replaceToken, true)
}

func (s *Service) redeemOrFail(ctx context.Context, realmID, token string, c Client, replaceToken string, recovery bool) (session.Issued, string, error) {
	is, uid, err := s.redeem(ctx, realmID, token, c, replaceToken, recovery)
	if err != nil {
		s.recordFailure(ctx, realmID, c, err)
		if d, ok := errors.AsType[errs.Denial](err); ok {
			return session.Issued{}, "", d
		}
		return session.Issued{}, "", ErrAuthFailed
	}
	return is, uid, nil
}

func (s *Service) redeem(ctx context.Context, realmID, token string, c Client, replaceToken string, recovery bool) (session.Issued, string, error) {
	seal, used, typ, method := purpose, "loginlink:v1:used:", "login.succeeded", "login_link"
	var ignore []string
	if recovery {
		seal, used, typ, method, ignore = purposeRecovery, "recoverylink:v1:used:", "recovery.started", "operator_link", account.RecoveryIgnores
	}
	sealed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(token) > 1024 {
		return session.Issued{}, "", errors.New("malformed token")
	}
	raw, err := s.Crypter.Open(ctx, seal, sealed)
	if err != nil {
		return session.Issued{}, "", errors.New("token does not open")
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return session.Issued{}, "", err
	}
	now := s.Clock.Now()
	if p.RealmID != realmID {
		return session.Issued{}, "", errors.New("token for another realm")
	}
	if !now.Before(p.ExpiresAt) {
		return session.Issued{}, "", errors.New("token expired")
	}
	// 1回限り：最初に数えた要求だけが続ける。期限まで覚えておけば足りる。
	n, err := s.Cache.Incr(ctx, used+p.Nonce, p.ExpiresAt.Sub(now)+time.Minute)
	if err != nil {
		return session.Issued{}, "", err
	}
	if n != 1 {
		return session.Issued{}, "", errors.New("token already used")
	}
	var out session.Issued
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, realmID, p.UserID)
		if err != nil {
			return err
		}
		if _, err := account.Check(ctx, tx, u, now, now, ignore...); err != nil {
			return err
		}
		if out, err = s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: []string{AMR}, Recovery: recovery,
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, ReplaceToken: replaceToken,
		}); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: out.Session.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"method": method},
		})
		return err
	})
	if err == nil {
		s.Sessions.Committed(ctx, realmID, out)
	}
	return out, p.UserID, err
}

func (s *Service) recordFailure(ctx context.Context, realmID string, c Client, cause error) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"method": "login_link", "reason": cause.Error()},
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record login failure", "error", err)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// ValidTTL はリンクの有効期間を確かめる。
func ValidTTL(d time.Duration) error {
	if d <= 0 || d > MaxTTL {
		return fmt.Errorf("login link ttl must be within (0, %s]", MaxTTL)
	}
	return nil
}
