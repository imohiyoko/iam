package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// AMR は TOTP の amr（RFC 8176）。
const AMR = "otp"

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "totp verification failed")

// ErrTOTPExists は、有効な TOTP を登録済みであること（1人に1つ）。
var ErrTOTPExists = errs.WithCode(errs.KindConflict, "totp_exists", "totp already registered")

// errRejected は利用者の入力による失敗（コードの不一致、未知・期限切れ・別人のフロー）。
// 外には ErrAuthFailed として返す。基盤の障害はこれに含めず、そのまま返す。
var errRejected = errors.New("totp rejected")

const (
	secretAAD   = "totp.secret"
	sealPurpose = "flow.totp"
)

// Service は TOTP の登録と照合を扱う。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	// Issuer は認証器アプリに表示する発行者の名前。
	Issuer string
	// TTL は登録のフローの期限（既定 10 分）。MaxAttempts はフローごとの照合の回数の上限（既定 5）。
	TTL         time.Duration
	MaxAttempts int
	// PerUser はユーザーごとの照合の回数の上限（総当たりの防止）。nil なら制限しない。
	PerUser *ratelimit.Limiter
	Log     *slog.Logger
}

// enrollment は登録のフローの状態。秘密を含むので EphemeralStore に封をして置く。
type enrollment struct {
	RealmID   string    `json:"realm_id"`
	UserID    string    `json:"user_id"`
	Secret    []byte    `json:"secret"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

func flowKey(flowID string) string {
	h := sha256.Sum256([]byte(flowID))
	return "flow:totp:v1:" + base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Service) ttl() time.Duration {
	if s.TTL <= 0 {
		return 10 * time.Minute
	}
	return s.TTL
}

func (s *Service) maxAttempts() int {
	if s.MaxAttempts <= 0 {
		return 5
	}
	return s.MaxAttempts
}

// Enrollment は始めた登録。秘密（Secret と URI）は本人にだけ返す。
type Enrollment struct {
	FlowID    string
	Secret    string // Base32
	URI       string // otpauth://
	ExpiresAt time.Time
}

// BeginEnroll はユーザー（内部 ID）の TOTP の登録を始め、秘密を返す。登録はコードの確認で完了する。
func (s *Service) BeginEnroll(ctx context.Context, realmID, userID string) (Enrollment, error) {
	account := ""
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, realmID, userID)
		if err != nil {
			return err
		}
		account = u.PublicID
		if err := active(ctx, tx, realmID, userID); err != nil {
			return err
		}
		es, err := tx.Emails().ListByUser(ctx, realmID, userID)
		if err != nil {
			return err
		}
		for _, e := range es {
			if e.IsPrimary && len(e.Ciphertext) > 0 {
				if account, err = s.Accounts.EmailAddress(ctx, tx, e); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := NewSecret()
	if err != nil {
		return Enrollment{}, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Enrollment{}, err
	}
	flowID := base64.RawURLEncoding.EncodeToString(b)
	st := enrollment{RealmID: realmID, UserID: userID, Secret: secret, ExpiresAt: s.Clock.Now().Add(s.ttl())}
	if err := s.put(ctx, flowID, st); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{FlowID: flowID, Secret: Encode(secret), URI: URI(secret, s.Issuer, account), ExpiresAt: st.ExpiresAt}, nil
}

func (s *Service) put(ctx context.Context, flowID string, st enrollment) error {
	raw, err := json.Marshal(st) // #nosec G117 -- 秘密は Crypter で封をしてから置く
	if err != nil {
		return err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, raw)
	if err != nil {
		return err
	}
	ttl := st.ExpiresAt.Sub(s.Clock.Now())
	if ttl <= 0 {
		return nil
	}
	return s.Cache.Set(ctx, flowKey(flowID), sealed, ttl)
}

// ConfirmEnroll はコードで秘密を確かめ、TOTP を登録する。呼び出し側のトランザクションで呼ぶ。
// コードが違えば ErrAuthFailed（回数の上限まではフローを残す）。基盤の障害はそのまま返す。
func (s *Service) ConfirmEnroll(ctx context.Context, tx port.Tx, realmID, userID, flowID, code string, actor audit.Actor, requestID string) (port.TOTPCredential, error) {
	c, err := s.confirm(ctx, tx, realmID, userID, flowID, code, actor, requestID)
	if errors.Is(err, errRejected) {
		s.logger().DebugContext(ctx, "totp enrollment failed", "error", err)
		return port.TOTPCredential{}, ErrAuthFailed
	}
	return c, err
}

func (s *Service) confirm(ctx context.Context, tx port.Tx, realmID, userID, flowID, code string, actor audit.Actor, requestID string) (port.TOTPCredential, error) {
	if flowID == "" {
		return port.TOTPCredential{}, fmt.Errorf("%w: flow id is required", errRejected)
	}
	if err := s.PerUser.Allow(ctx, "totp:"+realmID+":"+userID); err != nil {
		return port.TOTPCredential{}, err
	}
	b, ok, err := s.Cache.Take(ctx, flowKey(flowID))
	if err != nil {
		return port.TOTPCredential{}, err
	}
	if !ok {
		return port.TOTPCredential{}, fmt.Errorf("%w: unknown or used flow", errRejected)
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return port.TOTPCredential{}, err
	}
	var st enrollment
	if err := json.Unmarshal(pt, &st); err != nil {
		return port.TOTPCredential{}, err
	}
	now := s.Clock.Now()
	if st.RealmID != realmID || subtle.ConstantTimeCompare([]byte(st.UserID), []byte(userID)) != 1 || !now.Before(st.ExpiresAt) {
		return port.TOTPCredential{}, fmt.Errorf("%w: flow expired or for another user", errRejected)
	}
	step, ok := Verify(st.Secret, code, now)
	if !ok {
		if st.Attempts++; st.Attempts < s.maxAttempts() {
			if err := s.put(ctx, flowID, st); err != nil {
				return port.TOTPCredential{}, err
			}
		}
		return port.TOTPCredential{}, fmt.Errorf("%w: code mismatch", errRejected)
	}
	if err := active(ctx, tx, realmID, userID); err != nil {
		return port.TOTPCredential{}, err
	}
	ct, err := s.Crypter.Encrypt(ctx, tx.DataKeys(), userID, st.Secret, secretAAD)
	if err != nil {
		return port.TOTPCredential{}, err
	}
	c := port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: realmID, UserID: userID,
		SecretCiphertext: ct, LastUsedStep: step, CreatedAt: now}
	if err := tx.TOTP().Create(ctx, c); err != nil {
		return port.TOTPCredential{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "totp.registered", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"totp_id": c.PublicID},
	})
	return c, err
}

// Verify はユーザーの有効な TOTP のどれかでコードを確かめ、使った TOTP を返す。使った時間窓を記録し、
// 同じか前の窓のコードは拒否する。呼び出し側のトランザクションで呼ぶ。コードの不一致と再利用は ErrAuthFailed
// （上限を超えれば *ratelimit.ExceededError）。基盤の障害はそのまま返す。
func (s *Service) Verify(ctx context.Context, tx port.Tx, realmID, userID, code string) (port.TOTPCredential, error) {
	if err := s.PerUser.Allow(ctx, "totp:"+realmID+":"+userID); err != nil {
		return port.TOTPCredential{}, err
	}
	c, err := s.verify(ctx, tx, realmID, userID, code)
	if errors.Is(err, errRejected) || errors.Is(err, errs.Conflict) {
		s.logger().DebugContext(ctx, "totp verification failed", "error", err)
		return port.TOTPCredential{}, ErrAuthFailed
	}
	return c, err
}

func (s *Service) verify(ctx context.Context, tx port.Tx, realmID, userID, code string) (port.TOTPCredential, error) {
	cs, err := tx.TOTP().ListByUser(ctx, realmID, userID)
	if err != nil {
		return port.TOTPCredential{}, err
	}
	now := s.Clock.Now()
	for _, c := range cs {
		if c.RevokedAt != nil {
			continue
		}
		secret, err := s.Crypter.Decrypt(ctx, tx.DataKeys(), userID, c.SecretCiphertext, secretAAD)
		if err != nil {
			return port.TOTPCredential{}, err
		}
		if step, ok := Verify(secret, code, now); ok {
			if err := tx.TOTP().Use(ctx, realmID, c.ID, step); err != nil {
				return port.TOTPCredential{}, err // 再利用（Conflict）を含む
			}
			c.LastUsedStep = step
			return c, nil
		}
	}
	return port.TOTPCredential{}, fmt.Errorf("%w: no totp matched", errRejected)
}

// active は有効な TOTP があれば ErrTOTPExists を返す。
func active(ctx context.Context, tx port.Tx, realmID, userID string) error {
	cs, err := tx.TOTP().ListByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.RevokedAt == nil {
			return ErrTOTPExists
		}
	}
	return nil
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
