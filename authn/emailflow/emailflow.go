// Package emailflow はメールのコード・マジックリンクによる登録とログインを行う（design.md 4.1）。
//
// セキュリティ上重要なコード（13.2）。不変条件（13.5）：
//   - コード・リンクは要求したフローの外で通らない。フロー ID は要求した側（Cookie か API の応答）にだけ渡し、
//     通知には含めない。コード・リンクの照合はフローの状態に対して行う
//   - 有効期限（既定 10 分）、1回限り、試行回数の上限。IAM にはコード・リンクのハッシュだけを置く
//   - 本人確認の前は、アカウントの有無や状態で応答を変えない。登録済みならログイン、未登録なら登録の
//     通知を送り、どちらも同じ応答を返す（4.9）
//   - 未ログインでメールが一致しても、別の認証手段に自動リンクしない（4.2）
package emailflow

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
	"math/big"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Config はフローの設定。
type Config struct {
	TTL         time.Duration // 既定 10 分
	MaxAttempts int           // コードの試行回数の上限（既定 5）
}

// Service はメールのフローを扱う。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	Notify   *notify.Service
	Config   Config
	Log      *slog.Logger
}

// Client は要求の接続元（監査ログとセッションに残す）。
type Client struct {
	IP, UserAgent, RequestID string
}

// ErrAuthFailed は本人確認の失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "email flow failed")

const (
	purposeLogin  = "login"
	purposeSignup = "signup"
)

// state はフローの状態。EphemeralStore に暗号化して置く。
type state struct {
	RealmID   string    `json:"realm_id"`
	Purpose   string    `json:"purpose"`
	UserID    string    `json:"user_id,omitempty"`
	PublicID  string    `json:"public_id,omitempty"`
	EmailID   string    `json:"email_id,omitempty"`
	Email     string    `json:"email,omitempty"` // 登録時のみ（所有確認が済むまでユーザーを作らないため）
	CodeHash  []byte    `json:"code_hash"`
	LinkHash  []byte    `json:"link_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func flowKey(flowID string) string {
	return "flow:email:v1:" + base64.RawURLEncoding.EncodeToString(digest(flowID))
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (s *Service) ttl() time.Duration {
	if s.Config.TTL <= 0 {
		return 10 * time.Minute
	}
	return s.Config.TTL
}

func (s *Service) maxAttempts() int64 {
	if s.Config.MaxAttempts <= 0 {
		return 5
	}
	return int64(s.Config.MaxAttempts)
}

// Started は開始したフロー。FlowID は要求した側にだけ渡す秘密。
type Started struct {
	FlowID    string
	ExpiresAt time.Time
}

// Start はフローを始め、コードとリンクを通知する。アカウントの有無で応答を変えない。
// realm で `code` の経路が無効なら、通知を送らない（応答は同じ）。
func (s *Service) Start(ctx context.Context, realmID, email string, c Client) (Started, error) {
	email, err := account.NormalizeEmail(email)
	if err != nil {
		return Started{}, err
	}
	flowID, err := randomToken()
	if err != nil {
		return Started{}, err
	}
	code, err := randomCode()
	if err != nil {
		return Started{}, err
	}
	link, err := randomToken()
	if err != nil {
		return Started{}, err
	}
	now := s.Clock.Now()
	st := state{RealmID: realmID, CodeHash: digest(code), LinkHash: digest(link), ExpiresAt: now.Add(s.ttl())}
	send := s.Accounts.Allows(port.VerifiedViaCode)

	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e, err := s.Accounts.FindByEmail(ctx, tx, realmID, email)
		switch {
		case err == nil:
			u, err := tx.Users().Get(ctx, realmID, e.UserID)
			if err != nil {
				return err
			}
			st.Purpose, st.UserID, st.PublicID, st.EmailID = purposeLogin, u.ID, u.PublicID, e.ID
		case errors.Is(err, errs.NotFound):
			st.Purpose, st.Email = purposeSignup, email
		default:
			return err
		}
		if send {
			n := port.Notification{Type: notify.TypeEmailVerification, RealmID: realmID}
			if st.Purpose == purposeLogin {
				n.Type, n.UserID = notify.TypeMagicLink, st.PublicID
			}
			if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: email, Code: code, Token: link, ExpiresAt: st.ExpiresAt}); err != nil {
				return err
			}
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.email.requested", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"purpose": st.Purpose, "user_id": st.PublicID, "sent": send},
		})
		return err
	})
	if err != nil {
		return Started{}, err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return Started{}, err
	}
	sealed, err := s.Crypter.Seal(ctx, "flow.email", b)
	if err != nil {
		return Started{}, err
	}
	if err := s.Cache.Set(ctx, flowKey(flowID), sealed, s.ttl()); err != nil {
		return Started{}, err
	}
	return Started{FlowID: flowID, ExpiresAt: st.ExpiresAt}, nil
}

// Verify はフローを完了する入力。Code か LinkToken のどちらか。
type Verify struct {
	FlowID    string
	Code      string
	LinkToken string
	Client    Client
	// ReplaceToken はブラウザが持っていた古いセッション（ログイン時に ID を入れ替える）。
	ReplaceToken string
}

// Verified は完了したフロー。
type Verified struct {
	Session session.Issued
	UserID  string // 公開 ID
	Created bool   // 新規登録だったか
}

// Verify はコードかリンクを照合し、成功すればユーザーを作るかログインさせ、セッションを発行する。
func (s *Service) Verify(ctx context.Context, realmID string, in Verify) (Verified, error) {
	out, err := s.verify(ctx, realmID, in)
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		return Verified{}, ErrAuthFailed
	}
	return out, nil
}

func (s *Service) verify(ctx context.Context, realmID string, in Verify) (Verified, error) {
	if in.FlowID == "" || (in.Code == "") == (in.LinkToken == "") {
		return Verified{}, errors.New("flow id and exactly one of code or link token are required")
	}
	key := flowKey(in.FlowID)
	b, ok, err := s.Cache.Get(ctx, key)
	if err != nil {
		return Verified{}, err
	}
	if !ok {
		return Verified{}, errors.New("flow not found")
	}
	pt, err := s.Crypter.Open(ctx, "flow.email", b)
	if err != nil {
		return Verified{}, err
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil {
		return Verified{}, err
	}
	now := s.Clock.Now()
	if st.RealmID != realmID || !now.Before(st.ExpiresAt) {
		return Verified{}, errors.New("flow expired or in another realm")
	}
	// 試行回数はフローごとに数え、上限を超えたらフローを捨てる。
	n, err := s.Cache.Incr(ctx, key+":tries", st.ExpiresAt.Sub(now))
	if err != nil {
		return Verified{}, err
	}
	if n > s.maxAttempts() {
		_ = s.Cache.Delete(ctx, key)
		return Verified{}, errors.New("too many attempts")
	}
	method := "code"
	match := subtle.ConstantTimeCompare(digest(in.Code), st.CodeHash) == 1
	if in.LinkToken != "" {
		method = "link"
		match = subtle.ConstantTimeCompare(digest(in.LinkToken), st.LinkHash) == 1
	}
	if !match {
		return Verified{}, errors.New("code mismatch")
	}
	// 1回限り：取り出せた要求だけが続ける（同時の照合は1つだけ通る）。
	if _, ok, err := s.Cache.Take(ctx, key); err != nil || !ok {
		return Verified{}, errors.New("flow already used")
	}

	var out Verified
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		userID, emailID := st.UserID, st.EmailID
		if st.Purpose == purposeSignup {
			c, err := s.Accounts.CreateWithEmail(ctx, tx, realmID, st.Email, port.VerifiedViaCode, audit.Actor{}, in.Client.RequestID)
			switch {
			case err == nil:
				userID, emailID, out.Created = c.User.ID, c.Email.ID, true
			case errors.Is(err, errs.Conflict):
				// 開始から完了までの間に同じアドレスが登録された。所有は確認できたので、そのユーザーとしてログインする。
				e, ferr := s.Accounts.FindByEmail(ctx, tx, realmID, st.Email)
				if ferr != nil {
					return ferr
				}
				userID, emailID = e.UserID, e.ID
			default:
				return err
			}
		}
		u, err := tx.Users().Get(ctx, realmID, userID)
		if err != nil {
			return err
		}
		if !account.CanLogin(u, now) {
			return errors.New("user cannot log in")
		}
		is, err := s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: userID, AuthMethods: []string{"otp"}, Credentials: []string{emailID},
			IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, ReplaceToken: in.ReplaceToken,
		})
		if err != nil {
			return err
		}
		out.Session, out.UserID = is, u.PublicID
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: is.Session.ID, IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID,
			Details: map[string]any{"method": "email_" + method, "signup": out.Created},
		})
		return err
	})
	return out, err
}

// recordFailure は失敗を監査ログに残す（理由の種別は内部向け。6.1）。
func (s *Service) recordFailure(ctx context.Context, realmID string, c Client, cause error) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"method": "email", "reason": cause.Error()},
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
