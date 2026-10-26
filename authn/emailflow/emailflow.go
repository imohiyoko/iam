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
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
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
	// PerAccount はアドレスごとの開始の回数の上限（通知の送りつけと総当たりを防ぐ）。nil なら制限しない。
	PerAccount *ratelimit.Limiter
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
	purposeAdd    = "add_email" // ログイン済みのユーザーがメールを足す（4.2）
	// purposeRecovery は確認済みのメールによるアカウントの復旧（4.12）。復旧専用のセッションを出す。
	purposeRecovery = "recovery"
)

// state はフローの状態。EphemeralStore に暗号化して置く。
type state struct {
	RealmID   string    `json:"realm_id"`
	Purpose   string    `json:"purpose"`
	UserID    string    `json:"user_id,omitempty"`
	PublicID  string    `json:"public_id,omitempty"`
	EmailID   string    `json:"email_id,omitempty"`
	Email     string    `json:"email,omitempty"` // 登録と追加のときだけ（所有確認が済むまでアドレスを置かないため）
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
	if err := s.limit(ctx, realmID, email, c); err != nil {
		return Started{}, err
	}
	flowID, code, link, err := secrets()
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
	return s.store(ctx, flowID, st)
}

// secrets はフロー ID、コード、リンクのトークンを作る。
func secrets() (flowID, code, link string, err error) {
	if flowID, err = randomToken(); err != nil {
		return
	}
	if code, err = randomCode(); err != nil {
		return
	}
	link, err = randomToken()
	return
}

// store はフローの状態を封をして EphemeralStore に置く。
func (s *Service) store(ctx context.Context, flowID string, st state) (Started, error) {
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

// StartAdd は、ログイン済みのユーザー（内部 ID）が足すメールの所有確認を始める。
// アドレスが別のユーザーで使われていても、所有を確かめるまでは同じ応答を返す（4.9）。
// 本人のメールなら ErrEmailExists。realm で `code` が無効なら account.ErrViaNotAllowed。
func (s *Service) StartAdd(ctx context.Context, realmID, userID, email string, c Client) (Started, error) {
	if !s.Accounts.Allows(port.VerifiedViaCode) {
		return Started{}, account.ErrViaNotAllowed
	}
	email, err := account.NormalizeEmail(email)
	if err != nil {
		return Started{}, err
	}
	if err := s.limit(ctx, realmID, email, c); err != nil {
		return Started{}, err
	}
	flowID, code, link, err := secrets()
	if err != nil {
		return Started{}, err
	}
	now := s.Clock.Now()
	st := state{RealmID: realmID, Purpose: purposeAdd, UserID: userID, Email: email,
		CodeHash: digest(code), LinkHash: digest(link), ExpiresAt: now.Add(s.ttl())}
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, realmID, userID)
		if err != nil {
			return err
		}
		st.PublicID = u.PublicID
		switch e, err := s.Accounts.FindByEmail(ctx, tx, realmID, email); {
		case err == nil && e.UserID == userID:
			return account.ErrEmailExists
		case err != nil && !errors.Is(err, errs.NotFound):
			return err
		}
		n := port.Notification{Type: notify.TypeEmailVerification, RealmID: realmID, UserID: u.PublicID}
		if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: email, Code: code, Token: link, ExpiresAt: st.ExpiresAt}); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "email.verification.requested", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Details: map[string]any{"purpose": purposeAdd},
		})
		return err
	})
	if err != nil {
		return Started{}, err
	}
	return s.store(ctx, flowID, st)
}

// limit はアドレスごとの回数を数える。登録の有無に関係なく数えるので、制限されたことからアカウントの有無は分からない。
// キーはブラインドインデックスにし、アドレスそのものを EphemeralStore に置かない。
func (s *Service) limit(ctx context.Context, realmID, email string, c Client) error {
	if s.PerAccount == nil {
		return nil
	}
	idx, err := s.Crypter.EmailIndex(ctx, email)
	if err != nil {
		return err
	}
	err = s.PerAccount.Allow(ctx, "email:"+realmID+":"+base64.RawURLEncoding.EncodeToString(idx.Value))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok && ex.First {
		if aerr := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
				Type: "rate_limit.triggered", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
				IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
				Details: map[string]any{"scope": "account", "endpoint": "login.email.start"},
			})
			return err
		}); aerr != nil {
			s.logger().WarnContext(ctx, "could not record rate limit", "error", aerr)
		}
	}
	return err
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
		// 警告による拒否は本人確認の後なので、理由を返す（4.9）。
		if denied, ok := errors.AsType[errs.Denial](err); ok {
			return Verified{}, denied
		}
		return Verified{}, ErrAuthFailed
	}
	return out, nil
}

// take はコードかリンクをフローの状態と照合し、合えばフローを使い終える（1回限り）。
// 照合に使った方式（code / link）も返す。accept が受け付けないフロー（目的やユーザーが違う）は失敗にする。
func (s *Service) take(ctx context.Context, realmID string, in Verify, accept func(state) bool) (state, string, error) {
	if in.FlowID == "" || (in.Code == "") == (in.LinkToken == "") {
		return state{}, "", errors.New("flow id and exactly one of code or link token are required")
	}
	key := flowKey(in.FlowID)
	b, ok, err := s.Cache.Get(ctx, key)
	if err != nil {
		return state{}, "", err
	}
	if !ok {
		return state{}, "", errors.New("flow not found")
	}
	pt, err := s.Crypter.Open(ctx, "flow.email", b)
	if err != nil {
		return state{}, "", err
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil {
		return state{}, "", err
	}
	now := s.Clock.Now()
	if st.RealmID != realmID || !now.Before(st.ExpiresAt) {
		return state{}, "", errors.New("flow expired or in another realm")
	}
	if !accept(st) {
		return state{}, "", errors.New("flow is for another purpose or user")
	}
	// 試行回数はフローごとに数え、上限を超えたらフローを捨てる。
	n, err := s.Cache.Incr(ctx, key+":tries", st.ExpiresAt.Sub(now))
	if err != nil {
		return state{}, "", err
	}
	if n > s.maxAttempts() {
		_ = s.Cache.Delete(ctx, key)
		return state{}, "", errors.New("too many attempts")
	}
	method := "code"
	match := subtle.ConstantTimeCompare(digest(in.Code), st.CodeHash) == 1
	if in.LinkToken != "" {
		method = "link"
		match = subtle.ConstantTimeCompare(digest(in.LinkToken), st.LinkHash) == 1
	}
	if !match {
		return state{}, "", errors.New("code mismatch")
	}
	// 1回限り：取り出せた要求だけが続ける（同時の照合は1つだけ通る）。
	if _, ok, err := s.Cache.Take(ctx, key); err != nil || !ok {
		return state{}, "", errors.New("flow already used")
	}
	return st, method, nil
}

func (s *Service) verify(ctx context.Context, realmID string, in Verify) (Verified, error) {
	st, method, err := s.take(ctx, realmID, in, func(st state) bool { return st.Purpose == purposeLogin || st.Purpose == purposeSignup })
	if err != nil {
		return Verified{}, err
	}
	now := s.Clock.Now()
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
		if _, err := account.Check(ctx, tx, u, now, now); err != nil {
			return err
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
	if err == nil {
		s.Sessions.Committed(ctx, realmID, out.Session)
	}
	return out, err
}

// VerifyAdd は、ログイン済みのユーザー（内部 ID）がメールの追加のフローを完了する。
// 照合の失敗は ErrAuthFailed。所有を確かめた後、アドレスが使われていれば account.ErrEmailExists を返す。
func (s *Service) VerifyAdd(ctx context.Context, realmID, userID string, in Verify) (port.UserEmail, error) {
	st, _, err := s.take(ctx, realmID, in, func(st state) bool { return st.Purpose == purposeAdd && st.UserID == userID })
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		return port.UserEmail{}, ErrAuthFailed
	}
	var e port.UserEmail
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		e, err = s.Accounts.AddEmail(ctx, tx, realmID, userID, st.Email, port.VerifiedViaCode,
			audit.Actor{Type: "user", ID: st.PublicID}, in.Client.RequestID)
		return err
	})
	return e, err
}

// StartRecovery は確認済みのメールによる復旧（4.12）を始める。確認済みのアドレスにだけコードとリンクを送り、
// 応答はアカウントの有無で変えない（4.9）。
func (s *Service) StartRecovery(ctx context.Context, realmID, email string, c Client) (Started, error) {
	email, err := account.NormalizeEmail(email)
	if err != nil {
		return Started{}, err
	}
	if err := s.limit(ctx, realmID, email, c); err != nil {
		return Started{}, err
	}
	flowID, code, link, err := secrets()
	if err != nil {
		return Started{}, err
	}
	now := s.Clock.Now()
	st := state{RealmID: realmID, Purpose: purposeRecovery, CodeHash: digest(code), LinkHash: digest(link), ExpiresAt: now.Add(s.ttl())}
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e, err := s.Accounts.FindByEmail(ctx, tx, realmID, email)
		switch {
		case err == nil && e.VerifiedAt != nil:
			u, err := tx.Users().Get(ctx, realmID, e.UserID)
			if err != nil {
				return err
			}
			st.UserID, st.PublicID, st.EmailID = u.ID, u.PublicID, e.ID
			n := port.Notification{Type: notify.TypeAccountRecovery, RealmID: realmID, UserID: u.PublicID}
			if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: email, Code: code, Token: link, ExpiresAt: st.ExpiresAt}); err != nil {
				return err
			}
		case err == nil, errors.Is(err, errs.NotFound):
		default:
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "recovery.email.requested", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"user_id": st.PublicID, "sent": st.UserID != ""},
		})
		return err
	})
	if err != nil {
		return Started{}, err
	}
	return s.store(ctx, flowID, st)
}

// VerifyRecovery は復旧のフローのコードかリンクを照合し、復旧専用のセッションを発行する（警告 recovered_via_email を評価する）。
// 失敗は ErrAuthFailed、停止（security_risk 以外）や警告の deny は errs.Denial。
func (s *Service) VerifyRecovery(ctx context.Context, realmID string, in Verify) (Verified, error) {
	out, err := s.verifyRecovery(ctx, realmID, in)
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		if denied, ok := errors.AsType[errs.Denial](err); ok {
			return Verified{}, denied
		}
		return Verified{}, ErrAuthFailed
	}
	s.Sessions.Committed(ctx, realmID, out.Session)
	return out, nil
}

func (s *Service) verifyRecovery(ctx context.Context, realmID string, in Verify) (Verified, error) {
	st, method, err := s.take(ctx, realmID, in, func(st state) bool { return st.Purpose == purposeRecovery && st.UserID != "" })
	if err != nil {
		return Verified{}, err
	}
	now := s.Clock.Now()
	var out Verified
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, realmID, st.UserID)
		if err != nil {
			return err
		}
		if _, err := account.Check(ctx, tx, u, now, now, account.RecoveryIgnores...); err != nil {
			return err
		}
		// 開始の後にメールが外されていれば通さない。
		es, err := tx.Emails().ListByUser(ctx, realmID, u.ID)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(es, func(e port.UserEmail) bool { return e.ID == st.EmailID && e.VerifiedAt != nil })
		if i < 0 {
			return errors.New("email no longer verified for user")
		}
		e := es[i]
		is, err := s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: []string{"otp"}, Credentials: []string{e.ID}, Recovery: true,
			Evidence: warning.Evidence{RecoveredViaEmail: true},
			IP:       in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, ReplaceToken: in.ReplaceToken,
		})
		if err != nil {
			return err
		}
		out.Session, out.UserID = is, u.PublicID
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "recovery.started", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: is.Session.ID, IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID,
			Details: map[string]any{"via": "email", "method": "email_" + method},
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
