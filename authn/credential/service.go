// Package credential は認証方式のプラグイン（port.Authenticator）を呼ぶコアのサービス（ADR 0090、0092）。
//
// 方式に認証情報のストア（authn/method.Store。realm と方式に閉じ、データはユーザーのデータ鍵で暗号化する）を渡し、方式の
// フローの状態を封をして EphemeralStore に置き、結果を既存のセッションの発行（1要素目は authn/session の Issue、2要素目は
// CompleteSecondFactor。ADR 0050）につなぐ。方式は Storage・EphemeralStore・セッションを直接触らない。
//
// セキュリティ上重要なコード（13.2）。本人確認の前の失敗は理由を区別しない ErrAuthFailed にし（4.9）、フローは1回限りで、
// 照合の回数に上限を置く。
package credential

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/authn/method"
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

// ErrAuthFailed は照合の失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "credential verification failed")

// ErrUnknownMethod は、方式が無い・動いていない・その用途に使えないこと（404）。
var ErrUnknownMethod = errs.New(errs.KindNotFound, "authentication method")

// errRejected はフローの不一致（未知・期限切れ・別人・別の方式のフロー）。外には ErrAuthFailed として返す。
var errRejected = errors.New("credential flow rejected")

const sealPurpose = "flow.method"

// 用途ごとのフローの種類。別の種類のフローは使えない。
const (
	purposeLogin        = "login"
	purposeSecondFactor = "second_factor"
	purposeEnroll       = "enroll"
)

// Service は方式を呼び、結果をセッションにつなぐ。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	// Methods は動いている方式。nil なら方式が無い。
	Methods *method.Set
	// Issuer は認証器に表示する発行者の名前（登録）。
	Issuer string
	// TTL はフローの期限（既定 10 分）。MaxAttempts はフローごとの照合の回数の上限（既定 5）。
	TTL         time.Duration
	MaxAttempts int
	// PerUser はユーザーごとの照合の回数の上限（2要素目と登録。総当たりの防止）。nil なら制限しない。
	PerUser *ratelimit.Limiter
	// PerLogin はログイン ID（メールアドレス）ごと・接続元ごとの照合の回数の上限（ログイン ID で本人を決める方式。ADR 0101）。
	// nil なら制限しない。
	PerLogin *ratelimit.Limiter
	// Lockout はアカウント単位のロックアウト（フィーチャー account_lockout。ADR 0105）。ログイン ID で本人を決める1要素目は
	// メールアドレスごと、2要素目はユーザーごとに、接続元を問わず失敗を数える。nil なら数えない。
	Lockout *lockout.Guard
	Log     *slog.Logger
}

// Client は要求の接続元（監査ログとセッション）。
type Client struct{ IP, UserAgent, RequestID string }

// Challenge は始めたフロー。Payload は方式がクライアントに返すもの。
type Challenge struct {
	FlowID    string
	Payload   json.RawMessage
	ExpiresAt time.Time
}

// flow はフローの状態。方式の状態（秘密を含みうる）を持つので EphemeralStore に封をして置く。
type flow struct {
	RealmID   string    `json:"realm_id"`
	UserID    string    `json:"user_id"`
	Method    string    `json:"method"`
	Purpose   string    `json:"purpose"`
	State     []byte    `json:"state,omitempty"`
	Recovery  bool      `json:"recovery,omitempty"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

func flowKey(flowID string) string {
	h := sha256.Sum256([]byte(flowID))
	return "flow:method:v1:" + base64.RawURLEncoding.EncodeToString(h[:])
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

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Method は用途 u に使える、動いている方式を返す。無ければ ErrUnknownMethod。u が空なら用途を問わない（登録）。
func (s *Service) Method(name string, u port.MethodUsage) (port.Authenticator, error) {
	a, ok := s.Methods.Get(name)
	if !ok || (u != "" && !a.Info().Supports(u)) {
		return nil, ErrUnknownMethod
	}
	return a, nil
}

// env は方式に渡す環境。tx が nil なら、認証情報のストアは操作ごとに短いトランザクションで動く（方式の重い計算を、直列にした
// トランザクションの外で行うため。ADR 0101）。
func (s *Service) env(ctx context.Context, tx port.Tx, realmID, userID string, a port.Authenticator, u port.MethodUsage) port.MethodEnv {
	now := s.Clock.Now()
	st := &method.Store{Tx: tx, Crypter: s.Crypter, RealmID: realmID, Info: a.Info(), Now: now}
	if tx == nil {
		st.Storage = s.Storage
	}
	return port.MethodEnv{RealmID: realmID, UserID: userID, Usage: u, Now: now, Issuer: s.Issuer, Credentials: st,
		ClientCertificates: ClientCertificates(ctx)}
}

type clientCertsKey struct{}

// WithClientCertificates は要求で受け取ったクライアント証明書の連鎖（DER。先頭が本人の証明書）を ctx に載せる。HTTP の層が、
// mTLS の専用の待ち受けか、信じたプロキシのヘッダーから取り出して呼ぶ（ADR 0103）。方式には MethodEnv.ClientCertificates で渡す。
func WithClientCertificates(ctx context.Context, chain [][]byte) context.Context {
	return context.WithValue(ctx, clientCertsKey{}, chain)
}

// ClientCertificates は WithClientCertificates で載せた連鎖を返す（無ければ nil）。
func ClientCertificates(ctx context.Context) [][]byte {
	c, _ := ctx.Value(clientCertsKey{}).([][]byte)
	return c
}

// loginUsers は1要素目でログイン ID から本人を引き当てる（port.MethodUsers）。引き当てたメールとユーザーを覚え、発行する
// セッションをそのメールに結び付ける。
type loginUsers struct {
	s       *Service
	realmID string
	ip      string
	userID  string
	emailID string
	// subject はロックアウトの対象（メールアドレスのブラインドインデックス）。ロックアウトが無いか、ログイン ID を引かない方式なら空。
	subject string
}

// LoginUser は確認済みのメールの、ログインできる状態のユーザーを返す。それ以外は errs.NotFound（理由を区別しない。4.9）。
// ログイン ID ごと（接続元ごと）の回数の上限を先に数える。
func (l *loginUsers) LoginUser(ctx context.Context, identifier string) (string, error) {
	email, err := account.NormalizeEmail(identifier)
	if err != nil {
		return "", errs.New(errs.KindNotFound, "user")
	}
	if l.s.PerLogin != nil || l.s.Lockout != nil {
		ix, err := l.s.Crypter.EmailIndex(ctx, email)
		if err != nil {
			return "", err
		}
		subject := base64.RawURLEncoding.EncodeToString(ix.Value)
		if l.s.PerLogin != nil {
			if err := l.s.PerLogin.AllowFrom(ctx, "login:"+l.realmID+":"+subject, l.ip); err != nil {
				return "", err
			}
		}
		// ロックアウトは無いアドレスも同じに数える（有無を漏らさない。ADR 0105）。待ち時間とロックの間は照合しない。
		if l.s.Lockout != nil {
			if err := l.s.Lockout.Check(ctx, l.realmID, lockout.ScopeLoginID, subject); err != nil {
				return "", err
			}
			l.subject = subject
		}
	}
	err = l.s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e, err := l.s.Accounts.FindByEmail(ctx, tx, l.realmID, email)
		if err != nil {
			return err
		}
		if e.VerifiedAt == nil {
			return errs.New(errs.KindNotFound, "user")
		}
		u, err := tx.Users().Get(ctx, l.realmID, e.UserID)
		if err != nil {
			return err
		}
		if u.Status != port.UserActive {
			return errs.New(errs.KindNotFound, "user")
		}
		l.userID, l.emailID = u.ID, e.ID
		return nil
	})
	if err != nil {
		l.userID, l.emailID = "", ""
		return "", err
	}
	return l.userID, nil
}

// payload は方式の Payload を応答の形（nil なら {}）にする。
func payload(p json.RawMessage) json.RawMessage {
	if len(p) == 0 {
		return json.RawMessage("{}")
	}
	return p
}

// rejectedByUser は、利用者の入力による失敗（方式の照合の失敗、再利用、フローの不一致）か。
func rejectedByUser(err error) bool {
	return errors.Is(err, errRejected) || errors.Is(err, errs.AuthenticationFailed)
}

// Begin はログインのフローを始める。usage が 2要素目なら userID（内部 ID）の本人のフロー、1要素目なら userID は空。
// 方式が送信（Deliver）を返せば送り、失敗すれば port.ErrDeliveryFailed を返す（ADR 0104）。
func (s *Service) Begin(ctx context.Context, realmID, userID, name string, usage port.MethodUsage, p json.RawMessage, c Client) (Challenge, error) {
	a, err := s.Method(name, usage)
	if err != nil {
		return Challenge{}, err
	}
	purpose := purposeLogin
	if usage != port.UsageFirstFactor {
		if userID == "" {
			return Challenge{}, ErrAuthFailed
		}
		purpose = purposeSecondFactor
	} else {
		userID = ""
	}
	env := s.env(ctx, nil, realmID, userID, a, usage)
	env.ClientIP = c.IP
	ch, err := a.Begin(ctx, env, port.MethodRequest{Payload: p})
	// 1要素目の前は、方式が本人の有無を返しても区別しない（4.9）。2要素目は本人確認の後なので、方式の認証情報が無ければ 404。
	if errors.Is(err, errs.AuthenticationFailed) || (err != nil && usage == port.UsageFirstFactor && errors.Is(err, errs.NotFound)) {
		return Challenge{}, ErrAuthFailed
	}
	if err != nil {
		return Challenge{}, err
	}
	if err := s.deliver(ctx, realmID, name, ch, c); err != nil {
		return Challenge{}, err
	}
	return s.start(ctx, flow{RealmID: realmID, UserID: userID, Method: name, Purpose: purpose, State: ch.State}, ch.Payload)
}

// deliver は方式の送信を行い、方式の監査ログを記録する。送信に失敗すれば method.delivery_failed を記録して
// port.ErrDeliveryFailed を返す（理由は外に返さない）。
func (s *Service) deliver(ctx context.Context, realmID, name string, ch port.MethodChallenge, c Client) error {
	if ch.Deliver != nil {
		if err := ch.Deliver(ctx); err != nil {
			s.logger().WarnContext(ctx, "method delivery failed", "method", name, "error", err)
			var userID string
			if len(ch.Events) > 0 {
				userID = ch.Events[0].UserID
			}
			s.record(ctx, realmID, "", c, []port.MethodEvent{{Type: "delivery_failed", UserID: userID, Failure: true,
				Details: map[string]any{"method": name}}})
			return fmt.Errorf("%w: %w", port.ErrDeliveryFailed, err)
		}
	}
	s.record(ctx, realmID, name, c, ch.Events)
	return nil
}

// record は方式の監査ログを記録する（ADR 0104）。種類は method.<方式>.<出来事>（name が空なら method.<出来事>）。
// 記録の失敗はログに残すだけにする（送信は済んでいる）。
func (s *Service) record(ctx context.Context, realmID, name string, c Client, events []port.MethodEvent) {
	if len(events) == 0 {
		return
	}
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.recordTx(ctx, tx, realmID, name, c, events)
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record method events", "method", name, "error", err)
	}
}

func (s *Service) recordTx(ctx context.Context, tx port.Tx, realmID, name string, c Client, events []port.MethodEvent) error {
	for _, e := range events {
		typ := "method." + e.Type
		if name != "" {
			typ = method.EventType(name, e.Type)
		}
		if typ == "" || (name == "" && !method.ValidName(e.Type)) {
			return fmt.Errorf("credential: method %s returned an invalid event type %q", name, e.Type)
		}
		actor := audit.Actor{Type: "anonymous"}
		if e.UserID != "" {
			u, err := tx.Users().Get(ctx, realmID, e.UserID)
			if err != nil {
				return err
			}
			actor = audit.Actor{Type: "user", ID: u.PublicID}
		}
		result := audit.ResultSuccess
		if e.Failure {
			result = audit.ResultFailure
		}
		if _, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: typ, Result: result, RealmID: realmID, Actor: actor, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: e.Details,
		}); err != nil {
			return err
		}
	}
	return nil
}

// pending は、別の経路からの応答を待っているフローを、回数を数えずに置き直す（ADR 0104）。
func (s *Service) pending(ctx context.Context, flowID string, f flow) error {
	if err := s.put(ctx, flowID, f); err != nil {
		return err
	}
	return port.ErrMethodPending
}

// Callback は別の経路（本人の端末など）からの応答を方式に渡す（ADR 0104）。方式が port.CallbackAuthenticator でなければ
// ErrUnknownMethod。照合の失敗は ErrAuthFailed。方式はトランザクションの外で呼び、監査ログは後で記録する。
func (s *Service) Callback(ctx context.Context, realmID, name string, p json.RawMessage, c Client) (json.RawMessage, error) {
	a, err := s.Method(name, "")
	if err != nil {
		return nil, err
	}
	cb, ok := a.(port.CallbackAuthenticator)
	if !ok {
		return nil, ErrUnknownMethod
	}
	env := s.env(ctx, nil, realmID, "", a, "")
	env.ClientIP = c.IP
	r, err := cb.Callback(ctx, env, port.MethodRequest{Payload: p})
	if errors.Is(err, errs.AuthenticationFailed) || errors.Is(err, errs.NotFound) {
		s.logger().DebugContext(ctx, "method callback rejected", "method", name, "error", err)
		return nil, ErrAuthFailed
	}
	if err != nil {
		return nil, err
	}
	s.record(ctx, realmID, name, c, r.Events)
	return payload(r.Payload), nil
}

func (s *Service) start(ctx context.Context, f flow, p json.RawMessage) (Challenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Challenge{}, err
	}
	flowID := base64.RawURLEncoding.EncodeToString(b)
	f.ExpiresAt = s.Clock.Now().Add(s.ttl())
	if err := s.put(ctx, flowID, f); err != nil {
		return Challenge{}, err
	}
	return Challenge{FlowID: flowID, Payload: payload(p), ExpiresAt: f.ExpiresAt}, nil
}

func (s *Service) put(ctx context.Context, flowID string, f flow) error {
	raw, err := json.Marshal(f) // #nosec G117 -- 方式の状態は Crypter で封をしてから置く
	if err != nil {
		return err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, raw)
	if err != nil {
		return err
	}
	ttl := f.ExpiresAt.Sub(s.Clock.Now())
	if ttl <= 0 {
		return nil
	}
	return s.Cache.Set(ctx, flowKey(flowID), sealed, ttl)
}

// take はフローを取り出し（1回限り）、realm・本人・方式・種類・期限を確かめる。
func (s *Service) take(ctx context.Context, flowID, realmID, userID, name, purpose string) (flow, error) {
	if flowID == "" {
		return flow{}, fmt.Errorf("%w: flow id is required", errRejected)
	}
	b, ok, err := s.Cache.Take(ctx, flowKey(flowID))
	if err != nil {
		return flow{}, err
	}
	if !ok {
		return flow{}, fmt.Errorf("%w: unknown or used flow", errRejected)
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return flow{}, err
	}
	var f flow
	if err := json.Unmarshal(pt, &f); err != nil {
		return flow{}, err
	}
	if f.RealmID != realmID || subtle.ConstantTimeCompare([]byte(f.UserID), []byte(userID)) != 1 || f.Method != name ||
		f.Purpose != purpose || !s.Clock.Now().Before(f.ExpiresAt) {
		return flow{}, fmt.Errorf("%w: flow expired or for another user, method or purpose", errRejected)
	}
	return f, nil
}

// retry は照合に失敗したフローを、回数の上限まで同じ ID で置き直す。チャレンジを1回限りにする方式（passkey。ADR 0106）は
// 置き直さない。
func (s *Service) retry(ctx context.Context, flowID string, f flow) {
	if a, ok := s.Methods.Get(f.Method); !ok || a.Info().OneShot {
		return
	}
	if f.Attempts++; f.Attempts >= s.maxAttempts() {
		return
	}
	if err := s.put(ctx, flowID, f); err != nil {
		s.logger().WarnContext(ctx, "could not keep the method flow", "error", err)
	}
}

// used は方式が返した認証情報を Storage から読み直し、realm・方式・持ち主（userID が空でなければ）が合い、有効で、方式が確かめた
// 後に書き換わっていない（暗号文が同じ）ことを確かめて最終使用を記録する。方式はトランザクションの外で確かめるので、その間の
// 変更・無効化をここで拒む。
func (s *Service) used(ctx context.Context, tx port.Tx, realmID, userID, name string, r port.MethodResult) (port.Credential, error) {
	c, err := tx.Credentials().Get(ctx, realmID, r.Credential.ID)
	if errors.Is(err, errs.NotFound) {
		return port.Credential{}, fmt.Errorf("%w: method returned an unknown credential", errRejected)
	}
	if err != nil {
		return port.Credential{}, err
	}
	if c.Method != name || c.RevokedAt != nil || (userID != "" && c.UserID != userID) {
		return port.Credential{}, fmt.Errorf("%w: credential revoked or for another user or method", errRejected)
	}
	if !bytes.Equal(c.Data, r.Credential.Sealed) {
		return port.Credential{}, fmt.Errorf("%w: credential changed after verification", errRejected)
	}
	return c, tx.Credentials().Used(ctx, realmID, c.ID, s.Clock.Now())
}

func amr(a port.Authenticator, r port.MethodResult) []string {
	if len(r.AMR) > 0 {
		return slices.Clone(r.AMR)
	}
	return slices.Clone(a.Info().AMR)
}

// Login は1要素目のフローを完了し、セッションを発行する（2要素目が要れば制限つきのセッション。ADR 0050）。
// 失敗は ErrAuthFailed（停止などは errs.Denial、上限を超えれば *ratelimit.ExceededError）。返す文字列はユーザーの公開 ID。
func (s *Service) Login(ctx context.Context, realmID, name, flowID string, p json.RawMessage, c Client, replaceToken string) (session.Issued, string, error) {
	if _, err := s.Method(name, port.UsageFirstFactor); err != nil {
		return session.Issued{}, "", err
	}
	f, err := s.take(ctx, flowID, realmID, "", name, purposeLogin)
	if err != nil {
		return session.Issued{}, "", s.fail(ctx, realmID, name, c, err)
	}
	is, publicID, err := s.login(ctx, realmID, name, f.State, p, c, replaceToken)
	if errors.Is(err, port.ErrMethodPending) {
		return session.Issued{}, "", s.pending(ctx, flowID, f)
	}
	if rejectedByUser(err) {
		s.retry(ctx, flowID, f)
	}
	if err != nil {
		return session.Issued{}, "", s.fail(ctx, realmID, name, c, err)
	}
	return is, publicID, nil
}

// LoginOnce は、チャレンジの無い方式（パスワード）の1要素目を、フローを使わずに1回の要求で完了する（方式専用の互換のパス。
// ADR 0101）。失敗は Login と同じ。
func (s *Service) LoginOnce(ctx context.Context, realmID, name string, p json.RawMessage, c Client, replaceToken string) (session.Issued, string, error) {
	a, err := s.Method(name, port.UsageFirstFactor)
	if err != nil {
		return session.Issued{}, "", err
	}
	ch, err := a.Begin(ctx, s.env(ctx, nil, realmID, "", a, port.UsageFirstFactor), port.MethodRequest{})
	if err == nil && len(ch.State) > 0 {
		err = fmt.Errorf("credential: method %s needs a challenge", name)
	}
	if err == nil {
		var is session.Issued
		var publicID string
		if is, publicID, err = s.login(ctx, realmID, name, nil, p, c, replaceToken); err == nil {
			return is, publicID, nil
		}
	}
	return session.Issued{}, "", s.fail(ctx, realmID, name, c, err)
}

// login は方式の Complete をトランザクションの外で呼び、使った認証情報を確かめてセッションを発行する。
func (s *Service) login(ctx context.Context, realmID, name string, state []byte, p json.RawMessage, c Client, replaceToken string) (session.Issued, string, error) {
	a, err := s.Method(name, port.UsageFirstFactor)
	if err != nil {
		return session.Issued{}, "", err
	}
	users := &loginUsers{s: s, realmID: realmID, ip: c.IP}
	env := s.env(ctx, nil, realmID, "", a, port.UsageFirstFactor)
	env.Users, env.ClientIP = users, c.IP
	var is session.Issued
	var publicID string
	r, err := a.Complete(ctx, env, port.MethodRequest{Payload: p, State: state})
	// ロックアウトは方式の照合の結果で数える（停止・有効期間の外などの、照合が通った後の拒否は数えない）。
	if users.subject != "" {
		if lerr := s.lockoutResult(ctx, realmID, lockout.ScopeLoginID, users.subject, users.userID, err, c); lerr != nil {
			return session.Issued{}, "", lerr
		}
	}
	if err == nil {
		err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			cred, err := s.used(ctx, tx, realmID, users.userID, name, r)
			if err != nil {
				return err
			}
			u, err := tx.Users().Get(ctx, realmID, cred.UserID)
			if err != nil {
				return err
			}
			// 停止と有効期間は照合が通った後に見る（本人確認の後なので理由を返す。4.9）。
			now := s.Clock.Now()
			if _, err := account.Check(ctx, tx, u, now, now); err != nil {
				return err
			}
			// ログイン ID で本人を決めた方式（パスワード）は、セッションを引き当てたメールに結び付ける（従来どおり。パスワードの
			// 置き換えと削除は、今のセッション以外をまとめて失効させる）。それ以外は使った認証情報に結び付ける。
			bound := []string{cred.ID}
			if users.emailID != "" {
				bound = []string{users.emailID}
			}
			if is, err = s.Sessions.Issue(ctx, tx, session.Issue{RealmID: realmID, UserID: u.ID, AuthMethods: amr(a, r), Credentials: bound,
				Evidence: warning.Evidence{PasswordBreached: r.KnowledgeBreached},
				IP:       c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, ReplaceToken: replaceToken}); err != nil {
				return err
			}
			publicID = u.PublicID
			details := map[string]any{}
			for k, v := range r.Details {
				details[k] = v
			}
			details["method"], details["credential_id"] = name, cred.PublicID
			_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
				Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
				SessionID: is.Session.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Details: details,
			})
			return err
		})
	}
	if err != nil {
		// 認証情報・ユーザーが無い、ログインできない状態（削除済みなど）は、照合の失敗と区別しない（4.9）。
		if errors.Is(err, account.ErrInactive) || errors.Is(err, errs.NotFound) {
			err = fmt.Errorf("%w: %w", errRejected, err)
		}
		return session.Issued{}, "", err
	}
	s.Sessions.Committed(ctx, realmID, is)
	return is, publicID, nil
}

// lockoutResult は方式の照合の結果（cause）をロックアウトに数える。利用者の入力による失敗なら数え、成功なら失敗の回数を消す
// （基盤の障害は数えない）。この失敗でロックし、ユーザー（内部 ID。無いアドレスなら空）が分かれば監査ログに残す。
func (s *Service) lockoutResult(ctx context.Context, realmID, scope, subject, userID string, cause error, c Client) error {
	switch {
	case s.Lockout == nil:
		return nil
	case cause == nil:
		return s.Lockout.Succeeded(ctx, realmID, scope, subject)
	case !rejectedByUser(cause):
		return nil
	}
	l, err := s.Lockout.Failed(ctx, realmID, scope, subject)
	if err != nil || l == nil || userID == "" {
		return err
	}
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, realmID, userID)
		if err != nil {
			return err
		}
		return lockout.RecordLocked(ctx, tx, s.Clock, realmID, u.PublicID, scope, l, c.IP, c.UserAgent, c.RequestID)
	})
	if err != nil {
		// ロックはかかっている。記録できなかったことだけを残す。
		s.logger().WarnContext(ctx, "could not record account lock", "error", err)
	}
	return nil
}

// fail は1要素目の失敗を監査ログに残し、利用者の入力による失敗を ErrAuthFailed にする。本人確認の後の拒否（errs.Denial）は、
// 方式が詳細を付けたもの（認証器のポリシーなど。port.MethodAuditDetails）だけを残す。
func (s *Service) fail(ctx context.Context, realmID, name string, c Client, cause error) error {
	_, denied := errors.AsType[errs.Denial](cause)
	_, limited := errors.AsType[*ratelimit.ExceededError](cause)
	_, detailed := errors.AsType[port.MethodAuditDetails](cause)
	if (!denied && !limited) || detailed {
		s.recordFailure(ctx, realmID, "login.failed", name, c, cause)
	}
	if rejectedByUser(cause) {
		return ErrAuthFailed
	}
	return cause
}

// recordFailure は失敗を監査ログに残す（理由は内部向け。6.1）。方式が詳細を付けていれば（port.MethodAuditDetails）足す。
func (s *Service) recordFailure(ctx context.Context, realmID, typ, name string, c Client, cause error) {
	// 方式の詳細は reason（判定の理由のコード）を上書きしてよい。
	details := map[string]any{"method": name, "reason": cause.Error()}
	if d, ok := errors.AsType[port.MethodAuditDetails](cause); ok {
		for k, v := range d.AuditDetails() {
			details[k] = v
		}
	}
	details["method"] = name
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: typ, Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Details: details,
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record failure", "type", typ, "error", err)
	}
}

// EnrollFailed は登録の完了の失敗を監査ログに残す（呼び出し側のトランザクションが戻った後に呼ぶ）。passkey は従来どおり
// passkey.registration_failed を残し、ほかの方式は詳細を付けた失敗（port.MethodAuditDetails）だけを credential.registration_failed
// で残す（ADR 0106）。回数の上限と、方式の無いことは残さない。
func (s *Service) EnrollFailed(ctx context.Context, realmID, name string, c Client, cause error) {
	_, limited := errors.AsType[*ratelimit.ExceededError](cause)
	_, detailed := errors.AsType[port.MethodAuditDetails](cause)
	if cause == nil || limited || errors.Is(cause, ErrUnknownMethod) || (name != method.Passkey && !detailed) {
		return
	}
	typ := "credential.registration_failed"
	if name == method.Passkey {
		typ = "passkey.registration_failed"
	}
	s.recordFailure(ctx, realmID, typ, name, c, cause)
}

// SecondFactor は2要素目のフローを完了し、制限つきのセッション sessionID を通常のセッションに替える（ADR 0050）。
// 失敗は ErrAuthFailed（上限を超えれば *ratelimit.ExceededError、停止などは errs.Denial）。
func (s *Service) SecondFactor(ctx context.Context, realmID, userID, sessionID, name, flowID string, p json.RawMessage, c Client) (session.Issued, error) {
	a, err := s.Method(name, port.UsageSecondFactor)
	if err != nil {
		return session.Issued{}, err
	}
	// 別の経路から応答が届く方式は、クライアントの入力を照合しないので照合の回数で数えない（ADR 0104）。
	if !a.Info().OutOfBand {
		if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
			return session.Issued{}, err
		}
	}
	if err := s.Lockout.Check(ctx, realmID, lockout.ScopeSecondFactor, userID); err != nil {
		return session.Issued{}, err
	}
	f, err := s.take(ctx, flowID, realmID, userID, name, purposeSecondFactor)
	if err != nil {
		s.logger().DebugContext(ctx, "second factor rejected", "method", name, "error", err)
		return session.Issued{}, ErrAuthFailed
	}
	is, err := s.secondFactor(ctx, realmID, userID, sessionID, name, f.State, p, c)
	if errors.Is(err, port.ErrMethodPending) {
		return session.Issued{}, s.pending(ctx, flowID, f)
	}
	if rejectedByUser(err) {
		s.retry(ctx, flowID, f)
	}
	return is, err
}

// SecondFactorOnce は、チャレンジの無い方式（TOTP）の2要素目を、フローを使わずに1回の要求で完了する（方式専用の互換のパス
// `/v1/login/second-factor:verify`。ADR 0101）。失敗は SecondFactor と同じ。
func (s *Service) SecondFactorOnce(ctx context.Context, realmID, userID, sessionID, name string, p json.RawMessage, c Client) (session.Issued, error) {
	a, err := s.Method(name, port.UsageSecondFactor)
	if err != nil {
		return session.Issued{}, err
	}
	if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
		return session.Issued{}, err
	}
	if err := s.Lockout.Check(ctx, realmID, lockout.ScopeSecondFactor, userID); err != nil {
		return session.Issued{}, err
	}
	ch, err := a.Begin(ctx, s.env(ctx, nil, realmID, userID, a, port.UsageSecondFactor), port.MethodRequest{})
	switch {
	case errors.Is(err, errs.NotFound), errors.Is(err, errs.AuthenticationFailed):
		s.logger().DebugContext(ctx, "second factor rejected", "method", name, "error", err)
		return session.Issued{}, ErrAuthFailed
	case err != nil:
		return session.Issued{}, err
	case len(ch.State) > 0:
		return session.Issued{}, fmt.Errorf("credential: method %s needs a challenge", name)
	}
	return s.secondFactor(ctx, realmID, userID, sessionID, name, nil, p, c)
}

func (s *Service) secondFactor(ctx context.Context, realmID, userID, sessionID, name string, state []byte, p json.RawMessage, c Client) (session.Issued, error) {
	a, err := s.Method(name, port.UsageSecondFactor)
	if err != nil {
		return session.Issued{}, err
	}
	var is session.Issued
	env := s.env(ctx, nil, realmID, userID, a, port.UsageSecondFactor)
	env.ClientIP = c.IP
	r, err := a.Complete(ctx, env, port.MethodRequest{Payload: p, State: state})
	if lerr := s.lockoutResult(ctx, realmID, lockout.ScopeSecondFactor, userID, userID, err, c); lerr != nil {
		return session.Issued{}, lerr
	}
	if err == nil {
		err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			cred, err := s.used(ctx, tx, realmID, userID, name, r)
			if err != nil {
				return err
			}
			is, err = s.Sessions.CompleteSecondFactor(ctx, tx, realmID, sessionID, session.SecondFactor{
				AMR: amr(a, r), CredentialID: cred.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			})
			return err
		})
	}
	if err != nil {
		if _, ok := errors.AsType[port.MethodAuditDetails](err); ok {
			// 本人確認の後の、方式の判定による拒否（認証器のポリシーなど）。トランザクションは戻ったので、ここで残す。
			s.recordFailure(ctx, realmID, "login.failed", name, c, err)
		}
		if rejectedByUser(err) {
			s.logger().DebugContext(ctx, "second factor rejected", "method", name, "error", err)
			return session.Issued{}, ErrAuthFailed
		}
		return session.Issued{}, err
	}
	s.Sessions.Committed(ctx, realmID, is)
	return is, nil
}

// EnrollOptions は登録の呼び出しの条件。
type EnrollOptions struct {
	// Recovery は復旧専用のセッションでの登録（今の秘密を求めない再設定。4.12）。
	Recovery bool
	// RecentAuth は本人の認証が直近（max_auth_age の内）か。
	RecentAuth bool
	// Client は要求の接続元（方式の接続元ごとの制限と、送信の監査ログ。ADR 0104）。
	Client Client
}

// EnrollBegin は本人（内部 ID）の、方式 name の登録を始める。方式はトランザクションの外で呼ぶ（パスワードのハッシュなど）。
// 知識の要素は、始めで今の秘密を照合しうるので、本人ごとの回数の上限を掛ける。
func (s *Service) EnrollBegin(ctx context.Context, realmID, userID, name string, p json.RawMessage, o EnrollOptions) (Challenge, error) {
	a, err := s.Method(name, "")
	if err != nil {
		return Challenge{}, err
	}
	if a.Info().Kind == port.FactorKnowledge {
		if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
			return Challenge{}, err
		}
	}
	e := s.env(ctx, nil, realmID, userID, a, "")
	e.RecentAuth, e.ClientIP = o.RecentAuth, o.Client.IP
	if o.Recovery {
		e.Usage = port.UsageRecovery
	}
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		e.Account, e.UserPublicID, err = s.accountName(ctx, tx, realmID, userID)
		return err
	}); err != nil {
		return Challenge{}, err
	}
	ch, err := a.EnrollBegin(ctx, e, port.MethodRequest{Payload: p})
	if err != nil {
		return Challenge{}, err
	}
	if err := s.deliver(ctx, realmID, name, ch, o.Client); err != nil {
		return Challenge{}, err
	}
	return s.start(ctx, flow{RealmID: realmID, UserID: userID, Method: name, Purpose: purposeEnroll, State: ch.State, Recovery: o.Recovery}, ch.Payload)
}

// accountName は認証器に表示する本人の名前（primary のメールアドレス。最小化モードなら公開 ID）と、本人の公開 ID を返す。
func (s *Service) accountName(ctx context.Context, tx port.Tx, realmID, userID string) (string, string, error) {
	u, err := tx.Users().Get(ctx, realmID, userID)
	if err != nil {
		return "", "", err
	}
	es, err := tx.Emails().ListByUser(ctx, realmID, userID)
	if err != nil {
		return "", "", err
	}
	for _, e := range es {
		if e.IsPrimary && len(e.Ciphertext) > 0 {
			addr, err := s.Accounts.EmailAddress(ctx, tx, e)
			return addr, u.PublicID, err
		}
	}
	return u.PublicID, u.PublicID, nil
}

// Enrolled は登録の結果。
type Enrolled struct {
	Credential port.Credential
	Payload    json.RawMessage
	// RevokedSessions は、知識の要素の登録で失効させた、ほかのセッションの ID（確定の後に Sessions.ForgetIDs に渡す）。
	RevokedSessions []string
}

// EnrollInput は登録の完了の入力。
type EnrollInput struct {
	RealmID, UserID, Method, FlowID string
	Payload                         json.RawMessage
	Actor                           audit.Actor
	RequestID                       string
	// KeepSession は、知識の要素（パスワード）の登録で失効させないセッション（今のセッション。5.2）。
	KeepSession string
}

// EnrollComplete は登録を完了する。呼び出し側のトランザクションで呼ぶ。確認に失敗すれば ErrAuthFailed（回数の上限まではフローを
// 残す。ただしトランザクションの外のことなので、呼び出し側が失敗で終えたときにだけ意味を持つ）。知識の要素（パスワード）の登録は、
// 復旧専用のセッションでなければ、KeepSession 以外の本人のセッションを失効させる（5.2）。
func (s *Service) EnrollComplete(ctx context.Context, tx port.Tx, in EnrollInput) (Enrolled, error) {
	realmID, userID, name := in.RealmID, in.UserID, in.Method
	a, err := s.Method(name, "")
	if err != nil {
		return Enrolled{}, err
	}
	// 知識の要素は始め（今の秘密の照合）で数えたので、ここでは数えない。
	if a.Info().Kind != port.FactorKnowledge {
		if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
			return Enrolled{}, err
		}
	}
	f, err := s.take(ctx, in.FlowID, realmID, userID, name, purposeEnroll)
	if err != nil {
		s.logger().DebugContext(ctx, "enrollment rejected", "method", name, "error", err)
		return Enrolled{}, ErrAuthFailed
	}
	e := s.env(ctx, tx, realmID, userID, a, "")
	if f.Recovery {
		e.Usage = port.UsageRecovery
	}
	en, err := a.EnrollComplete(ctx, e, port.MethodRequest{Payload: in.Payload, State: f.State})
	if errors.Is(err, errs.AuthenticationFailed) {
		s.retry(ctx, in.FlowID, f)
		s.logger().DebugContext(ctx, "enrollment rejected", "method", name, "error", err)
		return Enrolled{}, ErrAuthFailed
	}
	if err != nil {
		return Enrolled{}, err
	}
	c, err := tx.Credentials().Get(ctx, realmID, en.Credential.ID)
	if err != nil {
		return Enrolled{}, fmt.Errorf("credential: method returned an unknown credential: %w", err)
	}
	if c.UserID != userID || c.Method != name || c.RevokedAt != nil {
		return Enrolled{}, fmt.Errorf("credential: method %s enrolled a credential for another user or method", name)
	}
	// passkey は従来どおり passkey.registered で残す（SIEM の対応表。ADR 0106）。
	typ, details := "credential.registered", map[string]any{}
	if name == method.Passkey {
		typ = "passkey.registered"
	}
	for k, v := range en.Details {
		details[k] = v
	}
	details["credential_id"], details["method"] = c.PublicID, name
	if _, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: in.Actor, RequestID: in.RequestID, Details: details,
	}); err != nil {
		return Enrolled{}, err
	}
	out := Enrolled{Credential: c, Payload: payload(en.Payload)}
	if a.Info().Kind == port.FactorKnowledge && !f.Recovery {
		out.RevokedSessions, err = s.Sessions.RevokeAllTx(ctx, tx, realmID, userID, in.KeepSession, session.ReasonCredentialChanged, in.Actor, in.RequestID)
	}
	return out, err
}
