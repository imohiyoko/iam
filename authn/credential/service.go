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
	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/session"
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

func (s *Service) env(ctx context.Context, tx port.Tx, realmID, userID string, a port.Authenticator, u port.MethodUsage) port.MethodEnv {
	now := s.Clock.Now()
	e := port.MethodEnv{RealmID: realmID, UserID: userID, Usage: u, Now: now, Issuer: s.Issuer, ClientCertificates: ClientCertificates(ctx)}
	if tx != nil {
		e.Credentials = &method.Store{Tx: tx, Crypter: s.Crypter, RealmID: realmID, Info: a.Info(), Now: now}
	}
	return e
}

// preflight は、方式が Preflighter なら、トランザクションの外で確かめを行う（ADR 0103）。そうでなければ nil。
func (s *Service) preflight(ctx context.Context, realmID, userID string, a port.Authenticator, u port.MethodUsage, req port.MethodRequest) ([]byte, error) {
	p, ok := a.(port.Preflighter)
	if !ok {
		return nil, nil
	}
	return p.Preflight(ctx, s.env(ctx, nil, realmID, userID, a, u), req)
}

// PreflightEnroll は登録の完了（EnrollComplete）の前に、トランザクションの外で方式の確かめを行う。結果を EnrollComplete に渡す。
// 確かめに失敗すれば ErrAuthFailed。
func (s *Service) PreflightEnroll(ctx context.Context, realmID, userID, name string, p json.RawMessage) ([]byte, error) {
	a, err := s.Method(name, "")
	if err != nil {
		return nil, err
	}
	pre, err := s.preflight(ctx, realmID, userID, a, "", port.MethodRequest{Payload: p})
	if errors.Is(err, errs.AuthenticationFailed) {
		s.logger().DebugContext(ctx, "enrollment rejected", "method", name, "error", err)
		return nil, ErrAuthFailed
	}
	return pre, err
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
func (s *Service) Begin(ctx context.Context, realmID, userID, name string, usage port.MethodUsage, p json.RawMessage) (Challenge, error) {
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
	var ch port.MethodChallenge
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ch, err = a.Begin(ctx, s.env(ctx, tx, realmID, userID, a, usage), port.MethodRequest{Payload: p})
		return err
	})
	// 1要素目の前は、方式が本人の有無を返しても区別しない（4.9）。2要素目は本人確認の後なので、方式の認証情報が無ければ 404。
	if errors.Is(err, errs.AuthenticationFailed) || (err != nil && usage == port.UsageFirstFactor && errors.Is(err, errs.NotFound)) {
		return Challenge{}, ErrAuthFailed
	}
	if err != nil {
		return Challenge{}, err
	}
	return s.start(ctx, flow{RealmID: realmID, UserID: userID, Method: name, Purpose: purpose, State: ch.State}, ch.Payload)
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

// retry は照合に失敗したフローを、回数の上限まで同じ ID で置き直す。
func (s *Service) retry(ctx context.Context, flowID string, f flow) {
	if f.Attempts++; f.Attempts >= s.maxAttempts() {
		return
	}
	if err := s.put(ctx, flowID, f); err != nil {
		s.logger().WarnContext(ctx, "could not keep the method flow", "error", err)
	}
}

// used は方式が返した認証情報を Storage から読み直し、realm・方式・持ち主（userID が空でなければ）が合い、有効なことを確かめて
// 最終使用を記録する。
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
	a, err := s.Method(name, port.UsageFirstFactor)
	if err != nil {
		return session.Issued{}, "", err
	}
	f, err := s.take(ctx, flowID, realmID, "", name, purposeLogin)
	if err != nil {
		return session.Issued{}, "", s.fail(ctx, realmID, name, c, err)
	}
	var is session.Issued
	var publicID string
	req := port.MethodRequest{Payload: p, State: f.State}
	req.Preflight, err = s.preflight(ctx, realmID, "", a, port.UsageFirstFactor, req)
	if err == nil {
		err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			return s.login(ctx, tx, a, realmID, name, req, c, replaceToken, &is, &publicID)
		})
	}
	if err != nil {
		// 認証情報・ユーザーが無い、ログインできない状態（削除済みなど）は、照合の失敗と区別しない（4.9）。
		if errors.Is(err, account.ErrInactive) || errors.Is(err, errs.NotFound) {
			err = fmt.Errorf("%w: %w", errRejected, err)
		}
		if rejectedByUser(err) {
			s.retry(ctx, flowID, f)
		}
		return session.Issued{}, "", s.fail(ctx, realmID, name, c, err)
	}
	s.Sessions.Committed(ctx, realmID, is)
	return is, publicID, nil
}

// login は1要素目の照合とセッションの発行（Login のトランザクションの中）。
func (s *Service) login(ctx context.Context, tx port.Tx, a port.Authenticator, realmID, name string, req port.MethodRequest, c Client, replaceToken string,
	is *session.Issued, publicID *string) error {
	r, err := a.Complete(ctx, s.env(ctx, tx, realmID, "", a, port.UsageFirstFactor), req)
	if err != nil {
		return err
	}
	cred, err := s.used(ctx, tx, realmID, "", name, r)
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
	if *is, err = s.Sessions.Issue(ctx, tx, session.Issue{RealmID: realmID, UserID: u.ID, AuthMethods: amr(a, r), Credentials: []string{cred.ID},
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, ReplaceToken: replaceToken}); err != nil {
		return err
	}
	*publicID = u.PublicID
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
		SessionID: is.Session.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
		Details: map[string]any{"method": name, "credential_id": cred.PublicID},
	})
	return err
}

// fail は1要素目の失敗を監査ログに残し、利用者の入力による失敗を ErrAuthFailed にする。
func (s *Service) fail(ctx context.Context, realmID, name string, c Client, cause error) error {
	if _, ok := errors.AsType[errs.Denial](cause); !ok {
		err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
				Type: "login.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
				IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
				Details: map[string]any{"method": name, "reason": cause.Error()},
			})
			return err
		})
		if err != nil {
			s.logger().WarnContext(ctx, "could not record login failure", "error", err)
		}
	}
	if rejectedByUser(cause) {
		return ErrAuthFailed
	}
	return cause
}

// SecondFactor は2要素目のフローを完了し、制限つきのセッション sessionID を通常のセッションに替える（ADR 0050）。
// 失敗は ErrAuthFailed（上限を超えれば *ratelimit.ExceededError、停止などは errs.Denial）。
func (s *Service) SecondFactor(ctx context.Context, realmID, userID, sessionID, name, flowID string, p json.RawMessage, c Client) (session.Issued, error) {
	a, err := s.Method(name, port.UsageSecondFactor)
	if err != nil {
		return session.Issued{}, err
	}
	if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
		return session.Issued{}, err
	}
	f, err := s.take(ctx, flowID, realmID, userID, name, purposeSecondFactor)
	if err != nil {
		s.logger().DebugContext(ctx, "second factor rejected", "method", name, "error", err)
		return session.Issued{}, ErrAuthFailed
	}
	var is session.Issued
	req := port.MethodRequest{Payload: p, State: f.State}
	if req.Preflight, err = s.preflight(ctx, realmID, userID, a, port.UsageSecondFactor, req); err == nil {
		err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			return s.secondFactor(ctx, tx, a, realmID, userID, sessionID, name, req, c, &is)
		})
	}
	if err != nil {
		if rejectedByUser(err) {
			s.retry(ctx, flowID, f)
			s.logger().DebugContext(ctx, "second factor rejected", "method", name, "error", err)
			return session.Issued{}, ErrAuthFailed
		}
		return session.Issued{}, err
	}
	s.Sessions.Committed(ctx, realmID, is)
	return is, nil
}

// secondFactor は2要素目の照合とセッションの切り替え（SecondFactor のトランザクションの中）。
func (s *Service) secondFactor(ctx context.Context, tx port.Tx, a port.Authenticator, realmID, userID, sessionID, name string, req port.MethodRequest,
	c Client, is *session.Issued) error {
	r, err := a.Complete(ctx, s.env(ctx, tx, realmID, userID, a, port.UsageSecondFactor), req)
	if err != nil {
		return err
	}
	cred, err := s.used(ctx, tx, realmID, userID, name, r)
	if err != nil {
		return err
	}
	*is, err = s.Sessions.CompleteSecondFactor(ctx, tx, realmID, sessionID, session.SecondFactor{
		AMR: amr(a, r), CredentialID: cred.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
	})
	return err
}

// EnrollBegin は本人（内部 ID）の、方式 name の登録を始める。
func (s *Service) EnrollBegin(ctx context.Context, realmID, userID, name string, p json.RawMessage) (Challenge, error) {
	a, err := s.Method(name, "")
	if err != nil {
		return Challenge{}, err
	}
	var ch port.MethodChallenge
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e := s.env(ctx, tx, realmID, userID, a, "")
		if e.Account, err = s.accountName(ctx, tx, realmID, userID); err != nil {
			return err
		}
		ch, err = a.EnrollBegin(ctx, e, port.MethodRequest{Payload: p})
		return err
	})
	if err != nil {
		return Challenge{}, err
	}
	return s.start(ctx, flow{RealmID: realmID, UserID: userID, Method: name, Purpose: purposeEnroll, State: ch.State}, ch.Payload)
}

// accountName は認証器に表示する本人の名前（primary のメールアドレス。最小化モードなら公開 ID）。
func (s *Service) accountName(ctx context.Context, tx port.Tx, realmID, userID string) (string, error) {
	u, err := tx.Users().Get(ctx, realmID, userID)
	if err != nil {
		return "", err
	}
	es, err := tx.Emails().ListByUser(ctx, realmID, userID)
	if err != nil {
		return "", err
	}
	for _, e := range es {
		if e.IsPrimary && len(e.Ciphertext) > 0 {
			return s.Accounts.EmailAddress(ctx, tx, e)
		}
	}
	return u.PublicID, nil
}

// Enrolled は登録の結果。
type Enrolled struct {
	Credential port.Credential
	Payload    json.RawMessage
}

// EnrollComplete は登録を完了する。呼び出し側のトランザクションで呼ぶ。pre は PreflightEnroll の結果（方式が Preflighter のとき）。確認に失敗すれば ErrAuthFailed（回数の上限まではフローを
// 残す。ただしトランザクションの外のことなので、呼び出し側が失敗で終えたときにだけ意味を持つ）。
func (s *Service) EnrollComplete(ctx context.Context, tx port.Tx, realmID, userID, name, flowID string, p, pre json.RawMessage, actor audit.Actor, requestID string) (Enrolled, error) {
	a, err := s.Method(name, "")
	if err != nil {
		return Enrolled{}, err
	}
	if err := s.PerUser.Allow(ctx, "method:"+name+":"+realmID+":"+userID); err != nil {
		return Enrolled{}, err
	}
	f, err := s.take(ctx, flowID, realmID, userID, name, purposeEnroll)
	if err != nil {
		s.logger().DebugContext(ctx, "enrollment rejected", "method", name, "error", err)
		return Enrolled{}, ErrAuthFailed
	}
	e := s.env(ctx, tx, realmID, userID, a, "")
	en, err := a.EnrollComplete(ctx, e, port.MethodRequest{Payload: p, State: f.State, Preflight: pre})
	if errors.Is(err, errs.AuthenticationFailed) {
		s.retry(ctx, flowID, f)
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
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "credential.registered", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"credential_id": c.PublicID, "method": name},
	})
	return Enrolled{Credential: c, Payload: payload(en.Payload)}, err
}
