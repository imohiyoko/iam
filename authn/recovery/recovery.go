// Package recovery はアカウントの復旧を扱う（design.md 4.12、ADR 0054）。
//
// リカバリーコードは最初の強い認証手段（passkey・TOTP）の登録時に10個作り、表示は1回だけ。argon2id のハッシュを持つ。
// コードの先頭の数文字は平文の lookup で、照合するハッシュを1つに絞る（10個すべてを argon2id で照合しない）。
// 復旧の経路（リカバリーコード・確認済みメール・運営者の復旧リンク）は、どれも復旧専用のセッションを出す。
// そのセッションでは新しい認証手段の登録と復旧の完了しかできず、完了で全セッションを失効させ、コードを作り直す。
//
// セキュリティ上重要なコード（13.2）。コードはログ・監査ログ・エラーに出さない。
package recovery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

const (
	// Count は1組のコードの数。
	Count = 10
	// lookupLen は lookup の文字数、secretLen は残りの文字数（Crockford の base32。合わせて 80 ビット）。
	lookupLen = 4
	secretLen = 12
	alphabet  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// AMR はリカバリーコードでの復旧の amr（RFC 8176 に無いため独自の値。要素の数には数えない）。
const AMR = "rec"

// 復旧の経路（監査ログと通知の via）。
const (
	ViaCode  = "recovery_code"
	ViaEmail = "email"
	ViaLink  = "operator_link"
)

// ErrAuthFailed は復旧の要求の失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "recovery failed")

// ErrNoNewMethod は、復旧専用のセッションで新しい認証手段をまだ登録していないこと。
var ErrNoNewMethod = errs.WithCode(errs.KindFailedPrecondition, "new_method_required", "register a new sign-in method before completing recovery")

// ErrNotRecovery は、復旧専用のセッションでないこと。
var ErrNotRecovery = errs.WithCode(errs.KindFailedPrecondition, "not_recovery_session", "session is not a recovery session")

// Service はリカバリーコードと復旧の完了を扱う。
type Service struct {
	Storage  port.Storage
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	Notify   *notify.Service
	// Params はコードのハッシュのパラメータ。零値なら password.DefaultParams。
	Params password.Params
	// PerAccount はメールアドレスごとのコードの照合の回数の上限。nil なら制限しない。
	PerAccount *ratelimit.Limiter
	Log        *slog.Logger

	dummyOnce sync.Once
	dummy     string
}

// Client は監査ログに残す接続元。
type Client struct{ IP, UserAgent, RequestID string }

func (s *Service) params() password.Params {
	if s.Params == (password.Params{}) {
		return password.DefaultParams
	}
	return s.Params
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, c := range b {
		out[i] = alphabet[c&31] // 256 は 32 で割り切れるので偏らない
	}
	return string(out), nil
}

// format は表示の形（4文字ずつハイフンで区切る）。
func format(c string) string {
	var b strings.Builder
	for i := 0; i < len(c); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(c[i:min(i+4, len(c))])
	}
	return b.String()
}

// normalize は入力を正規化する（大文字にし、区切りを除き、Crockford の読み替え O→0、I・L→1 をする）。
func normalize(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch {
		case r == '-' || r == ' ':
		case r == 'O':
			b.WriteByte('0')
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r < 128 && strings.ContainsRune(alphabet, r):
			b.WriteRune(r)
		default:
			return ""
		}
	}
	return b.String()
}

// Generate はユーザー（内部 ID）のコードを作り直し、表示用のコードを返す（古いコードは使えなくなる）。
// 呼び出し側のトランザクションで呼ぶ。
func (s *Service) Generate(ctx context.Context, tx port.Tx, realmID, userID string, actor audit.Actor, requestID string) ([]string, error) {
	now := s.Clock.Now()
	codes := make([]port.RecoveryCode, 0, Count)
	shown := make([]string, 0, Count)
	seen := map[string]bool{}
	for len(codes) < Count {
		lookup, err := randomString(lookupLen)
		if err != nil {
			return nil, err
		}
		if seen[lookup] {
			continue
		}
		seen[lookup] = true
		secret, err := randomString(secretLen)
		if err != nil {
			return nil, err
		}
		h, err := password.Hash(lookup+secret, s.params())
		if err != nil {
			return nil, err
		}
		codes = append(codes, port.RecoveryCode{ID: id.New(id.RecoveryCode), RealmID: realmID, UserID: userID, Lookup: lookup, Hash: h, CreatedAt: now})
		shown = append(shown, format(lookup+secret))
	}
	if err := tx.RecoveryCodes().Replace(ctx, realmID, userID, codes); err != nil {
		return nil, err
	}
	subject, err := tx.Users().Get(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "recovery_codes.generated", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"user_id": subject.PublicID, "count": Count},
	})
	return shown, err
}

// Initial は最初の強い認証手段の登録の後に呼ぶ。コードを持っていなければ作って返し、持っていれば nil を返す。
func (s *Service) Initial(ctx context.Context, tx port.Tx, realmID, userID string, actor audit.Actor, requestID string) ([]string, error) {
	cs, err := tx.RecoveryCodes().ListByUser(ctx, realmID, userID)
	if err != nil || len(cs) > 0 {
		return nil, err
	}
	return s.Generate(ctx, tx, realmID, userID, actor, requestID)
}

// Remaining は未使用のコードの数を返す。
func Remaining(ctx context.Context, tx port.Tx, realmID, userID string) (int, error) {
	cs, err := tx.RecoveryCodes().ListByUser(ctx, realmID, userID)
	n := 0
	for _, c := range cs {
		if c.UsedAt == nil {
			n++
		}
	}
	return n, err
}

// dummyHash は、アカウントやコードが無いときにも同じ重さの照合をするためのハッシュ（応答時間から有無を読ませない）。
func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() {
		s.dummy, _ = password.Hash("not a recovery code", s.params())
	})
	return s.dummy
}

// Redeem は確認済みのメールアドレスとリカバリーコードで照合し、復旧専用のセッションを発行する。コードは使い終える。
// 失敗は ErrAuthFailed（回数の上限を超えれば *ratelimit.ExceededError、停止などは errs.Denial）。
func (s *Service) Redeem(ctx context.Context, realmID, email, code string, c Client, replaceToken string) (session.Issued, string, error) {
	email, err := account.NormalizeEmail(email)
	if err != nil {
		return session.Issued{}, "", ErrAuthFailed
	}
	if s.PerAccount != nil {
		ix, err := s.Crypter.EmailIndex(ctx, email)
		if err != nil {
			return session.Issued{}, "", err
		}
		if err := s.PerAccount.Allow(ctx, "recovery:"+realmID+":"+base64.RawURLEncoding.EncodeToString(ix.Value)); err != nil {
			return session.Issued{}, "", err
		}
	}
	is, uid, err := s.redeem(ctx, realmID, email, normalize(code), c, replaceToken)
	if err != nil {
		s.recordFailure(ctx, realmID, c, err)
		if d, ok := errors.AsType[errs.Denial](err); ok {
			return session.Issued{}, "", d
		}
		return session.Issued{}, "", ErrAuthFailed
	}
	s.Sessions.Committed(ctx, realmID, is)
	return is, uid, nil
}

var errNoCode = errors.New("no matching recovery code")

func (s *Service) redeem(ctx context.Context, realmID, email, code string, c Client, replaceToken string) (session.Issued, string, error) {
	var u port.User
	var cand port.RecoveryCode
	lookup := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		e, err := s.Accounts.FindByEmail(ctx, tx, realmID, email)
		if err != nil {
			return err
		}
		if e.VerifiedAt == nil {
			return errNoCode
		}
		if u, err = tx.Users().Get(ctx, realmID, e.UserID); err != nil {
			return err
		}
		if len(code) != lookupLen+secretLen {
			return errNoCode
		}
		cs, err := tx.RecoveryCodes().ListByUser(ctx, realmID, u.ID)
		if err != nil {
			return err
		}
		for _, x := range cs {
			if x.Lookup == code[:lookupLen] && x.UsedAt == nil {
				cand = x
				return nil
			}
		}
		return errNoCode
	})
	if lookup != nil && !errors.Is(lookup, errs.NotFound) && !errors.Is(lookup, errNoCode) {
		return session.Issued{}, "", lookup // ストレージの障害
	}
	hash := cand.Hash
	if lookup != nil {
		hash = s.dummyHash()
	}
	ok, _, err := password.Verify(code, hash, s.params())
	switch {
	case lookup != nil:
		return session.Issued{}, "", lookup
	case err != nil:
		return session.Issued{}, "", err
	case !ok:
		return session.Issued{}, "", errors.New("recovery code mismatch")
	}
	var out session.Issued
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		now := s.Clock.Now()
		used, err := tx.RecoveryCodes().MarkUsed(ctx, realmID, cand.ID, now)
		if err != nil {
			return err
		}
		if !used {
			return errors.New("recovery code already used")
		}
		if u, err = tx.Users().Get(ctx, realmID, u.ID); err != nil {
			return err
		}
		if _, err := account.Check(ctx, tx, u, now, now, account.RecoveryIgnores...); err != nil {
			return err
		}
		out, err = s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: []string{AMR}, Recovery: true,
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, ReplaceToken: replaceToken,
		})
		if err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "recovery.started", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: out.Session.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"via": ViaCode},
		})
		return err
	})
	return out, u.PublicID, err
}

// Via は復旧専用のセッションの amr から経路を返す。
func Via(amr []string) string {
	for _, a := range amr {
		switch a {
		case AMR:
			return ViaCode
		case "otp":
			return ViaEmail
		case "link":
			return ViaLink
		}
	}
	return ""
}

// Complete は復旧専用のセッションでの復旧を終える。セッションの発行の後に新しい認証手段（passkey・TOTP・パスワード・
// 外部 ID）を登録していなければ ErrNoNewMethod。ユーザーの全セッション（このセッションも）を失効させ、コードを作り直して
// 返し、確認済みの全メールに通知する。古い認証手段は残す（無効化を勧めるのは呼び出し側）。
func (s *Service) Complete(ctx context.Context, realmID, sessionID string, c Client) ([]string, []string, error) {
	var codes, revoked []string
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		now := s.Clock.Now()
		ses, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if err != nil {
			return err
		}
		if ses.Restriction != port.RestrictionRecovery || ses.RevokedAt != nil || !now.Before(ses.ExpiresAt) {
			return ErrNotRecovery
		}
		u, err := tx.Users().Get(ctx, realmID, ses.PrincipalID)
		if err != nil {
			return err
		}
		ok, err := addedSince(ctx, tx, realmID, u.ID, ses.CreatedAt)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNoNewMethod
		}
		actor := audit.Actor{Type: "user", ID: u.PublicID}
		if revoked, err = tx.Sessions().RevokeByPrincipal(ctx, realmID, port.PrincipalUser, u.ID, "", now, session.ReasonRecovered); err != nil {
			return err
		}
		if err := s.Sessions.EndLineagesTx(ctx, tx, realmID, revoked, session.ReasonRecovered, c.RequestID); err != nil {
			return err
		}
		if codes, err = s.Generate(ctx, tx, realmID, u.ID, actor, c.RequestID); err != nil {
			return err
		}
		via := Via(ses.AuthMethods)
		if err := s.notifyAll(ctx, tx, realmID, u, now); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "account.recovered", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, SessionID: ses.ID,
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Details: map[string]any{"via": via, "sessions": revoked},
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	s.Sessions.ForgetIDs(ctx, realmID, revoked)
	return codes, revoked, nil
}

// addedSince はユーザーが since より後に認証手段を足したかを返す。
func addedSince(ctx context.Context, tx port.Tx, realmID, userID string, since time.Time) (bool, error) {
	after := func(t time.Time) bool { return t.After(since) }
	ps, err := tx.Passkeys().ListByUser(ctx, realmID, userID)
	if err != nil {
		return false, err
	}
	for _, p := range ps {
		if p.RevokedAt == nil && after(p.CreatedAt) {
			return true, nil
		}
	}
	ts, err := tx.TOTP().ListByUser(ctx, realmID, userID)
	if err != nil {
		return false, err
	}
	for _, t := range ts {
		if t.RevokedAt == nil && after(t.CreatedAt) {
			return true, nil
		}
	}
	is, err := tx.Identities().ListByUser(ctx, realmID, userID)
	if err != nil {
		return false, err
	}
	for _, i := range is {
		if i.RevokedAt == nil && after(i.CreatedAt) {
			return true, nil
		}
	}
	switch p, err := tx.Passwords().GetActive(ctx, realmID, userID); {
	case err == nil:
		return after(p.CreatedAt), nil
	case errors.Is(err, errs.NotFound):
		return false, nil
	default:
		return false, err
	}
}

// notifyAll は確認済みの全メールに復旧の完了を知らせる（4.12）。宛先は claim で取り出させる。
// アドレスを保存しない構成（index_only。9.6）のメールがあれば、宛先なしの通知を1件出す（外部が user_id から宛先を解決する）。
// index_only では、切り替え前の暗号文が掃除前に残っていても宛先付きでは送らない。
func (s *Service) notifyAll(ctx context.Context, tx port.Tx, realmID string, u port.User, now time.Time) error {
	es, err := tx.Emails().ListByUser(ctx, realmID, u.ID)
	if err != nil {
		return err
	}
	unresolved := false
	for _, e := range es {
		if e.VerifiedAt == nil {
			continue
		}
		if s.Accounts.IndexOnly || len(e.Ciphertext) == 0 {
			unresolved = true
			continue
		}
		addr, err := s.Accounts.EmailAddress(ctx, tx, e)
		if err != nil {
			return err
		}
		n := port.Notification{Type: notify.TypeAccountRecovered, RealmID: realmID, UserID: u.PublicID}
		if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: addr, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			return err
		}
	}
	if unresolved {
		_, err := s.Notify.Enqueue(ctx, tx, port.Notification{Type: notify.TypeAccountRecovered, RealmID: realmID, UserID: u.PublicID}, nil)
		return err
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, realmID string, c Client, cause error) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "recovery.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"via": ViaCode, "reason": cause.Error()},
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record recovery failure", "error", err)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
