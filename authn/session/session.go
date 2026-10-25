// Package session はセッションの発行・検証・入れ替え・失効を行う（design.md 5.2〜5.4）。
//
// セキュリティ上重要なコード（13.2）。変更時は不変条件のテスト（13.5）を確かめること。
//
//   - トークンは "<公開のセッション ID>.<256bit の乱数>"。DB とキャッシュには秘密部分の SHA-256 だけを置き、定数時間で照合する
//   - ログ・監査ログ・エラーに出してよいのは公開のセッション ID だけ。トークンはどこにも出さない
//   - 検証の結果は EphemeralStore にキャッシュする。TTL は反映遅れの上限（ValidityMaxDelay）以下にし、
//     次に状態が変わる時刻（期限、無操作の期限、有効期間の終わり）を過ぎたら再検証する（5.3）
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Config はセッションの寿命の設定（M1 ではホストの設定のみ。5.4）。
type Config struct {
	AbsoluteLifetime time.Duration
	IdleTimeout      time.Duration
	// ValidityMaxDelay は変更が検証に反映されるまでの遅れの上限（保証値。5.3）。
	ValidityMaxDelay time.Duration
	// RotationInterval ごとに ID を入れ替える。0 なら入れ替えない。
	RotationInterval time.Duration
	// RotationGrace は入れ替え前の ID を使える猶予（同時に送られたリクエストを失敗させないため）。
	RotationGrace time.Duration
}

// 失効の理由。
const (
	ReasonLogout          = "logout"
	ReasonRotated         = "rotated"
	ReasonReplacedByLogin = "replaced_by_login"
	ReasonUser            = "revoked_by_user"
	ReasonAdmin           = "revoked_by_admin"
)

// ErrInvalid は検証の失敗。理由は外部に返さない（authentication_failed に統一する。4.9）。
var ErrInvalid = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "session invalid")

// ErrNotRotated は入れ替えなかったことを表す（呼び出し側は今のトークンを使い続ける）。
var ErrNotRotated = errors.New("session: not rotated")

// Manager はセッションを扱う。
type Manager struct {
	Storage port.Storage
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	Config  Config
	Log     *slog.Logger
}

// Issue は新しいセッションの発行の内容。
type Issue struct {
	RealmID     string
	UserID      string
	AuthMethods []string // amr
	Credentials []string // 認証に使った認証情報の ID
	Warnings    []byte   // JSON
	IP          string
	UserAgent   string
	RequestID   string
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン。ログイン時に ID を入れ替える（5.2）。
	// トークン（秘密を含む）で指定させ、ID だけで他人のセッションを失効させられないようにする。
	ReplaceToken string
}

// Issued は発行したセッションと、クライアントに渡すトークン。
type Issued struct {
	Session port.Session
	Token   string
}

// Issue はセッションを発行する。呼び出し側のトランザクション（ユーザーの作成などと同じ）で呼ぶ。
func (m *Manager) Issue(ctx context.Context, tx port.Tx, in Issue) (Issued, error) {
	now := m.Clock.Now()
	ip, err := m.encrypt(ctx, tx, in.UserID, in.IP, "session.ip")
	if err != nil {
		return Issued{}, err
	}
	ua, err := m.encrypt(ctx, tx, in.UserID, in.UserAgent, "session.user_agent")
	if err != nil {
		return Issued{}, err
	}
	s := port.Session{
		ID: id.NewExternal(id.Session), RealmID: in.RealmID, PrincipalType: port.PrincipalUser, PrincipalID: in.UserID,
		AuthMethods: in.AuthMethods, AuthCredentialIDs: in.Credentials, Warnings: in.Warnings, IP: ip, UserAgent: ua,
		AuthenticatedAt: now, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(m.Config.AbsoluteLifetime),
	}
	if s.Warnings == nil {
		s.Warnings = []byte("[]")
	}
	token, hash, err := newToken(s.ID)
	if err != nil {
		return Issued{}, err
	}
	s.TokenHash = hash
	actor, err := userActor(ctx, tx, in.RealmID, in.UserID)
	if err != nil {
		return Issued{}, err
	}
	if err := tx.Sessions().Create(ctx, s); err != nil {
		return Issued{}, err
	}
	details := map[string]any{"amr": in.AuthMethods}
	if sid, secret, ok := SplitToken(in.ReplaceToken); ok {
		old, err := tx.Sessions().Get(ctx, in.RealmID, sid)
		if err == nil && (old.RevokedAt == nil || now.Before(*old.RevokedAt)) && subtle.ConstantTimeCompare(old.TokenHash, hashSecret(secret)) == 1 {
			oldActor, err := userActor(ctx, tx, in.RealmID, old.PrincipalID)
			if err != nil {
				return Issued{}, err
			}
			if err := m.revokeInTx(ctx, tx, old, ReasonReplacedByLogin, oldActor, in.RequestID); err != nil {
				return Issued{}, err
			}
			details["replaced"] = old.ID
		}
	}
	_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
		Type: "session.created", Result: audit.ResultSuccess, RealmID: in.RealmID,
		Actor: actor, SessionID: s.ID, IP: in.IP, UserAgent: in.UserAgent,
		RequestID: in.RequestID, Details: details,
	})
	return Issued{Session: s, Token: token}, err
}

// userActor は監査ログの行為者。内部 ID は外に出さず、公開 ID を使う（ADR 0045）。
func userActor(ctx context.Context, tx port.Tx, realmID, userID string) (audit.Actor, error) {
	u, err := tx.Users().Get(ctx, realmID, userID)
	if err != nil {
		return audit.Actor{}, err
	}
	return audit.Actor{Type: "user", ID: u.PublicID}, nil
}

func (m *Manager) encrypt(ctx context.Context, tx port.Tx, userID, v, purpose string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	return m.Crypter.Encrypt(ctx, tx.DataKeys(), userID, []byte(v), purpose)
}

// newToken はセッション ID と 256bit の乱数からトークンを作り、秘密部分のハッシュを返す。
func newToken(sessionID string) (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	return sessionID + "." + secret, hashSecret(secret), nil
}

func hashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// SplitToken はトークンを公開 ID と秘密に分ける。形式が違えば ok=false。
func SplitToken(token string) (sessionID, secret string, ok bool) {
	sessionID, secret, ok = strings.Cut(token, ".")
	if !ok || !id.Valid(id.Session, sessionID) || len(secret) != 43 {
		return "", "", false
	}
	return sessionID, secret, true
}

// ---------------------------------------------------------------------------

// Validated は検証済みのセッション。
type Validated struct {
	SessionID     string
	RealmID       string
	PrincipalType port.PrincipalType
	PrincipalID   string // 内部 ID。外に出さない（ADR 0045）
	// PublicID は主体の公開 ID。API の応答や監査ログにはこちらを使う。
	PublicID        string
	AuthMethods     []string
	AuthenticatedAt time.Time
	// RotateDue は ID の入れ替えの時期を過ぎていることを表す（Cookie のセッションで入れ替える）。
	RotateDue bool
}

// cached はキャッシュに置く検証の結果。秘密は置かない。
type cached struct {
	Hash            []byte             `json:"h"`
	PrincipalType   port.PrincipalType `json:"pt"`
	PrincipalID     string             `json:"p"`
	PublicID        string             `json:"u"`
	AuthMethods     []string           `json:"amr"`
	AuthenticatedAt time.Time          `json:"at"`
	CreatedAt       time.Time          `json:"c"`
	NextCheck       time.Time          `json:"n"`
}

func cacheKey(realmID, sessionID string) string { return "session:v1:" + realmID + ":" + sessionID }

// Validate はトークンを検証する。失敗はすべて ErrInvalid（理由はログにだけ出す）。
func (m *Manager) Validate(ctx context.Context, realmID, token string) (Validated, error) {
	sid, secret, ok := SplitToken(token)
	if !ok {
		return Validated{}, ErrInvalid
	}
	hash := hashSecret(secret)
	now := m.Clock.Now()
	key := cacheKey(realmID, sid)

	if b, hit, err := m.Cache.Get(ctx, key); err == nil && hit {
		var c cached
		if json.Unmarshal(b, &c) == nil && now.Before(c.NextCheck) {
			if subtle.ConstantTimeCompare(c.Hash, hash) != 1 {
				return Validated{}, ErrInvalid
			}
			return m.validated(realmID, sid, c, now), nil
		}
	}

	var c cached
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		s, err := tx.Sessions().Get(ctx, realmID, sid)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(s.TokenHash, hash) != 1 {
			return errors.New("token mismatch")
		}
		next, u, err := m.check(ctx, tx, s, now)
		if err != nil {
			return err
		}
		// 無操作の期限を延ばす。書き込みはキャッシュに外れたとき（最大でも ValidityMaxDelay ごと）だけ。
		if err := tx.Sessions().Touch(ctx, realmID, sid, now); err != nil {
			return err
		}
		if m.Config.IdleTimeout > 0 {
			next = earliest(next, now.Add(m.Config.IdleTimeout))
		}
		c = cached{Hash: s.TokenHash, PrincipalType: s.PrincipalType, PrincipalID: s.PrincipalID, PublicID: u.PublicID,
			AuthMethods: s.AuthMethods, AuthenticatedAt: s.AuthenticatedAt, CreatedAt: s.CreatedAt, NextCheck: next}
		return nil
	})
	if err != nil {
		m.logger().DebugContext(ctx, "session rejected", "session_id", sid, "reason", err.Error())
		return Validated{}, ErrInvalid
	}
	if ttl := c.NextCheck.Sub(now); ttl > 0 {
		if b, err := json.Marshal(c); err == nil {
			if err := m.Cache.Set(ctx, key, b, ttl); err != nil {
				m.logger().WarnContext(ctx, "session cache write failed", "session_id", sid, "error", err)
			}
		}
	}
	return m.validated(realmID, sid, c, now), nil
}

func (m *Manager) validated(realmID, sid string, c cached, now time.Time) Validated {
	v := Validated{SessionID: sid, RealmID: realmID, PrincipalType: c.PrincipalType, PrincipalID: c.PrincipalID,
		PublicID: c.PublicID, AuthMethods: c.AuthMethods, AuthenticatedAt: c.AuthenticatedAt}
	if m.Config.RotationInterval > 0 && !now.Before(c.CreatedAt.Add(m.Config.RotationInterval)) {
		v.RotateDue = true
	}
	return v
}

// check はセッションが今有効かを確かめ、次に状態が変わる時刻（再検証の期限）と主体を返す。
func (m *Manager) check(ctx context.Context, tx port.Tx, s port.Session, now time.Time) (time.Time, port.User, error) {
	if s.RevokedAt != nil && !now.Before(*s.RevokedAt) {
		return time.Time{}, port.User{}, errors.New("revoked")
	}
	if !now.Before(s.ExpiresAt) {
		return time.Time{}, port.User{}, errors.New("expired")
	}
	if m.Config.IdleTimeout > 0 && !now.Before(s.LastSeenAt.Add(m.Config.IdleTimeout)) {
		return time.Time{}, port.User{}, errors.New("idle timeout")
	}
	next := earliest(s.ExpiresAt, now.Add(m.Config.ValidityMaxDelay))
	if s.RevokedAt != nil {
		next = earliest(next, *s.RevokedAt) // 入れ替え後の猶予の終わり
	}
	if s.PrincipalType != port.PrincipalUser {
		return time.Time{}, port.User{}, errors.New("unsupported principal")
	}
	u, err := tx.Users().Get(ctx, s.RealmID, s.PrincipalID)
	if err != nil {
		return time.Time{}, port.User{}, err
	}
	if !account.CanLogin(u, now) {
		return time.Time{}, port.User{}, errors.New("user cannot log in")
	}
	if u.ValidUntil != nil {
		next = earliest(next, *u.ValidUntil)
	}
	// 認証に使った外部 ID が無効化されていれば、そのセッションも使えない（4.6）。
	if err := checkCredentials(ctx, tx, s); err != nil {
		return time.Time{}, port.User{}, err
	}
	return next, u, nil
}

func checkCredentials(ctx context.Context, tx port.Tx, s port.Session) error {
	var identities []port.Identity
	for _, c := range s.AuthCredentialIDs {
		if !strings.HasPrefix(c, string(id.Identity)+"_") {
			continue
		}
		if identities == nil {
			var err error
			if identities, err = tx.Identities().ListByUser(ctx, s.RealmID, s.PrincipalID); err != nil {
				return err
			}
		}
		found := false
		for _, i := range identities {
			if i.ID == c {
				if i.RevokedAt != nil {
					return errors.New("credential revoked")
				}
				found = true
			}
		}
		if !found {
			return errors.New("credential missing")
		}
	}
	return nil
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// ---------------------------------------------------------------------------

// Rotate はセッションの ID を入れ替え、新しいトークンを返す（5.2）。
// 本人確認の時刻と寿命は引き継ぐ。古い ID は RotationGrace の後に失効する（一覧には出さない）。
func (m *Manager) Rotate(ctx context.Context, realmID, sessionID, requestID string) (Issued, error) {
	now := m.Clock.Now()
	var out Issued
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		old, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if err != nil {
			return err
		}
		// 入れ替え済み（失効の予定があるもの）は入れ替えない。同時に届いたリクエストが二重に入れ替えないため。
		if old.RevokedAt != nil || !now.Before(old.ExpiresAt) {
			return ErrNotRotated
		}
		s := old
		s.ID, s.CreatedAt, s.LastSeenAt = id.NewExternal(id.Session), now, now
		token, hash, err := newToken(s.ID)
		if err != nil {
			return err
		}
		s.TokenHash = hash
		if err := tx.Sessions().Create(ctx, s); err != nil {
			return err
		}
		if err := tx.Sessions().Revoke(ctx, realmID, old.ID, now.Add(m.Config.RotationGrace), ReasonRotated); err != nil {
			return err
		}
		actor, err := userActor(ctx, tx, realmID, s.PrincipalID)
		if err != nil {
			return err
		}
		if _, err := eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.rotated", Result: audit.ResultSuccess, RealmID: realmID,
			Actor: actor, SessionID: s.ID, RequestID: requestID,
			Details: map[string]any{"previous": old.ID},
		}); err != nil {
			return err
		}
		out = Issued{Session: s, Token: token}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	// 古い ID のキャッシュは猶予より長く残さない。
	m.forget(ctx, realmID, sessionID)
	return out, nil
}

// Revoke はセッションを失効させる。principalID が空でなければ、その主体のセッションに限る（本人による失効）。
func (m *Manager) Revoke(ctx context.Context, realmID, sessionID, principalID, reason string, actor audit.Actor, requestID string) error {
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		s, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if err != nil {
			return err
		}
		if principalID != "" && s.PrincipalID != principalID {
			// 他人のセッションの有無は明かさない。
			return errs.New(errs.KindNotFound, "session %s", sessionID)
		}
		if s.RevokedAt != nil && !m.Clock.Now().Before(*s.RevokedAt) {
			return nil
		}
		return m.revokeInTx(ctx, tx, s, reason, actor, requestID)
	})
	if err != nil {
		return err
	}
	m.forget(ctx, realmID, sessionID)
	return nil
}

// RevokeAll は主体のセッションを except 以外すべて失効させる（認証手段の変更時など。5.2）。
func (m *Manager) RevokeAll(ctx context.Context, realmID, userID, except, reason string, actor audit.Actor, requestID string) ([]string, error) {
	var ids []string
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ids, err = tx.Sessions().RevokeByPrincipal(ctx, realmID, port.PrincipalUser, userID, except, m.Clock.Now(), reason)
		if err != nil || len(ids) == 0 {
			return err
		}
		subject, err := userActor(ctx, tx, realmID, userID)
		if err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.revoked", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
			Details: map[string]any{"sessions": ids, "reason": reason, "user_id": subject.ID},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, sid := range ids {
		m.forget(ctx, realmID, sid)
	}
	return ids, nil
}

func (m *Manager) revokeInTx(ctx context.Context, tx port.Tx, s port.Session, reason string, actor audit.Actor, requestID string) error {
	subject, err := userActor(ctx, tx, s.RealmID, s.PrincipalID)
	if err != nil {
		return err
	}
	if err := tx.Sessions().Revoke(ctx, s.RealmID, s.ID, m.Clock.Now(), reason); err != nil {
		return err
	}
	_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
		Type: "session.revoked", Result: audit.ResultSuccess, RealmID: s.RealmID, Actor: actor, SessionID: s.ID,
		RequestID: requestID, Details: map[string]any{"reason": reason, "user_id": subject.ID},
	})
	return err
}

// forget はキャッシュを消す（ベストエフォート。失敗しても TTL で上限内に反映される。5.3）。
// Storage に書いた後に呼ぶ。
func (m *Manager) forget(ctx context.Context, realmID, sessionID string) {
	if err := m.Cache.Delete(ctx, cacheKey(realmID, sessionID)); err != nil {
		m.logger().WarnContext(ctx, "session cache delete failed", "session_id", sessionID, "error", err)
	}
}

// List は主体の有効なセッションを新しい順に返す。
func (m *Manager) List(ctx context.Context, realmID, userID string) ([]port.Session, error) {
	now := m.Clock.Now()
	var out []port.Session
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		all, err := tx.Sessions().ListByPrincipal(ctx, realmID, port.PrincipalUser, userID)
		if err != nil {
			return err
		}
		for _, s := range all {
			if s.RevokedAt == nil && now.Before(s.ExpiresAt) &&
				(m.Config.IdleTimeout <= 0 || now.Before(s.LastSeenAt.Add(m.Config.IdleTimeout))) {
				out = append(out, s)
			}
		}
		return nil
	})
	return out, err
}

func (m *Manager) logger() *slog.Logger {
	if m.Log == nil {
		return slog.Default()
	}
	return m.Log
}

// Actor は監査ログの行為者（公開 ID）。
func (v Validated) Actor() audit.Actor { return audit.Actor{Type: "user", ID: v.PublicID} }
