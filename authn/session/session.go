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
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/warning"
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
	// RequireSecondFactor は2段階認証を必須にする（2.8）。2要素目が未登録のユーザーには、登録だけできる
	// セッションを発行する。false でも、2要素目を登録したユーザーには2要素目を求める（4.1）。
	RequireSecondFactor bool
	// SecondFactorTTL は2要素目の確認・登録を待つ制限つきのセッションの寿命。既定 10 分。
	SecondFactorTTL time.Duration
}

// 失効の理由。
const (
	ReasonLogout          = "logout"
	ReasonRotated         = "rotated"
	ReasonReplacedByLogin = "replaced_by_login"
	ReasonUser            = "revoked_by_user"
	ReasonAdmin           = "revoked_by_admin"
	// ReasonCredentialChanged は本人がパスワードを変えた・外したこと（他のセッションを失効させる。5.2）。
	ReasonCredentialChanged = "credential_changed" // #nosec G101 -- 失効の理由で、秘密ではない
	// ReasonSecondFactor は2要素目の確認で、制限つきのセッションを通常のセッションに替えたこと。
	ReasonSecondFactor = "second_factor_completed"
)

// 2要素目の種類（LoginResult の second_factor_methods）。
const (
	SecondFactorPasskey = "passkey"
	SecondFactorTOTP    = "totp"
)

// AMRMFA は複数の要素で認証したことを表す amr（RFC 8176）。
const AMRMFA = "mfa"

// ErrInvalid は検証の失敗。理由は外部に返さない（authentication_failed に統一する。4.9）。
var ErrInvalid = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "session invalid")

// errRejected はセッションが使えないことを表す（ErrInvalid になる）。これに当たらないエラーは
// ストレージの障害などで、セッションの有効・無効は分からない。
var errRejected = errors.New("rejected")

func rejected(reason string) error { return fmt.Errorf("%w: %s", errRejected, reason) }

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
	// Warnings は認証の警告の評価器（10章）。nil ならフィーチャー warnings が動いておらず、評価しない。
	Warnings *warning.Evaluator
}

// Issue は新しいセッションの発行の内容。
type Issue struct {
	RealmID     string
	UserID      string
	AuthMethods []string // amr
	Credentials []string // 認証に使った認証情報の ID
	// Evidence は警告の評価に渡す事実。AMR は AuthMethods から埋める。
	Evidence  warning.Evidence
	IP        string
	UserAgent string
	RequestID string
	// Carried は前の段（2要素目の前の制限つきのセッション）の警告。評価の結果に合わせて残す。
	Carried []warning.Warning
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン。ログイン時に ID を入れ替える（5.2）。
	// トークン（秘密を含む）で指定させ、ID だけで他人のセッションを失効させられないようにする。
	ReplaceToken string
}

// Issued は発行したセッションと、クライアントに渡すトークン。
type Issued struct {
	Session port.Session
	Token   string
	// Warnings は本人に返す警告（ignore のものは含まない）。
	Warnings []warning.Warning
	// Replaced は入れ替えで失効させた古いセッションの ID（無ければ空）。
	Replaced string
	// SecondFactorMethods は、制限つき（2要素目の確認待ち）のときに使える2要素目の種類。
	SecondFactorMethods []string
}

// Committed は Issue を呼んだトランザクションが確定した後に呼ぶ。入れ替えた古いセッションの
// 有効性のキャッシュを消し、失効をすぐに反映する（確定の前に消すと、間に古い状態が載り直しうる）。
func (m *Manager) Committed(ctx context.Context, realmID string, is Issued) {
	if is.Replaced != "" {
		m.forget(ctx, realmID, is.Replaced)
	}
}

// Issue はセッションを発行する。呼び出し側のトランザクション（ユーザーの作成などと同じ）で呼ぶ。
// 警告が deny になれば *warning.DeniedError を返す（セッションは作らない）。呼び出し側はトランザクションを戻す。
func (m *Manager) Issue(ctx context.Context, tx port.Tx, in Issue) (Issued, error) {
	now := m.Clock.Now()
	// 認証の後・セッションの作成の前に警告を評価する（10章、11.8 の post_authentication）。
	restriction, methods, err := m.secondFactor(ctx, tx, in)
	if err != nil {
		return Issued{}, err
	}
	ev := in.Evidence
	ev.AMR = in.AuthMethods
	warnings, err := m.Warnings.Evaluate(ev)
	if restriction != port.RestrictionNone {
		// 2要素目を待つ間は1要素なのが当然なので、single_factor は2要素目の後に評価する（deny でも2要素目に進める）。
		warnings, err = withoutSingleFactor(warnings, err)
	}
	if err != nil {
		return Issued{}, err
	}
	warnings = carry(warnings, in.Carried)
	warningsJSON, err := json.Marshal(nonNilWarnings(warnings))
	if err != nil {
		return Issued{}, err
	}
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
		AuthMethods: in.AuthMethods, AuthCredentialIDs: in.Credentials, Warnings: warningsJSON, IP: ip, UserAgent: ua,
		AuthenticatedAt: now, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(m.Config.AbsoluteLifetime), Restriction: restriction,
	}
	if restriction != port.RestrictionNone {
		s.ExpiresAt = earliest(s.ExpiresAt, now.Add(m.secondFactorTTL()))
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
	if restriction != port.RestrictionNone {
		details["restriction"] = string(restriction)
	}
	var replaced string
	if len(warnings) > 0 {
		details["warnings"] = warnings
	}
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
			replaced = old.ID
		}
	}
	_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
		Type: "session.created", Result: audit.ResultSuccess, RealmID: in.RealmID,
		Actor: actor, SessionID: s.ID, IP: in.IP, UserAgent: in.UserAgent,
		RequestID: in.RequestID, Details: details,
	})
	return Issued{Session: s, Token: token, Warnings: warnings, Replaced: replaced, SecondFactorMethods: methods}, err
}

func withoutSingleFactor(ws []warning.Warning, err error) ([]warning.Warning, error) {
	ws = slices.DeleteFunc(ws, func(w warning.Warning) bool { return w.Code == warning.CodeSingleFactor })
	if d, ok := errors.AsType[*warning.DeniedError](err); ok {
		codes := slices.DeleteFunc(slices.Clone(d.Codes), func(c string) bool { return c == warning.CodeSingleFactor })
		if len(codes) == 0 {
			return ws, nil
		}
		return ws, &warning.DeniedError{Codes: codes}
	}
	return ws, err
}

// carry は前の段の警告のうち、新しい評価に無いコードのものを足す。
func carry(ws, carried []warning.Warning) []warning.Warning {
	for _, c := range carried {
		if !slices.ContainsFunc(ws, func(w warning.Warning) bool { return w.Code == c.Code }) {
			ws = append(ws, c)
		}
	}
	return ws
}

func (m *Manager) secondFactorTTL() time.Duration {
	if m.Config.SecondFactorTTL <= 0 {
		return 10 * time.Minute
	}
	return m.Config.SecondFactorTTL
}

// secondFactor は発行するセッションの制限を決める（4.1）。本人確認（UV）つきの passkey と、2要素目を
// 確認した後（amr に mfa）は制限しない。2要素目を登録したユーザーには2要素目の確認を、必須で未登録なら登録を求める。
func (m *Manager) secondFactor(ctx context.Context, tx port.Tx, in Issue) (port.SessionRestriction, []string, error) {
	if slices.Contains(in.AuthMethods, AMRMFA) || (slices.Contains(in.AuthMethods, "hwk") && slices.Contains(in.AuthMethods, "user")) {
		return port.RestrictionNone, nil, nil
	}
	methods, err := SecondFactors(ctx, tx, in.RealmID, in.UserID)
	if err != nil {
		return "", nil, err
	}
	switch {
	case len(methods) > 0:
		return port.RestrictionSecondFactor, methods, nil
	case m.Config.RequireSecondFactor:
		return port.RestrictionEnroll, nil, nil
	}
	return port.RestrictionNone, nil, nil
}

// SecondFactors はユーザーが登録している（無効化していない）2要素目の種類を返す。
func SecondFactors(ctx context.Context, tx port.Tx, realmID, userID string) ([]string, error) {
	var out []string
	ps, err := tx.Passkeys().ListByUser(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(ps, func(p port.Passkey) bool { return p.RevokedAt == nil }) {
		out = append(out, SecondFactorPasskey)
	}
	ts, err := tx.TOTP().ListByUser(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(ts, func(c port.TOTPCredential) bool { return c.RevokedAt == nil }) {
		out = append(out, SecondFactorTOTP)
	}
	return out, nil
}

// ErrNotRestricted は、2要素目で替えようとしたセッションが制限つきでないこと。
var ErrNotRestricted = errs.New(errs.KindFailedPrecondition, "session is not waiting for a second factor")

// SecondFactor は2要素目の確認の内容。
type SecondFactor struct {
	AMR          []string // 確認した要素の amr（otp、hwk など）
	CredentialID string   // 使った認証情報の ID（内部 ID）
	IP           string
	UserAgent    string
	RequestID    string
}

// CompleteSecondFactor は、2要素目を確認した制限つきのセッション（内部の確認待ちか登録だけのもの）を失効させ、
// 通常のセッションを発行する。amr は1要素目と2要素目を合わせ、mfa を加える。呼び出し側のトランザクションで呼び、
// 確定の後に Committed を呼ぶ。
func (m *Manager) CompleteSecondFactor(ctx context.Context, tx port.Tx, realmID, sessionID string, f SecondFactor) (Issued, error) {
	now := m.Clock.Now()
	old, err := tx.Sessions().Get(ctx, realmID, sessionID)
	if err != nil {
		return Issued{}, err
	}
	if old.Restriction == port.RestrictionNone || (old.RevokedAt != nil && !now.Before(*old.RevokedAt)) || !now.Before(old.ExpiresAt) {
		return Issued{}, ErrNotRestricted
	}
	actor, err := userActor(ctx, tx, realmID, old.PrincipalID)
	if err != nil {
		return Issued{}, err
	}
	if err := m.revokeInTx(ctx, tx, old, ReasonSecondFactor, actor, f.RequestID); err != nil {
		return Issued{}, err
	}
	amr := slices.Clone(old.AuthMethods)
	for _, a := range append(slices.Clone(f.AMR), AMRMFA) {
		if !slices.Contains(amr, a) {
			amr = append(amr, a)
		}
	}
	var carried []warning.Warning
	if len(old.Warnings) > 0 {
		if err := json.Unmarshal(old.Warnings, &carried); err != nil {
			return Issued{}, err
		}
	}
	is, err := m.Issue(ctx, tx, Issue{
		RealmID: realmID, UserID: old.PrincipalID, AuthMethods: amr, Credentials: append(slices.Clone(old.AuthCredentialIDs), f.CredentialID),
		IP: f.IP, UserAgent: f.UserAgent, RequestID: f.RequestID, Carried: carried,
	})
	if err != nil {
		return Issued{}, err
	}
	is.Replaced = old.ID
	return is, nil
}

func nonNilWarnings(w []warning.Warning) []warning.Warning {
	if w == nil {
		return []warning.Warning{}
	}
	return w
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
	// Restriction は使える操作の制限（2要素目の確認待ちなど）。空なら制限なし。
	Restriction port.SessionRestriction
	// RotateDue は ID の入れ替えの時期を過ぎていることを表す（Cookie のセッションで入れ替える）。
	RotateDue bool
}

// cached はキャッシュに置く検証の結果。秘密は置かない。
type cached struct {
	Hash            []byte                  `json:"h"`
	PrincipalType   port.PrincipalType      `json:"pt"`
	PrincipalID     string                  `json:"p"`
	PublicID        string                  `json:"u"`
	AuthMethods     []string                `json:"amr"`
	AuthenticatedAt time.Time               `json:"at"`
	CreatedAt       time.Time               `json:"c"`
	NextCheck       time.Time               `json:"n"`
	Restriction     port.SessionRestriction `json:"r,omitempty"`
}

func cacheKey(realmID, sessionID string) string { return "session:v1:" + realmID + ":" + sessionID }

// Validate はトークンを検証する。使えないセッションは ErrInvalid（理由はログにだけ出す）。
// ストレージの障害では ErrInvalid 以外のエラーを返す（呼び出し側は Cookie を消さない）。
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
			return rejected("token mismatch")
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
			AuthMethods: s.AuthMethods, AuthenticatedAt: s.AuthenticatedAt, CreatedAt: s.CreatedAt, NextCheck: next, Restriction: s.Restriction}
		return nil
	})
	if errors.Is(err, errRejected) || errors.Is(err, errs.NotFound) {
		m.logger().DebugContext(ctx, "session rejected", "session_id", sid, "reason", err.Error())
		return Validated{}, ErrInvalid
	}
	if err != nil {
		return Validated{}, errs.Wrap(errs.KindUnavailable, err, "session: validate")
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
		PublicID: c.PublicID, AuthMethods: c.AuthMethods, AuthenticatedAt: c.AuthenticatedAt, Restriction: c.Restriction}
	if m.Config.RotationInterval > 0 && !now.Before(c.CreatedAt.Add(m.Config.RotationInterval)) {
		v.RotateDue = true
	}
	return v
}

// check はセッションが今有効かを確かめ、次に状態が変わる時刻（再検証の期限）と主体を返す。
func (m *Manager) check(ctx context.Context, tx port.Tx, s port.Session, now time.Time) (time.Time, port.User, error) {
	if s.RevokedAt != nil && !now.Before(*s.RevokedAt) {
		return time.Time{}, port.User{}, rejected("revoked")
	}
	if !now.Before(s.ExpiresAt) {
		return time.Time{}, port.User{}, rejected("expired")
	}
	if m.Config.IdleTimeout > 0 && !now.Before(s.LastSeenAt.Add(m.Config.IdleTimeout)) {
		return time.Time{}, port.User{}, rejected("idle timeout")
	}
	next := earliest(s.ExpiresAt, now.Add(m.Config.ValidityMaxDelay))
	if s.RevokedAt != nil {
		next = earliest(next, *s.RevokedAt) // 入れ替え後の猶予の終わり
	}
	if s.PrincipalType != port.PrincipalUser {
		return time.Time{}, port.User{}, rejected("unsupported principal")
	}
	u, err := tx.Users().Get(ctx, s.RealmID, s.PrincipalID)
	if err != nil {
		return time.Time{}, port.User{}, err
	}
	if !account.CanLogin(u, now) {
		return time.Time{}, port.User{}, rejected("user cannot log in")
	}
	if u.ValidUntil != nil {
		next = earliest(next, *u.ValidUntil)
	}
	// 認証に使った外部 ID・passkey・TOTP が無効化されていれば、そのセッションも使えない（4.6）。
	if err := checkCredentials(ctx, tx, s); err != nil {
		return time.Time{}, port.User{}, err
	}
	return next, u, nil
}

func checkCredentials(ctx context.Context, tx port.Tx, s port.Session) error {
	var identities []port.Identity
	var passkeys []port.Passkey
	var totps []port.TOTPCredential
	for _, c := range s.AuthCredentialIDs {
		var revoked, found bool
		switch {
		case strings.HasPrefix(c, string(id.Identity)+"_"):
			if identities == nil {
				var err error
				if identities, err = tx.Identities().ListByUser(ctx, s.RealmID, s.PrincipalID); err != nil {
					return err
				}
			}
			for _, i := range identities {
				if i.ID == c {
					found, revoked = true, i.RevokedAt != nil
				}
			}
		case strings.HasPrefix(c, string(id.Passkey)+"_"):
			if passkeys == nil {
				var err error
				if passkeys, err = tx.Passkeys().ListByUser(ctx, s.RealmID, s.PrincipalID); err != nil {
					return err
				}
			}
			for _, p := range passkeys {
				if p.ID == c {
					found, revoked = true, p.RevokedAt != nil
				}
			}
		case strings.HasPrefix(c, string(id.TOTP)+"_"):
			if totps == nil {
				var err error
				if totps, err = tx.TOTP().ListByUser(ctx, s.RealmID, s.PrincipalID); err != nil {
					return err
				}
			}
			for _, t := range totps {
				if t.ID == c {
					found, revoked = true, t.RevokedAt != nil
				}
			}
		default:
			continue
		}
		if revoked {
			return rejected("credential revoked")
		}
		if !found {
			return rejected("credential missing")
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
		ids, err = m.RevokeAllTx(ctx, tx, realmID, userID, except, reason, actor, requestID)
		return err
	})
	if err != nil {
		return nil, err
	}
	m.ForgetIDs(ctx, realmID, ids)
	return ids, nil
}

// RevokeAllTx は RevokeAll を呼び出し側のトランザクションで行う。確定の後に ForgetIDs で返した ID のキャッシュを消す。
func (m *Manager) RevokeAllTx(ctx context.Context, tx port.Tx, realmID, userID, except, reason string, actor audit.Actor, requestID string) ([]string, error) {
	ids, err := tx.Sessions().RevokeByPrincipal(ctx, realmID, port.PrincipalUser, userID, except, m.Clock.Now(), reason)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	subject, err := userActor(ctx, tx, realmID, userID)
	if err != nil {
		return nil, err
	}
	_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
		Type: "session.revoked", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"sessions": ids, "reason": reason, "user_id": subject.ID},
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// ForgetIDs はセッションの検証結果のキャッシュを消す（呼び出し側のトランザクションで失効させた後に呼ぶ）。
func (m *Manager) ForgetIDs(ctx context.Context, realmID string, sessionIDs []string) {
	for _, sid := range sessionIDs {
		m.forget(ctx, realmID, sid)
	}
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
