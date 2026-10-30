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
	"github.com/imohiyoko/iam/authn/hook"
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
	// MaxAuthAge は重要な操作に求める直近の認証の期限（realm の値。Org の段で変わる）。
	MaxAuthAge time.Duration
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
	// RecoveryTTL は復旧専用のセッションの寿命（4.12）。既定 15 分。
	RecoveryTTL time.Duration
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
	// ReasonDeletionCancelled は削除の取り消しで、取り消し専用のセッションを通常のセッションに替えたこと（4.10）。
	ReasonDeletionCancelled = "deletion_cancelled"
	// ReasonRecovered はアカウントの復旧の完了で、全セッションを失効させたこと（4.12）。
	ReasonRecovered = "account_recovered"
	// ReasonOrgSwitched は Org の切り替えで ID を入れ替えたこと（4.4）。
	ReasonOrgSwitched = "org_switched"
	// ReasonSuspended と ReasonValidity は、ユーザーの停止・有効期間の外でログインの系列を終えたこと（EndUserTx。失効はしない）。
	ReasonSuspended = "user_suspended"
	ReasonValidity  = "outside_validity"
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
	// Orgs はセッションの active な Org を決める（4.4）。nil ならフィーチャー org が動いておらず、active な Org を持たない。
	Orgs OrgPicker
	// Lineages はログインの系列が終わったときに呼ぶ（Back-Channel Logout。5.2）。nil なら呼ばない。
	Lineages LineageHook
	// Hooks はフロー フック（11.8）。nil ならフィーチャー flow_hooks が動いておらず、呼ばない。
	Hooks *hook.Runner
}

// LineageHook はログインの系列（sid）が終わったことを受け取る（authn/provider）。失効と同じトランザクションで呼ぶ。
type LineageHook interface {
	LineageEnded(ctx context.Context, tx port.Tx, realmID, sid, reason, requestID string) error
}

// OrgPicker はログインで入る Org を決めるもの（authn/org）。
type OrgPicker interface {
	Pick(ctx context.Context, tx port.Tx, u port.User, in OrgPick) (PickedOrg, error)
	// CheckActive はセッションの active な Org が本人にとって now に使えるかを返す（5.3）。使えなければ errs.Denial か
	// errs.PermissionDenied のエラー、next は可否が次に変わりうる時刻。
	CheckActive(ctx context.Context, tx port.Tx, realmID, userID, orgID string, now time.Time) (*time.Time, error)
	// Limits は Org の段で決まる、セッションに効く値を返す（2.8）。個人 Org は空（realm に従う）。
	Limits(ctx context.Context, tx port.Tx, realmID, orgID string) (OrgLimits, error)
}

// OrgLimits は active な Org で決まる、セッションに効く値（2.8、5.4、10章）。0 の項目は realm の値に従う。
type OrgLimits struct {
	// AbsoluteLifetime は認証の時刻からの寿命。
	AbsoluteLifetime time.Duration
	IdleTimeout      time.Duration
	// MaxAuthAge は重要な操作に求める直近の認証の期限。
	MaxAuthAge time.Duration
	// Warnings は Org の段の警告のアクション。realm の段より厳しいものだけが効く（warning.Evaluator.Apply）。
	Warnings map[string]warning.Action
}

// ErrReauthRequired は、切り替え先の Org の寿命（認証の時刻から・無操作）を超えていること。再認証を求める（5.4）。
var ErrReauthRequired = errs.WithCode(errs.KindUnauthenticated, CodeReauthRequired, "reauthentication required")

// CodeReauthRequired は再認証を求めるエラーのコード。
const CodeReauthRequired = "reauthentication_required"

// limits は Org の段の値を realm の値で埋めて返す。Org がオフか orgID が空なら realm の値。
func (m *Manager) limits(ctx context.Context, tx port.Tx, realmID, orgID string) (OrgLimits, error) {
	var l OrgLimits
	if m.Orgs != nil && orgID != "" {
		var err error
		if l, err = m.Orgs.Limits(ctx, tx, realmID, orgID); err != nil {
			return OrgLimits{}, err
		}
	}
	if l.AbsoluteLifetime <= 0 {
		l.AbsoluteLifetime = m.Config.AbsoluteLifetime
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = m.Config.IdleTimeout
	}
	if l.MaxAuthAge <= 0 {
		l.MaxAuthAge = m.Config.MaxAuthAge
	}
	return l, nil
}

// beyond は認証の時刻 authAt・最後の利用 lastSeen のセッションが、now に l の寿命を超えているかを返す。
func (l OrgLimits) beyond(authAt, lastSeen, now time.Time) bool {
	return (l.AbsoluteLifetime > 0 && !now.Before(authAt.Add(l.AbsoluteLifetime))) ||
		(l.IdleTimeout > 0 && !now.Before(lastSeen.Add(l.IdleTimeout)))
}

// OrgPick は Org の決定に渡す手がかり（4.4）。
type OrgPick struct {
	// Explicit は明示的な指定（Org の内部 ID）。
	Explicit string
	// Credentials はログインに使った認証情報（メール・passkey・外部 ID の内部 ID）。結び付けたメールと passkey の既定の Org を
	// 手がかりにし、Org のログインポリシー require_sso（ADR 0077）の判定にも使う。
	Credentials []string
	// Email は OAuth のプロバイダが返したアドレス。結び付けたメールと一致すれば手がかりにする。
	Email string
	// Warnings はこの認証で該当した警告（warning.Evaluator.Hits）。Org の段で deny になる Org には入れない（10章）。
	Warnings []warning.Warning
	// AuthMethods はこの認証の amr、IP は要求の IP（Org のログインポリシーの判定。4.4）。
	AuthMethods []string
	IP          string
	// Partial は2要素目の前の段。ログインポリシーは完了のときに判定する。
	Partial bool
	// Fallback は、Explicit に入れなければ明示的な指定が無いものとして決め直す（2要素目の前の段で決めた Org を引き継ぐとき）。
	Fallback  bool
	RequestID string
}

// PickedOrg は決めた Org と、選ばせるべき候補（手がかりに結び付いた Org が複数あり、前回の Org がその中に無いとき。公開 ID）。
type PickedOrg struct {
	OrgID   string
	Choices []string
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
	// AuthenticatedAt は認証の時刻。空なら今。2要素目の完了では1要素目の時刻を引き継ぎ、
	// 要素の間に始まった停止が解除で戻らないようにする（4.7）。
	AuthenticatedAt time.Time
	// Recovery は復旧専用のセッション（新しい認証手段の登録と復旧の完了だけ。4.12）を発行する。2要素目は求めない。
	Recovery bool
	// OrgID は入る Org の内部 ID（明示的な指定、2要素目の前の段の Org）。空なら OrgPicker が手がかりから決める。
	OrgID string
	// OrgFallback は、OrgID に入れなければ手がかりから決め直す（2要素目の前の段の Org。ログインポリシーは完了のときに判定する）。
	OrgFallback bool
	// OrgEmail は OAuth のプロバイダが返したアドレス（Org の手がかり）。
	OrgEmail string
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
	// OrgChoices は選ばせるべき Org の候補（公開 ID。4.4）。空なら選ばせなくてよい。
	OrgChoices []string
	// OrgPublicID は active な Org の公開 ID（Org がオフなら空）。
	OrgPublicID string
	// current は、古いセッションが入れ替えの猶予の内だったときに一緒に失効させた、系列の今のセッションの ID。
	current string
}

// Committed は Issue を呼んだトランザクションが確定した後に呼ぶ。入れ替えた古いセッションの
// 有効性のキャッシュを消し、失効をすぐに反映する（確定の前に消すと、間に古い状態が載り直しうる）。
func (m *Manager) Committed(ctx context.Context, realmID string, is Issued) {
	if is.Replaced != "" {
		m.forget(ctx, realmID, is.Replaced)
	}
	if is.current != "" {
		m.forget(ctx, realmID, is.current)
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
	if in.Recovery {
		restriction, methods = port.RestrictionRecovery, nil
	}
	u, err := tx.Users().Get(ctx, in.RealmID, in.UserID)
	if err != nil {
		return Issued{}, err
	}
	// 削除の猶予期間の間は、本人確認（2要素目まで）の後に取り消しだけができる（4.10）。
	if restriction == port.RestrictionNone && u.DeletionScheduledAt != nil {
		restriction = port.RestrictionDeletion
	}
	ev := in.Evidence
	ev.AMR = in.AuthMethods
	// 該当した警告はすべて（ignore のものも）セッションに残し、Org の段のアクションを後から当てはめる（2.8、10章）。
	hits := m.Warnings.Hits(ev)
	if restriction != port.RestrictionNone {
		// 2要素目を待つ間は1要素なのが当然なので、single_factor は2要素目の後に評価する（deny でも2要素目に進める）。
		hits = slices.DeleteFunc(hits, func(w warning.Warning) bool { return w.Code == warning.CodeSingleFactor })
	}
	hits = carry(hits, in.Carried)
	if _, err := m.Warnings.Apply(hits, nil); err != nil {
		return Issued{}, err
	}
	// post_authentication は本人確認を終えた（制限の無いセッションになる）ときだけ呼ぶ。2要素目の後は CompleteSecondFactor が
	// Issue を呼び直すので、そこで呼ばれる。
	// フックの応答のリスクの点数をセッションに保存する（ADR 0084）。一覧に無い・止めた種類と範囲外の値は捨てて監査ログに残す。
	// フックの失敗（fail_open で通したときを含む）では点数は無い（評価していない）。
	var scores map[string]int
	var dropped []string
	if restriction == port.RestrictionNone && m.Hooks.Has(port.HookPostAuthentication) {
		res, err := m.Hooks.Run(ctx, port.HookInput{Hook: port.HookPostAuthentication, UserID: u.PublicID, AuthMethods: in.AuthMethods})
		if err != nil {
			return Issued{}, err
		}
		if scores, dropped, err = hookRisk(ctx, tx, in.RealmID, res.Risk); err != nil {
			return Issued{}, err
		}
	}
	riskJSON, err := encodeRisk(scores)
	if err != nil {
		return Issued{}, err
	}
	warningsJSON, err := json.Marshal(nonNilWarnings(hits))
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
	authAt := now
	if !in.AuthenticatedAt.IsZero() {
		authAt = in.AuthenticatedAt
	}
	s := port.Session{
		ID: id.NewExternal(id.Session), RealmID: in.RealmID, PrincipalType: port.PrincipalUser, PrincipalID: in.UserID,
		AuthMethods: in.AuthMethods, AuthCredentialIDs: in.Credentials, Warnings: warningsJSON, Risk: riskJSON, IP: ip, UserAgent: ua,
		AuthenticatedAt: authAt, CreatedAt: now, LastSeenAt: now, Restriction: restriction,
	}
	token, hash, err := newToken(s.ID)
	if err != nil {
		return Issued{}, err
	}
	s.TokenHash = hash
	actor := audit.Actor{Type: "user", ID: u.PublicID}
	var choices []string
	if m.Orgs != nil {
		pick := OrgPick{Explicit: in.OrgID, Credentials: in.Credentials, Email: in.OrgEmail, Warnings: hits,
			AuthMethods: in.AuthMethods, IP: in.IP, Partial: restriction != port.RestrictionNone, Fallback: in.OrgFallback, RequestID: in.RequestID}
		picked, err := m.Orgs.Pick(ctx, tx, u, pick)
		if errors.Is(err, ErrPasskeyEnrollment) && restriction == port.RestrictionNone {
			// 管理ユーザーが passkey の必須だけで入れないなら、passkey の登録だけができるセッションにする（ADR 0076）。
			restriction, s.Restriction = port.RestrictionEnroll, port.RestrictionEnroll
			hits = slices.DeleteFunc(hits, func(w warning.Warning) bool { return w.Code == warning.CodeSingleFactor })
			if s.Warnings, err = json.Marshal(nonNilWarnings(hits)); err != nil {
				return Issued{}, err
			}
			pick.Warnings, pick.Partial = hits, true
			picked, err = m.Orgs.Pick(ctx, tx, u, pick)
		}
		if err != nil {
			return Issued{}, err
		}
		s.ActiveOrgID, choices = picked.OrgID, picked.Choices
	}
	lim, err := m.limits(ctx, tx, in.RealmID, s.ActiveOrgID)
	if err != nil {
		return Issued{}, err
	}
	// 寿命は認証の時刻から数え、active な Org の値に従う（5.4）。
	s.ExpiresAt = authAt.Add(lim.AbsoluteLifetime)
	switch restriction {
	case port.RestrictionNone:
	case port.RestrictionRecovery:
		s.ExpiresAt = earliest(s.ExpiresAt, now.Add(m.recoveryTTL()))
	default:
		s.ExpiresAt = earliest(s.ExpiresAt, now.Add(m.secondFactorTTL()))
	}
	// 入った Org で deny にならないことは Pick が確かめている。本人に返すのは Org の段を当てはめた警告。
	warnings, _ := m.Warnings.Apply(hits, lim.Warnings)
	// 同じブラウザの古いセッション。同じ本人の通常のセッションなら、ログインの系列（sid）を引き継ぐ（連携先の認可が続く。5.1）。
	var old *port.Session
	var current port.Session // 引き継ぐ系列の今のセッション
	if sid, secret, ok := SplitToken(in.ReplaceToken); ok {
		o, err := tx.Sessions().Get(ctx, in.RealmID, sid)
		if err == nil && (o.RevokedAt == nil || now.Before(*o.RevokedAt)) && subtle.ConstantTimeCompare(o.TokenHash, hashSecret(secret)) == 1 {
			old = &o
		}
	}
	s.SID = s.ID
	if old != nil && old.PrincipalType == port.PrincipalUser && old.PrincipalID == s.PrincipalID && old.Restriction == port.RestrictionNone &&
		restriction == port.RestrictionNone && old.SID != "" {
		// 古いセッションと、その系列の今のセッション（入れ替えの後なら新しい方）がどちらも使える（寿命・無操作・停止などを
		// Validate と同じに確かめる）ときだけ引き継ぐ。今のセッションをログアウトした後に、猶予の残る古い Cookie で系列を蘇らせない。
		_, _, _, err := m.check(ctx, tx, *old, now)
		if err == nil {
			current, _, err = m.CheckLineage(ctx, tx, in.RealmID, old.SID, now)
		}
		switch {
		case err == nil:
			s.SID = old.SID
			s.CreatedAt = successorTime(current.CreatedAt, now)
		case errors.Is(err, errRejected) || errors.Is(err, errs.NotFound) || errors.Is(err, ErrInvalid):
		default:
			return Issued{}, err
		}
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
	if old != nil {
		oldActor, err := userActor(ctx, tx, in.RealmID, old.PrincipalID)
		if err != nil {
			return Issued{}, err
		}
		if err := m.revokeInTx(ctx, tx, *old, ReasonReplacedByLogin, oldActor, in.RequestID); err != nil {
			return Issued{}, err
		}
		details["replaced"] = old.ID
		replaced = old.ID
	}
	// 古いセッションが入れ替えの猶予の内なら、系列の今のセッションも置き換わる（同じ系列の使えるセッションを2つ残さない）。
	var retired string
	if current.ID != "" && old != nil && current.ID != old.ID {
		if err := m.revokeInTx(ctx, tx, current, ReasonReplacedByLogin, actor, in.RequestID); err != nil {
			return Issued{}, err
		}
		retired = current.ID
	}
	var orgPublicID string
	if s.ActiveOrgID != "" {
		o, err := tx.Orgs().Get(ctx, in.RealmID, s.ActiveOrgID)
		if err != nil {
			return Issued{}, err
		}
		orgPublicID = o.PublicID
	}
	_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
		Type: "session.created", Result: audit.ResultSuccess, RealmID: in.RealmID, OrgID: orgPublicID,
		Actor: actor, SessionID: s.ID, IP: in.IP, UserAgent: in.UserAgent,
		RequestID: in.RequestID, Details: details,
	})
	if err == nil && (len(scores) > 0 || len(dropped) > 0) {
		rd := map[string]any{"source": riskSourceHook, "risk": nonNilScores(scores)}
		if len(dropped) > 0 {
			rd["dropped"] = dropped
		}
		_, err = eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.risk_updated", Result: audit.ResultSuccess, RealmID: in.RealmID, OrgID: orgPublicID,
			Actor: actor, SessionID: s.ID, RequestID: in.RequestID, Details: rd,
		})
	}
	return Issued{Session: s, Token: token, Warnings: warnings, Replaced: replaced, SecondFactorMethods: methods, OrgChoices: choices,
		OrgPublicID: orgPublicID, current: retired}, err
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

func (m *Manager) recoveryTTL() time.Duration {
	if m.Config.RecoveryTTL <= 0 {
		return 15 * time.Minute
	}
	return m.Config.RecoveryTTL
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

// ErrPasskeyEnrollment は、管理ユーザー（ADR 0076）が管理する Org に入れない理由が passkey の必須（require_passkey）だけで、
// passkey を1つも登録していないこと（OrgPicker が返す）。Issue は登録だけのセッション（RestrictionEnroll）を発行し、
// 本人は passkey を登録してからそれでログインし直す。
var ErrPasskeyEnrollment = errors.New("session: passkey enrollment required")

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
		IP: f.IP, UserAgent: f.UserAgent, RequestID: f.RequestID, Carried: carried, AuthenticatedAt: old.AuthenticatedAt,
		OrgID: old.ActiveOrgID, OrgFallback: true,
	})
	if err != nil {
		return Issued{}, err
	}
	is.Replaced = old.ID
	return is, nil
}

// DeletionCancelled は、削除の取り消し専用のセッション（RestrictionDeletion）を失効させ、同じ本人確認の通常のセッションを
// 発行する（4.10）。削除の予定を取り消したのと同じトランザクションで呼び、確定の後に Committed を呼ぶ。
func (m *Manager) DeletionCancelled(ctx context.Context, tx port.Tx, realmID, sessionID, ip, userAgent, requestID string) (Issued, error) {
	now := m.Clock.Now()
	old, err := tx.Sessions().Get(ctx, realmID, sessionID)
	if err != nil {
		return Issued{}, err
	}
	if old.Restriction != port.RestrictionDeletion || (old.RevokedAt != nil && !now.Before(*old.RevokedAt)) || !now.Before(old.ExpiresAt) {
		return Issued{}, ErrNotRestricted
	}
	actor, err := userActor(ctx, tx, realmID, old.PrincipalID)
	if err != nil {
		return Issued{}, err
	}
	if err := m.revokeInTx(ctx, tx, old, ReasonDeletionCancelled, actor, requestID); err != nil {
		return Issued{}, err
	}
	var carried []warning.Warning
	if len(old.Warnings) > 0 {
		if err := json.Unmarshal(old.Warnings, &carried); err != nil {
			return Issued{}, err
		}
	}
	is, err := m.Issue(ctx, tx, Issue{
		RealmID: realmID, UserID: old.PrincipalID, AuthMethods: old.AuthMethods, Credentials: old.AuthCredentialIDs,
		IP: ip, UserAgent: userAgent, RequestID: requestID, Carried: carried, AuthenticatedAt: old.AuthenticatedAt, OrgID: old.ActiveOrgID,
		OrgFallback: true,
	})
	if err != nil {
		return Issued{}, err
	}
	is.Replaced = old.ID
	return is, nil
}

// deniedWarnings は、セッションに残した警告のうち Org の段のアクション（lim）で deny になるものの理由のコードを返す。
func (m *Manager) deniedWarnings(s port.Session, lim OrgLimits) ([]string, error) {
	if len(lim.Warnings) == 0 || len(s.Warnings) == 0 {
		return nil, nil
	}
	var hits []warning.Warning
	if err := json.Unmarshal(s.Warnings, &hits); err != nil {
		return nil, err
	}
	if _, err := m.Warnings.Apply(hits, lim.Warnings); err != nil {
		if d, ok := errors.AsType[*warning.DeniedError](err); ok {
			return d.Reasons(), nil
		}
		return nil, err
	}
	return nil, nil
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
	SessionID string
	// SID はログインの系列の ID（ID を入れ替えても変わらない。OIDC の sid）。
	SID           string
	RealmID       string
	PrincipalType port.PrincipalType
	PrincipalID   string // 内部 ID。外に出さない（ADR 0045）
	// PublicID は主体の公開 ID。API の応答や監査ログにはこちらを使う。
	PublicID string
	// ActiveOrgID は active な Org の内部 ID。フィーチャー org が動いていなければ空。
	ActiveOrgID string
	// OrgUnavailable は active な Org が使えない理由のコード（Org・Membership の停止や有効期間の外、所属の終わり。4.7）。
	// 空なら使える。使えないセッションは失効させず、Org の操作だけを止める（個人 Org への切り替えはできる）。
	OrgUnavailable []string
	// MaxAuthAge は重要な操作に求める直近の認証の期限（active な Org の値。5.4）。
	MaxAuthAge      time.Duration
	AuthMethods     []string
	AuthenticatedAt time.Time
	// Risk はリスクの種類ごとの点数（一覧で有効なものだけ。ADR 0084）。評価していない種類は無い。
	Risk map[string]int
	// Restriction は使える操作の制限（2要素目の確認待ちなど）。空なら制限なし。
	Restriction port.SessionRestriction
	// RotateDue は ID の入れ替えの時期を過ぎていることを表す（Cookie のセッションで入れ替える）。
	RotateDue bool
}

// cached はキャッシュに置く検証の結果。秘密は置かない。
type cached struct {
	Hash            []byte                  `json:"h"`
	SID             string                  `json:"s,omitempty"`
	PrincipalType   port.PrincipalType      `json:"pt"`
	PrincipalID     string                  `json:"p"`
	PublicID        string                  `json:"u"`
	ActiveOrgID     string                  `json:"o,omitempty"`
	OrgUnavailable  []string                `json:"ou,omitempty"`
	MaxAuthAge      time.Duration           `json:"ma,omitempty"`
	AuthMethods     []string                `json:"amr"`
	AuthenticatedAt time.Time               `json:"at"`
	Risk            map[string]int          `json:"rk,omitempty"`
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
		next, u, lim, err := m.check(ctx, tx, s, now)
		if err != nil {
			return err
		}
		// 無操作の期限を延ばす。書き込みはキャッシュに外れたとき（最大でも ValidityMaxDelay ごと）だけ。
		if err := tx.Sessions().Touch(ctx, realmID, sid, now); err != nil {
			return err
		}
		if lim.IdleTimeout > 0 {
			next = earliest(next, now.Add(lim.IdleTimeout))
		}
		var orgUnavailable []string
		if s.ActiveOrgID != "" && m.Orgs != nil {
			// Org の段で deny にした警告に当たるセッションは、その Org に入れない（10章）。
			denied, err := m.deniedWarnings(s, lim)
			if err != nil {
				return err
			}
			orgUnavailable = append(orgUnavailable, denied...)
			at, err := m.Orgs.CheckActive(ctx, tx, realmID, s.PrincipalID, s.ActiveOrgID, now)
			if d, ok := errors.AsType[errs.Denial](err); ok {
				orgUnavailable = append(orgUnavailable, d.Reasons()...)
			} else if errors.Is(err, errs.PermissionDenied) {
				orgUnavailable = append(orgUnavailable, errs.CodeNoAvailableOrg)
			} else if err != nil {
				return err
			} else if at != nil {
				next = earliest(next, *at)
			}
		}
		slices.Sort(orgUnavailable)
		scores, err := sessionRisk(ctx, tx, s)
		if err != nil {
			return err
		}
		c = cached{Risk: scores, Hash: s.TokenHash, SID: s.SID, PrincipalType: s.PrincipalType, PrincipalID: s.PrincipalID, PublicID: u.PublicID,
			ActiveOrgID: s.ActiveOrgID, OrgUnavailable: slices.Compact(orgUnavailable), MaxAuthAge: lim.MaxAuthAge, AuthMethods: s.AuthMethods, AuthenticatedAt: s.AuthenticatedAt, CreatedAt: s.CreatedAt, NextCheck: next, Restriction: s.Restriction}
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
	lineage := c.SID
	if lineage == "" {
		lineage = sid
	}
	v := Validated{SessionID: sid, SID: lineage, RealmID: realmID, PrincipalType: c.PrincipalType, PrincipalID: c.PrincipalID,
		PublicID: c.PublicID, ActiveOrgID: c.ActiveOrgID, OrgUnavailable: c.OrgUnavailable, MaxAuthAge: c.MaxAuthAge, AuthMethods: c.AuthMethods,
		AuthenticatedAt: c.AuthenticatedAt, Risk: c.Risk, Restriction: c.Restriction}
	if m.Config.RotationInterval > 0 && !now.Before(c.CreatedAt.Add(m.Config.RotationInterval)) {
		v.RotateDue = true
	}
	return v
}

// check はセッションが今有効かを確かめ、次に状態が変わる時刻（再検証の期限）と主体、active な Org で決まる値を返す。
// 寿命は active な Org の値に従う（設定の変更は ValidityMaxDelay の内に既存のセッションにも効く。5.4）。
func (m *Manager) check(ctx context.Context, tx port.Tx, s port.Session, now time.Time) (time.Time, port.User, OrgLimits, error) {
	next, u, err := m.checkSession(ctx, tx, s, now)
	if err != nil {
		return time.Time{}, port.User{}, OrgLimits{}, err
	}
	lim, err := m.limits(ctx, tx, s.RealmID, s.ActiveOrgID)
	if err != nil {
		return time.Time{}, port.User{}, OrgLimits{}, err
	}
	if lim.beyond(s.AuthenticatedAt, s.LastSeenAt, now) {
		return time.Time{}, port.User{}, OrgLimits{}, rejected("beyond the lifetime")
	}
	if lim.AbsoluteLifetime > 0 {
		next = earliest(next, s.AuthenticatedAt.Add(lim.AbsoluteLifetime))
	}
	return next, u, lim, nil
}

func (m *Manager) checkSession(ctx context.Context, tx port.Tx, s port.Session, now time.Time) (time.Time, port.User, error) {
	if s.RevokedAt != nil && !now.Before(*s.RevokedAt) {
		return time.Time{}, port.User{}, rejected("revoked")
	}
	if !now.Before(s.ExpiresAt) {
		return time.Time{}, port.User{}, rejected("expired")
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
	// 停止と有効期間は時刻から計算する。認証の後に始まった停止は、解除されてもこのセッションを戻さない（4.7）。
	// 復旧専用のセッションは security_risk の停止を見ない（認証手段を入れ替えてから、セキュリティ担当が解除する。4.12）。
	var ignore []string
	if s.Restriction == port.RestrictionRecovery {
		ignore = account.RecoveryIgnores
	}
	// 削除の予定があれば、取り消し専用（と、そこへ至る途中の段）のセッションだけが使える（4.10）。
	if u.DeletionScheduledAt != nil && s.Restriction == port.RestrictionNone {
		return time.Time{}, port.User{}, rejected("deletion scheduled")
	}
	at, err := account.Check(ctx, tx, u, s.AuthenticatedAt, now, ignore...)
	if err != nil {
		if errors.Is(err, account.ErrInactive) || errors.As(err, new(*account.UnavailableError)) {
			return time.Time{}, port.User{}, rejected(err.Error())
		}
		return time.Time{}, port.User{}, err
	}
	if at != nil {
		next = earliest(next, *at)
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

// successorTime は系列を継ぐセッションの作成時刻。系列の今のセッションは作成時刻の新しい方なので（GetCurrentBySID）、
// 同じ時刻に作っても前のセッションより後になるようにする（時計の粒度が粗いときやテストの時計）。
func successorTime(prev, now time.Time) time.Time {
	if now.After(prev) {
		return now
	}
	return prev.Add(time.Nanosecond)
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// CheckLineage はログインの系列（sid）の今のセッションが使えるかを、Validate と同じ規則で確かめる（OIDC の認可の検証。5.3）。
// 使えれば今のセッションと、次に状態が変わる時刻（再検証の期限）を返す。使えない系列は ErrInvalid。
// 連携先からの利用は無操作の期限を延ばさない（延ばすのはリフレッシュ。Touch）。
func (m *Manager) CheckLineage(ctx context.Context, tx port.Tx, realmID, sid string, now time.Time) (port.Session, time.Time, error) {
	s, err := tx.Sessions().GetCurrentBySID(ctx, realmID, sid)
	if errors.Is(err, errs.NotFound) {
		return port.Session{}, time.Time{}, ErrInvalid
	}
	if err != nil {
		return port.Session{}, time.Time{}, err
	}
	if s.Restriction != port.RestrictionNone {
		return port.Session{}, time.Time{}, ErrInvalid
	}
	next, _, lim, err := m.check(ctx, tx, s, now)
	if errors.Is(err, errRejected) || errors.Is(err, errs.NotFound) {
		m.logger().DebugContext(ctx, "session lineage rejected", "sid", sid, "reason", err.Error())
		return port.Session{}, time.Time{}, ErrInvalid
	}
	if err != nil {
		return port.Session{}, time.Time{}, err
	}
	if lim.IdleTimeout > 0 {
		next = earliest(next, s.LastSeenAt.Add(lim.IdleTimeout))
	}
	return s, next, nil
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
		s.ID, s.CreatedAt, s.LastSeenAt = id.NewExternal(id.Session), successorTime(old.CreatedAt, now), now
		if s.SID == "" {
			s.SID = old.ID
		}
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

// ErrNotSwitchable は Org を切り替えられないセッション（失効・期限切れ・制限つき）。
var ErrNotSwitchable = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "session cannot switch org")

// SwitchOrg はセッションの active な Org を orgID（内部 ID）に替え、ID を入れ替える（4.4、5.2）。
// 古い ID はすぐに失効させる（別の Org の文脈で使われ続けないように）。入れる Org かは OrgPicker で確かめる。
// ip は切り替えの要求の IP（Org のログインポリシーの判定）。
func (m *Manager) SwitchOrg(ctx context.Context, realmID, sessionID, orgID, ip, requestID string) (Issued, error) {
	if m.Orgs == nil {
		return Issued{}, errs.New(errs.KindNotFound, "org feature is off")
	}
	now := m.Clock.Now()
	var out Issued
	var retired string // 一緒に失効させた系列の今のセッション
	err := m.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		old, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if err != nil {
			return err
		}
		if (old.RevokedAt != nil && !now.Before(*old.RevokedAt)) || !now.Before(old.ExpiresAt) || old.Restriction != port.RestrictionNone {
			return ErrNotSwitchable
		}
		// 系列の今のセッション（入れ替えの後なら新しい方）も使えなければ切り替えない。ログアウトした系列を、猶予の残る
		// 古いセッションから蘇らせない。
		lineage := old.SID
		if lineage == "" {
			lineage = old.ID
		}
		current, _, err := m.CheckLineage(ctx, tx, realmID, lineage, now)
		if errors.Is(err, ErrInvalid) {
			return ErrNotSwitchable
		}
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, realmID, old.PrincipalID)
		if err != nil {
			return err
		}
		var hits []warning.Warning
		if len(old.Warnings) > 0 {
			if err := json.Unmarshal(old.Warnings, &hits); err != nil {
				return err
			}
		}
		picked, err := m.Orgs.Pick(ctx, tx, u, OrgPick{Explicit: orgID, Credentials: old.AuthCredentialIDs, Warnings: hits, AuthMethods: old.AuthMethods, IP: ip, RequestID: requestID})
		if err != nil {
			return err
		}
		// 切り替え先の Org の寿命を超えていれば再認証を求める（5.4）。
		lim, err := m.limits(ctx, tx, realmID, picked.OrgID)
		if err != nil {
			return err
		}
		if lim.beyond(old.AuthenticatedAt, old.LastSeenAt, now) {
			return ErrReauthRequired
		}
		o, err := tx.Orgs().Get(ctx, realmID, picked.OrgID)
		if err != nil {
			return err
		}
		s := old
		s.ID, s.ActiveOrgID, s.CreatedAt, s.LastSeenAt, s.RevokedAt, s.RevokeReason = id.NewExternal(id.Session), picked.OrgID, successorTime(current.CreatedAt, now), now, nil, ""
		if s.SID == "" {
			s.SID = old.ID
		}
		s.ExpiresAt = old.AuthenticatedAt.Add(lim.AbsoluteLifetime)
		token, hash, err := newToken(s.ID)
		if err != nil {
			return err
		}
		s.TokenHash = hash
		if err := tx.Sessions().Create(ctx, s); err != nil {
			return err
		}
		if err := tx.Sessions().Revoke(ctx, realmID, old.ID, now, ReasonOrgSwitched); err != nil {
			return err
		}
		if current.ID != old.ID {
			if err := tx.Sessions().Revoke(ctx, realmID, current.ID, now, ReasonOrgSwitched); err != nil {
				return err
			}
			retired = current.ID
		}
		if _, err := eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.org_switched", Result: audit.ResultSuccess, RealmID: realmID, OrgID: o.PublicID,
			Actor: audit.Actor{Type: "user", ID: u.PublicID}, SessionID: s.ID, RequestID: requestID,
			Details: map[string]any{"previous": old.ID},
		}); err != nil {
			return err
		}
		out = Issued{Session: s, Token: token, Replaced: old.ID, OrgPublicID: o.PublicID}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	m.forget(ctx, realmID, sessionID)
	if retired != "" {
		m.forget(ctx, realmID, retired)
	}
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
	if err := m.EndLineagesTx(ctx, tx, realmID, ids, reason, requestID); err != nil {
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
	if err != nil {
		return err
	}
	return m.EndLineagesTx(ctx, tx, s.RealmID, []string{s.ID}, reason, requestID)
}

// EndLineagesTx は失効させたセッションのうち、ログインの系列の今のセッションだったものの系列を終える（Lineages を呼ぶ）。
// ID の入れ替えで古い ID を失効させたときは、系列の今のセッションは新しい ID なので終わらない。
func (m *Manager) EndLineagesTx(ctx context.Context, tx port.Tx, realmID string, sessionIDs []string, reason, requestID string) error {
	if m.Lineages == nil {
		return nil
	}
	now := m.Clock.Now()
	done := map[string]bool{}
	for _, sessionID := range sessionIDs {
		s, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if s.SID == "" || done[s.SID] {
			continue
		}
		cur, err := tx.Sessions().GetCurrentBySID(ctx, realmID, s.SID)
		if err != nil {
			return err
		}
		if cur.RevokedAt == nil || now.Before(*cur.RevokedAt) {
			continue
		}
		done[s.SID] = true
		if err := m.Lineages.LineageEnded(ctx, tx, realmID, s.SID, reason, requestID); err != nil {
			return err
		}
	}
	return nil
}

// EndUserTx は主体のログインの系列をすべて終える（停止・有効期間の終わりなど、セッションを失効させずに使えなくなったとき。
// Back-Channel Logout。5.2）。停止が解けてもその系列の連携先の認可は戻らない。
func (m *Manager) EndUserTx(ctx context.Context, tx port.Tx, realmID, userID, reason, requestID string) error {
	if m.Lineages == nil {
		return nil
	}
	all, err := tx.Sessions().ListByPrincipal(ctx, realmID, port.PrincipalUser, userID)
	if err != nil {
		return err
	}
	now := m.Clock.Now()
	done := map[string]bool{}
	for _, s := range all {
		if s.SID == "" || done[s.SID] || (s.RevokedAt != nil && !now.Before(*s.RevokedAt)) || !now.Before(s.ExpiresAt) {
			continue
		}
		done[s.SID] = true
		if err := m.Lineages.LineageEnded(ctx, tx, realmID, s.SID, reason, requestID); err != nil {
			return err
		}
	}
	return nil
}

// forget はキャッシュを消す（ベストエフォート。失敗しても TTL で上限内に反映される。5.3）。
// Storage に書いた後に呼ぶ。
func (m *Manager) forget(ctx context.Context, realmID, sessionID string) {
	if err := m.Cache.Delete(ctx, cacheKey(realmID, sessionID)); err != nil {
		m.logger().WarnContext(ctx, "session cache delete failed", "session_id", sessionID, "error", err)
	}
}

// Forget は主体のセッションの検証結果のキャッシュを消し、次の検証で状態（停止・有効期間など）を見直させる。
// 状態を Storage に書いた後に呼ぶ。消せなくても上限の時間内に反映される（5.3）。
func (m *Manager) Forget(ctx context.Context, realmID, userID string) {
	ss, err := m.List(ctx, realmID, userID)
	if err != nil {
		m.logger().WarnContext(ctx, "session list for cache delete failed", "error", err)
		return
	}
	for _, x := range ss {
		m.forget(ctx, realmID, x.ID)
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
