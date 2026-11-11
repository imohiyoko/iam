package provider

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// offline_access（OIDC Core 11。ADR 0126）。
//
// フィーチャー offline_access が動いていて、連携先に offline_access を許していれば、offline_access のスコープを含む認可を
// ログインの系列から切り離す（Grant.Offline）。系列のログアウト・セッションの期限では失効せず、ユーザーの状態（削除・削除の予定・
// 停止・有効期間）、認可に使った認証情報、Org で確かめる。系列が失効・停止・認証情報の変更・復旧で終わったときは一緒に失効させる。
// 本人は連携先ごとに取り消せる（/v1/me/offline-access）。リフレッシュトークンは無操作の期限（OfflineIdleTTL）で切れ、
// 認可は OfflineMaxTTL で切れる。

// OfflineAccessFeature は offline_access のフィーチャー（既定オフ）。持つデータは連携先の offline_access と Offline の認可。
var OfflineAccessFeature = feature.Feature{Name: feature.OfflineAccess, DataVersion: 1}

// ScopeOfflineAccess は offline_access のスコープ（OIDC Core 11）。
const ScopeOfflineAccess = "offline_access"

// Offline の認可の既定の寿命。
const (
	// DefaultOfflineIdleTTL はリフレッシュトークンの無操作の期限（使うたびに延びる）。
	DefaultOfflineIdleTTL = 30 * 24 * time.Hour
	// DefaultOfflineMaxTTL は認可の寿命（延びない）。
	DefaultOfflineMaxTTL = 365 * 24 * time.Hour
)

// RevokeReasonUser は本人が取り消した Offline の認可の失効の理由。
const RevokeReasonUser = "revoked_by_user"

// offlineKept はログインの系列が終わっても Offline の認可を残す理由（ログアウトと、系列の続きへの入れ替え）。
// ほかの理由（本人・運営者による失効、停止、有効期間、認証情報の変更、復旧、削除の取り消し）では一緒に失効させる。
var offlineKept = []string{session.ReasonLogout, session.ReasonRotated, session.ReasonReplacedByLogin, session.ReasonOrgSwitched}

// offlineScope は、認可を Offline にするかを返す（フィーチャーが動いていて、連携先に許していて、スコープを求めたとき）。
func (t *Tokens) offlineScope(cl port.Client, scopes []string) bool {
	return t.Offline && cl.OfflineAccess && slices.Contains(scopes, ScopeOfflineAccess)
}

// withoutOffline は offline_access を除いたスコープ（Offline にしない認可には残さない）。
func withoutOffline(scopes []string) []string {
	if !slices.Contains(scopes, ScopeOfflineAccess) {
		return scopes
	}
	return slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == ScopeOfflineAccess })
}

// refreshExpiry はリフレッシュトークンの期限。Offline の認可は無操作の期限（使うたびに延びる）と認可の期限の早い方。
func (t *Tokens) refreshExpiry(g port.Grant, now time.Time) time.Time {
	if !g.Offline {
		return g.ExpiresAt
	}
	return earliestOf(g.ExpiresAt, now.Add(ttlOr(t.OfflineIdleTTL, DefaultOfflineIdleTTL)))
}

// offlineAliveUntil は Offline の認可がまだ使えるかを、ログインの系列の代わりにユーザー・認証情報・連携先・Org で確かめる。
// 使えなければ ErrInvalidToken。次に状態が変わる時刻を返す。
func (t *Tokens) offlineAliveUntil(ctx context.Context, tx port.Tx, g port.Grant, now time.Time) (time.Time, error) {
	if !t.Offline {
		return time.Time{}, ErrInvalidToken // フィーチャーが止まっていれば使えない（fail-closed）
	}
	cl, err := tx.Clients().Get(ctx, g.RealmID, g.ClientID)
	if errors.Is(err, errs.NotFound) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	if !cl.OfflineAccess {
		return time.Time{}, ErrInvalidToken // 連携先の許可を外した
	}
	u, err := tx.Users().Get(ctx, g.RealmID, g.UserID)
	if errors.Is(err, errs.NotFound) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	if u.DeletionScheduledAt != nil {
		return time.Time{}, ErrInvalidToken
	}
	// 認可の後に始まった停止は、解除されても認可を戻さない（セッションと同じ。4.7）。
	at, err := account.Check(ctx, tx, u, g.CreatedAt, now)
	if errors.Is(err, account.ErrInactive) || errors.As(err, new(*account.UnavailableError)) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	next := g.ExpiresAt
	if at != nil {
		next = earliestOf(next, *at)
	}
	if err := session.CheckCredentials(ctx, tx, g.RealmID, g.UserID, g.AuthCredentialIDs); errors.Is(err, session.ErrInvalid) {
		return time.Time{}, ErrInvalidToken
	} else if err != nil {
		return time.Time{}, err
	}
	return t.orgAliveUntil(ctx, tx, g.RealmID, g.UserID, g.OrgID, now, next)
}

// PrincipalRevoked はユーザーのセッションをまとめて失効させたとき（認証情報の変更・復旧・運営者による失効など）、
// 残したセッションの系列 keepSID 以外の Offline の認可を、ログアウト済みの系列のものも含めて失効させる（session.PrincipalHook）。
// 系列の失効と同じく、ログアウトと系列の続きへの入れ替え（offlineKept）では残す。
func (t *Tokens) PrincipalRevoked(ctx context.Context, tx port.Tx, realmID, userID, keepSID, reason, requestID string) error {
	if slices.Contains(offlineKept, reason) {
		return nil
	}
	gs, err := tx.Grants().ListOfflineByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	now := t.Clock.Now()
	for _, g := range gs {
		if revoked(g, now) || (keepSID != "" && g.SID == keepSID) {
			continue
		}
		cl, err := tx.Clients().Get(ctx, realmID, g.ClientID)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := t.revoke(ctx, tx, cl, g, RevokeReasonLogout, requestID, now); err != nil {
			return err
		}
	}
	return nil
}

// OfflineApp は本人の Offline の認可を連携先ごとにまとめたもの（/v1/me/offline-access）。
type OfflineApp struct {
	Client port.Client
	// Scopes は使える認可のスコープの和（作成の順）。
	Scopes []string
	// CreatedAt は使える認可のうち最も古いものの作成時刻。
	CreatedAt time.Time
	// ExpiresAt は使える認可のうち最も遅い期限。
	ExpiresAt time.Time
}

// OfflineApps は本人の使える（失効・期限切れでない）Offline の認可を、連携先ごとにまとめて返す（最初に許した順）。
func (t *Tokens) OfflineApps(ctx context.Context, tx port.Tx, realmID, userID string) ([]OfflineApp, error) {
	gs, err := tx.Grants().ListOfflineByUser(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	now := t.Clock.Now()
	var out []OfflineApp
	idx := map[string]int{}
	for _, g := range gs {
		if revoked(g, now) || g.Exchange != "" {
			continue
		}
		i, ok := idx[g.ClientID]
		if !ok {
			cl, err := tx.Clients().Get(ctx, realmID, g.ClientID)
			if errors.Is(err, errs.NotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			i = len(out)
			idx[g.ClientID] = i
			out = append(out, OfflineApp{Client: cl, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt})
		}
		a := &out[i]
		for _, s := range g.Scopes {
			if !slices.Contains(a.Scopes, s) {
				a.Scopes = append(a.Scopes, s)
			}
		}
		if g.ExpiresAt.After(a.ExpiresAt) {
			a.ExpiresAt = g.ExpiresAt
		}
	}
	return out, nil
}

// RevokeOffline は本人の、連携先 clientID（公開の client_id）の Offline の認可をすべて失効させる（監査ログ oidc.grant_revoked）。
// 連携先が無いか、使える認可が無ければ errs.NotFound。
func (t *Tokens) RevokeOffline(ctx context.Context, tx port.Tx, realmID, userID, clientID, requestID string) error {
	cl, err := tx.Clients().GetByPublicID(ctx, realmID, clientID)
	if err != nil {
		return err
	}
	gs, err := tx.Grants().ListOfflineByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	now := t.Clock.Now()
	n := 0
	for _, g := range gs {
		if g.ClientID != cl.ID || revoked(g, now) {
			continue
		}
		if err := t.revoke(ctx, tx, cl, g, RevokeReasonUser, requestID, now); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "no offline access for client %s", clientID)
	}
	return nil
}
