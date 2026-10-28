package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ユーザーが停止・有効期間の外になったときに、ログインの系列を終える（Back-Channel Logout。design.md 5.2、ADR 0066）。
// セッションは失効させない（停止が解ければ使える）が、連携先の認可は戻らない。

// inValidity はユーザーが now に有効期間の内かを返す。
func inValidity(u port.User, now time.Time) bool {
	return (u.ValidFrom == nil || !now.Before(*u.ValidFrom)) && (u.ValidUntil == nil || now.Before(*u.ValidUntil))
}

// endOnSuspensionStart は予約したユーザーの停止の始まり（scheduler の Handler）。解除済みなら何もしない。
func (a *App) endOnSuspensionStart(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	spID, _ := details["suspension_id"].(string)
	sp, err := tx.Suspensions().GetByPublicID(ctx, e.RealmID, spID)
	if errors.Is(err, errs.NotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if sp.LiftedAt != nil || sp.TargetType != port.SuspensionTargetUser {
		return nil
	}
	return a.sessions.EndUserTx(ctx, tx, e.RealmID, sp.TargetID, session.ReasonSuspended, "")
}

// endOnValidityEnd は有効期間の終わり（scheduler の Handler）。期間が延びていれば何もしない。
func (a *App) endOnValidityEnd(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	userID, _ := details["user_id"].(string)
	u, err := tx.Users().GetByPublicID(ctx, e.RealmID, userID)
	if errors.Is(err, errs.NotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if inValidity(u, a.deps.Clock.Now()) {
		return nil
	}
	return a.sessions.EndUserTx(ctx, tx, e.RealmID, u.ID, session.ReasonValidity, "")
}
