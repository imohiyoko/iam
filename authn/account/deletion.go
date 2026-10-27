package account

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウントの削除（design.md 4.10、ADR 0061）。

// EventUserDeleted は猶予期間の後の削除の出来事（Scheduler の Handler は PurgeDue）。
const EventUserDeleted = "user.deleted"

// ReasonDeletionScheduled は削除の予約で失効させたセッションの理由。
const ReasonDeletionScheduled = "deletion_scheduled"

var (
	// ErrDeletionScheduled は既に削除の予定があること。
	ErrDeletionScheduled = errs.WithCode(errs.KindConflict, "deletion_scheduled", "account deletion already scheduled")
	// ErrLastRealmOwner は realm の最後の realm:owner を消そうとしたこと。先に別のユーザーに realm:owner を付与する。
	ErrLastRealmOwner = errs.WithCode(errs.KindFailedPrecondition, "last_owner", "grant realm:owner to another user first")
	// ErrDeletionNotScheduled は取り消す削除の予定が無いこと。
	ErrDeletionNotScheduled = errs.WithCode(errs.KindConflict, "deletion_not_scheduled", "account deletion is not scheduled")
)

func deletionRef(u port.User) string { return "user_deletion:" + u.PublicID }

// ScheduleDeletion はアカウントの削除を予約する（本人か運営者）。猶予期間の間はログインしても削除の取り消しだけができる。
// 既存のセッションは呼び出し側が同じトランザクションで失効させ（ReasonDeletionScheduled）、確定の後に検証結果のキャッシュを
// 消す。grace が 0 以下なら今削除する。
// 共有 Org の最後のオーナーの間と、realm の最後の realm:owner の間はできない（先に譲るか Org を削除する）。
func (s *Service) ScheduleDeletion(ctx context.Context, tx port.Tx, u port.User, grace time.Duration, actor audit.Actor, requestID string) (port.User, error) {
	if u.Status != port.UserActive {
		return port.User{}, errs.New(errs.KindNotFound, "user")
	}
	if u.DeletionScheduledAt != nil {
		return port.User{}, ErrDeletionScheduled
	}
	if s.Orgs != nil {
		if err := s.Orgs.Deletable(ctx, tx, u); err != nil {
			return port.User{}, err
		}
	}
	if last, err := s.lastOwner(ctx, tx, u); err != nil {
		return port.User{}, err
	} else if last {
		return port.User{}, ErrLastRealmOwner
	}
	now := s.Clock.Now()
	if grace <= 0 && !u.LegalHold {
		if err := s.purge(ctx, tx, u, actor, requestID); err != nil {
			return port.User{}, err
		}
		u.Status, u.UpdatedAt = port.UserDeleted, now
		return u, s.record(ctx, tx, u.RealmID, EventUserDeleted, actor, requestID, map[string]any{"user_id": u.PublicID})
	}
	at := now.Add(max(grace, 0))
	if err := tx.Users().SetDeletion(ctx, u.RealmID, u.ID, &at, now); err != nil {
		return port.User{}, err
	}
	if err := eventlog.Schedule(ctx, tx, s.Clock, u.RealmID, deletionRef(u), EventUserDeleted, at, map[string]any{"user_id": u.PublicID}); err != nil {
		return port.User{}, err
	}
	u.DeletionScheduledAt, u.UpdatedAt = &at, now
	return u, s.record(ctx, tx, u.RealmID, "user.deletion_scheduled", actor, requestID,
		map[string]any{"user_id": u.PublicID, "deletes_at": at.UTC().Format(time.RFC3339Nano)})
}

// CancelDeletion は猶予期間の間に削除の予定を取り消す（本人は本人確認の後、運営者）。
func (s *Service) CancelDeletion(ctx context.Context, tx port.Tx, u port.User, actor audit.Actor, requestID string) (port.User, error) {
	if u.Status != port.UserActive {
		return port.User{}, errs.New(errs.KindNotFound, "user")
	}
	if u.DeletionScheduledAt == nil {
		return port.User{}, ErrDeletionNotScheduled
	}
	now := s.Clock.Now()
	if err := tx.Users().SetDeletion(ctx, u.RealmID, u.ID, nil, now); err != nil {
		return port.User{}, err
	}
	if err := tx.ScheduledEvents().CancelByRef(ctx, u.RealmID, deletionRef(u)); err != nil {
		return port.User{}, err
	}
	u.DeletionScheduledAt, u.UpdatedAt = nil, now
	return u, s.record(ctx, tx, u.RealmID, "user.deletion_cancelled", actor, requestID, map[string]any{"user_id": u.PublicID})
}

// SetLegalHold は消去の保留を立てる・下ろす（運営者。4.10）。保留の間は猶予が終わっても消さない。
// 下ろしたときに猶予が終わっていれば、次の回に消すよう予約し直す。
func (s *Service) SetLegalHold(ctx context.Context, tx port.Tx, u port.User, hold bool, actor audit.Actor, requestID string) (port.User, error) {
	if u.Status != port.UserActive {
		return port.User{}, errs.New(errs.KindNotFound, "user")
	}
	now := s.Clock.Now()
	if err := tx.Users().SetLegalHold(ctx, u.RealmID, u.ID, hold, now); err != nil {
		return port.User{}, err
	}
	if !hold && u.LegalHold && u.DeletionScheduledAt != nil && !u.DeletionScheduledAt.After(now) {
		if err := eventlog.Schedule(ctx, tx, s.Clock, u.RealmID, deletionRef(u), EventUserDeleted, now, map[string]any{"user_id": u.PublicID}); err != nil {
			return port.User{}, err
		}
	}
	u.LegalHold, u.UpdatedAt = hold, now
	return u, s.record(ctx, tx, u.RealmID, "user.legal_hold_changed", actor, requestID, map[string]any{"user_id": u.PublicID, "legal_hold": hold})
}

// PurgeDue は猶予期間の終わったユーザーを消す（eventlog.Handler）。取り消された・消去済みなら何もせず、保留中なら
// user.deletion_held を残す（保留を下ろすと予約し直す）。猶予の間に realm の最後の realm:owner になっていれば消さず、
// user.deletion_held（reason: last_owner）を残す（運営者が取り消すか、別のユーザーに付与してから保留の操作で予約し直す）。
// どれも user.deleted は出さない。
func (s *Service) PurgeDue(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	publicID, _ := details["user_id"].(string)
	u, err := tx.Users().GetByPublicID(ctx, e.RealmID, publicID)
	if errors.Is(err, errs.NotFound) {
		return eventlog.ErrSkip
	}
	if err != nil {
		return err
	}
	if u.Status != port.UserActive || u.DeletionScheduledAt == nil || u.DeletionScheduledAt.After(s.Clock.Now()) {
		return eventlog.ErrSkip
	}
	if u.LegalHold {
		// 消していないことを監査ログに残す。
		if err := s.record(ctx, tx, u.RealmID, "user.deletion_held", audit.Actor{Type: "system"}, "", map[string]any{"user_id": u.PublicID}); err != nil {
			return err
		}
		return eventlog.ErrSkip
	}
	if last, err := s.lastOwner(ctx, tx, u); err != nil {
		return err
	} else if last {
		if err := s.record(ctx, tx, u.RealmID, "user.deletion_held", audit.Actor{Type: "system"}, "",
			map[string]any{"user_id": u.PublicID, "reason": "last_owner"}); err != nil {
			return err
		}
		return eventlog.ErrSkip
	}
	return s.purge(ctx, tx, u, audit.Actor{Type: "system"}, "")
}

// purge はユーザーを消す：所属を終えて個人 Org を削除し、認証情報・セッション・メールのインデックスを消し、
// データ鍵を消して（crypto-shredding）、ID を墓標として残す（4.10）。
func (s *Service) purge(ctx context.Context, tx port.Tx, u port.User, actor audit.Actor, requestID string) error {
	if s.Orgs != nil {
		if err := s.Orgs.Release(ctx, tx, u, actor, requestID); err != nil {
			return err
		}
	}
	if err := tx.Users().Erase(ctx, u.RealmID, u.ID, s.Clock.Now()); err != nil {
		return err
	}
	return tx.DataKeys().Delete(ctx, u.ID)
}

func (s *Service) lastOwner(ctx context.Context, tx port.Tx, u port.User) (bool, error) {
	if s.Roles == nil {
		return false, nil
	}
	return s.Roles.IsLastOwner(ctx, tx, u.RealmID, u.ID)
}
