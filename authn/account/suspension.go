package account

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 停止の種別（design.md 4.7）。realm で足せる（Service.ExtraCategories）。
const (
	CategoryTOSViolation    = "tos_violation"
	CategoryCustomerRequest = "customer_request"
	CategorySecurityRisk    = "security_risk"
	CategoryBilling         = "billing"
)

// BuiltinCategories は組み込みの停止の種別。
var BuiltinCategories = []string{CategoryTOSViolation, CategoryCustomerRequest, CategorySecurityRisk, CategoryBilling}

// ユーザーの境界のイベントの種類（scheduled_events に予約し、時刻の後に監査ログへ出す。4.8）。
// Org・Membership は接頭辞が org.・membership. になる（Target）。
const (
	EventSuspensionStarted = "user.suspension_started"
	EventSuspensionEnded   = "user.suspension_ended"
	EventValidityStarted   = "user.validity_started"
	EventValidityEnded     = "user.validity_ended"
)

const (
	maxReason      = 1000
	maxExternalRef = 200
)

var (
	ErrUnknownCategory = errs.WithCode(errs.KindInvalid, "unknown_category", "unknown suspension category")
	ErrInvalidPeriod   = errs.WithCode(errs.KindInvalid, "invalid_period", "end must be after start and in the future")
	// ErrReason は理由が空か長すぎる（管理操作は理由を必須にする。4.13）。
	ErrReason             = errs.WithCode(errs.KindInvalid, "invalid_reason", "reason is required and at most 1000 bytes")
	ErrExternalRefTooLong = errs.WithCode(errs.KindInvalid, "invalid_external_ref", "external_ref too long")
)

// Suspend は停止の指定。
type Suspend struct {
	Category string
	// Reason は内部向けの理由（監査ログに出し、本人には見せない）。
	Reason string
	// StartsAt は nil か過去なら今から。未来なら予約。
	StartsAt *time.Time
	// EndsAt は nil なら無期限。
	EndsAt *time.Time
	// ExternalRef は外部のシステムの参照。同じ対象・種別・参照の停止があれば、新しく作らずそれを返す（冪等）。
	ExternalRef string
}

// Categories は使える停止の種別。
func (s *Service) Categories() []string {
	return append(slices.Clone(BuiltinCategories), s.ExtraCategories...)
}

// Target は停止の対象（design.md 4.7）。
type Target struct {
	Type     port.SuspensionTarget
	ID       string // 内部 ID
	PublicID string // 監査ログに出す公開 ID
}

// UserTarget はユーザーの停止の対象。
func UserTarget(u port.User) Target {
	return Target{Type: port.SuspensionTargetUser, ID: u.ID, PublicID: u.PublicID}
}

// label は監査ログのイベントの種類と詳細の鍵の接頭辞（user.suspended、org_id など）。
func (t Target) label() string { return string(t.Type) }

// SuspendUser はユーザーを停止する（Suspend）。
func (s *Service) SuspendUser(ctx context.Context, tx port.Tx, realmID string, u port.User, in Suspend, actor audit.Actor, requestID string) (port.Suspension, bool, error) {
	return s.Suspend(ctx, tx, realmID, UserTarget(u), in, actor, requestID)
}

// Suspend は対象を停止する。2つ目の戻り値は新しく作ったか（ExternalRef で既存を返したときは false）。
// 停止中かは時刻から計算するので、予約や終わりの時刻は scheduled_events の処理の遅れに左右されない（4.7、4.8）。
// 呼び出し側は確定の後に session.Manager.Forget で検証結果のキャッシュを消す。
func (s *Service) Suspend(ctx context.Context, tx port.Tx, realmID string, t Target, in Suspend, actor audit.Actor, requestID string) (port.Suspension, bool, error) {
	if !slices.Contains(s.Categories(), in.Category) {
		return port.Suspension{}, false, ErrUnknownCategory
	}
	if !validReason(in.Reason) {
		return port.Suspension{}, false, ErrReason
	}
	if len(in.ExternalRef) > maxExternalRef {
		return port.Suspension{}, false, ErrExternalRefTooLong
	}
	now := s.Clock.Now()
	start := now
	if in.StartsAt != nil && in.StartsAt.After(now) {
		start = *in.StartsAt
	}
	if in.EndsAt != nil && (!in.EndsAt.After(start) || !in.EndsAt.After(now)) {
		return port.Suspension{}, false, ErrInvalidPeriod
	}
	if in.ExternalRef != "" {
		if x, ok, err := byExternalRef(ctx, tx, realmID, t, in.Category, in.ExternalRef); err != nil || ok {
			return x, false, err
		}
	}
	sp := port.Suspension{
		ID: id.New(id.Suspension), PublicID: id.NewExternal(id.Suspension), RealmID: realmID,
		TargetType: t.Type, TargetID: t.ID, Category: in.Category, Reason: in.Reason,
		ExternalRef: in.ExternalRef, StartsAt: start, EndsAt: in.EndsAt, CreatedBy: actor.ID, CreatedAt: now,
	}
	if err := tx.Suspensions().Create(ctx, sp); err != nil {
		return port.Suspension{}, false, err
	}
	key := t.label() + "_id"
	boundary := map[string]any{key: t.PublicID, "suspension_id": sp.PublicID, "category": sp.Category}
	if start.After(now) {
		if err := eventlog.Schedule(ctx, tx, s.Clock, realmID, sp.PublicID, t.label()+".suspension_started", start, boundary); err != nil {
			return port.Suspension{}, false, err
		}
	}
	if sp.EndsAt != nil {
		if err := eventlog.Schedule(ctx, tx, s.Clock, realmID, sp.PublicID, t.label()+".suspension_ended", *sp.EndsAt, boundary); err != nil {
			return port.Suspension{}, false, err
		}
	}
	details := map[string]any{key: t.PublicID, "suspension_id": sp.PublicID, "category": sp.Category, "reason": sp.Reason,
		"starts_at": sp.StartsAt.UTC().Format(time.RFC3339Nano)}
	if sp.EndsAt != nil {
		details["ends_at"] = sp.EndsAt.UTC().Format(time.RFC3339Nano)
	}
	if sp.ExternalRef != "" {
		details["external_ref"] = sp.ExternalRef
	}
	return sp, true, s.record(ctx, tx, realmID, t.label()+".suspended", actor, requestID, details)
}

func validReason(r string) bool { return strings.TrimSpace(r) != "" && len(r) <= maxReason }

func byExternalRef(ctx context.Context, tx port.Tx, realmID string, t Target, category, ref string) (port.Suspension, bool, error) {
	ss, err := tx.Suspensions().ListByTarget(ctx, realmID, t.Type, t.ID)
	if err != nil {
		return port.Suspension{}, false, err
	}
	for _, x := range ss {
		if x.Category == category && x.ExternalRef == ref {
			return x, true, nil
		}
	}
	return port.Suspension{}, false, nil
}

// LiftSuspension は停止を解除する。既に解除・終了していれば何もせずそのまま返す。予約した境界のイベントは取り消す。
// reason は解除の理由（監査ログに出す）。本人が自分の停止を解除できないことと、種別ごとの権限は呼び出し側で確かめる（4.7、4.11）。
func (s *Service) LiftSuspension(ctx context.Context, tx port.Tx, realmID string, sp port.Suspension, reason string, actor audit.Actor, requestID string) (port.Suspension, error) {
	if !validReason(reason) {
		return port.Suspension{}, ErrReason
	}
	now := s.Clock.Now()
	if sp.LiftedAt != nil || (sp.EndsAt != nil && !sp.EndsAt.After(now)) {
		return sp, nil
	}
	if err := tx.Suspensions().Lift(ctx, realmID, sp.ID, now, actor.ID); err != nil {
		return port.Suspension{}, err
	}
	if err := tx.ScheduledEvents().CancelByRef(ctx, realmID, sp.PublicID); err != nil {
		return port.Suspension{}, err
	}
	sp.LiftedAt, sp.LiftedBy = &now, actor.ID
	details := map[string]any{"suspension_id": sp.PublicID, "category": sp.Category, "reason": reason}
	publicID, err := TargetPublicID(ctx, tx, realmID, sp)
	if err != nil {
		return port.Suspension{}, err
	}
	details[string(sp.TargetType)+"_id"] = publicID
	return sp, s.record(ctx, tx, realmID, string(sp.TargetType)+".suspension_lifted", actor, requestID, details)
}

// TargetPublicID は停止の対象の公開 ID を返す。
func TargetPublicID(ctx context.Context, tx port.Tx, realmID string, sp port.Suspension) (string, error) {
	switch sp.TargetType {
	case port.SuspensionTargetUser:
		u, err := tx.Users().Get(ctx, realmID, sp.TargetID)
		return u.PublicID, err
	case port.SuspensionTargetOrg:
		o, err := tx.Orgs().Get(ctx, realmID, sp.TargetID)
		return o.PublicID, err
	case port.SuspensionTargetMembership:
		m, err := tx.Memberships().Get(ctx, realmID, sp.TargetID)
		return m.PublicID, err
	case port.SuspensionTargetServiceAccount:
		// サービスアカウントの ID は外部 ID（ADR 0045）。
		return sp.TargetID, nil
	}
	return "", errs.New(errs.KindInternal, "unknown suspension target %q", sp.TargetType)
}

// SetValidity はユーザーの有効期間を置き換える（nil は制限なし。4.8）。境界のイベントを予約し直す。
// 呼び出し側は確定の後に session.Manager.Forget で検証結果のキャッシュを消す。
func (s *Service) SetValidity(ctx context.Context, tx port.Tx, realmID string, u port.User, from, until *time.Time, actor audit.Actor, requestID string) (port.User, error) {
	if err := ValidPeriod(from, until); err != nil {
		return port.User{}, err
	}
	now := s.Clock.Now()
	if err := tx.Users().SetValidity(ctx, realmID, u.ID, from, until, now); err != nil {
		return port.User{}, err
	}
	u.ValidFrom, u.ValidUntil, u.UpdatedAt = from, until, now
	return u, s.ValidityChanged(ctx, tx, realmID, UserTarget(u), from, until, actor, requestID)
}

// ValidPeriod は有効期間の終わりが始まりより後であることを確かめる。
func ValidPeriod(from, until *time.Time) error {
	if from != nil && until != nil && !until.After(*from) {
		return ErrInvalidPeriod
	}
	return nil
}

// ValidityChanged は対象の有効期間を置き換えたことを監査ログに残し、境界のイベント（<対象>.validity_started・
// _ended）を予約し直す（4.8）。有効期間の保存は呼び出し側が同じトランザクションで行う。
func (s *Service) ValidityChanged(ctx context.Context, tx port.Tx, realmID string, t Target, from, until *time.Time, actor audit.Actor, requestID string) error {
	now := s.Clock.Now()
	ref := "validity:" + t.PublicID
	if err := tx.ScheduledEvents().CancelByRef(ctx, realmID, ref); err != nil {
		return err
	}
	key := t.label() + "_id"
	boundary := map[string]any{key: t.PublicID}
	details := map[string]any{key: t.PublicID, "valid_from": nil, "valid_until": nil}
	if from != nil {
		details["valid_from"] = from.UTC().Format(time.RFC3339Nano)
		if from.After(now) {
			if err := eventlog.Schedule(ctx, tx, s.Clock, realmID, ref, t.label()+".validity_started", *from, boundary); err != nil {
				return err
			}
		}
	}
	if until != nil {
		details["valid_until"] = until.UTC().Format(time.RFC3339Nano)
		if until.After(now) {
			if err := eventlog.Schedule(ctx, tx, s.Clock, realmID, ref, t.label()+".validity_ended", *until, boundary); err != nil {
				return err
			}
		}
	}
	return s.record(ctx, tx, realmID, t.label()+".validity_changed", actor, requestID, details)
}
