package account

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/port"
)

// CodeOutsideValidity は有効期間の外の拒否理由（4.9）。
const CodeOutsideValidity = "outside_validity"

// SuspendedCode は停止の拒否理由のコード（`suspended.<category>`）。
func SuspendedCode(category string) string { return "suspended." + category }

// RecoveryIgnores は復旧（4.12）で見ない停止の種別。security_risk で止められた本人は、復旧で認証手段を入れ替える。
var RecoveryIgnores = []string{CategorySecurityRisk}

// ErrInactive は削除・統合済みのユーザー。理由は返さない（本人の状態ではなく、もう本人がいない）。
var ErrInactive = errors.New("account: user is not active")

// UnavailableError はユーザーが有効期間の外か停止中であること。本人確認の後なので理由のコードを返す（4.9）。
// reason（内部向けの理由）は含めない。
type UnavailableError struct {
	Codes []string
}

func (e *UnavailableError) Error() string {
	return "account unavailable: " + strings.Join(e.Codes, ",")
}

// Reasons は拒否理由のコード。
func (e *UnavailableError) Reasons() []string { return append([]string(nil), e.Codes...) }

// Check はユーザーが now に使えるかを時刻から計算する（4.7、4.8）。削除・統合済みなら ErrInactive、有効期間の外か
// 停止中なら *UnavailableError を返す。since は判定の始まりで、[since, now] に重なる停止も停止中とみなす。
// セッションの検証では認証の時刻を渡し、停止の後に解除しても、停止をまたいだセッションは戻らない（ログインは now を渡す）。
// ignore の種別の停止は見ない（復旧専用のセッション。RecoveryIgnores）。
// next は now より後で可否が次に変わりうる最も早い時刻（予約した停止の開始、有効期間の終わり）で、無ければ nil。
func Check(ctx context.Context, tx port.Tx, u port.User, since, now time.Time, ignore ...string) (*time.Time, error) {
	if u.Status != port.UserActive {
		return nil, ErrInactive
	}
	return CheckWindow(ctx, tx, u.RealmID, port.SuspensionTargetUser, u.ID, u.ValidFrom, u.ValidUntil, since, now, ignore...)
}

// CheckWindow は対象（ユーザー・Org・Membership）の有効期間と停止を、Check と同じ規則で時刻から計算する。
// 有効期間の外か停止中なら *UnavailableError を返す。
func CheckWindow(ctx context.Context, tx port.Tx, realmID string, t port.SuspensionTarget, targetID string, from, until *time.Time, since, now time.Time, ignore ...string) (*time.Time, error) {
	var codes []string
	var next *time.Time
	if (from != nil && now.Before(*from)) || (until != nil && !now.Before(*until)) {
		codes = append(codes, CodeOutsideValidity)
	} else if until != nil {
		next = earliest(next, *until)
	}
	ss, err := tx.Suspensions().ListByTarget(ctx, realmID, t, targetID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if slices.Contains(ignore, s.Category) {
			continue
		}
		end := s.EndsAt
		if s.LiftedAt != nil && (end == nil || s.LiftedAt.Before(*end)) {
			end = s.LiftedAt
		}
		if end != nil && !end.After(since) {
			continue // since より前に終わった
		}
		if s.StartsAt.After(now) {
			if end == nil || end.After(s.StartsAt) {
				next = earliest(next, s.StartsAt) // 予約
			}
			continue
		}
		if end != nil && !end.After(s.StartsAt) {
			continue // 始まる前に解除された
		}
		if c := SuspendedCode(s.Category); !seen[c] {
			seen[c] = true
			codes = append(codes, c)
		}
	}
	if len(codes) > 0 {
		slices.Sort(codes)
		return nil, &UnavailableError{Codes: codes}
	}
	return next, nil
}

func earliest(a *time.Time, b time.Time) *time.Time {
	if a == nil || b.Before(*a) {
		return &b
	}
	return a
}
