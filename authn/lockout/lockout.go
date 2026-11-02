// Package lockout はアカウント単位のロックアウト（フィーチャー account_lockout。ADR 0105）。
//
// 推測で当てられる照合（パスワード・2要素目のコード）の失敗を、接続元を問わずに対象（メールアドレスのブラインドインデックスか
// ユーザー）ごとに数える。delay_after 回目の失敗から次の試行までの待ち時間をかけ（倍々）、window の内に threshold 回失敗すれば
// ロックする（続けてロックされるたびに倍々）。待ち時間とロックの間は照合をせずに *ratelimit.ExceededError を返す（レートリミット
// と同じ 429。区別させない）。状態は EphemeralStore に置く。
package lockout

import (
	"context"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Feature はアカウント単位のロックアウト（既定オフ）。
var Feature = feature.Feature{Name: feature.AccountLockout, DataVersion: 1}

// 数える照合の種類（監査ログの scope）。
const (
	// ScopePassword はパスワードのログイン。対象はメールアドレスのブラインドインデックス（無いアドレスも同じに数える）。
	ScopePassword = "password"
	// ScopeSecondFactor は 2 要素目のコード（TOTP と汎用の認証方式）。対象はユーザーの内部 ID。
	ScopeSecondFactor = "second_factor"
)

// Config はロックアウトの設定。
type Config struct {
	// Threshold は Window の内にロックする失敗の回数。
	Threshold int
	Window    time.Duration
	// LockDuration は最初のロックの長さ。続けてロックされるたびに倍にし、MaxLockDuration で止める。ロックの回数は
	// 最後のロックが明けてから MaxLockDuration の間覚えておく。
	LockDuration, MaxLockDuration time.Duration
	// DelayAfter は待ち時間をかけ始める失敗の回数（0 なら待ち時間なし）。BaseDelay から倍々で MaxDelay まで。
	DelayAfter          int
	BaseDelay, MaxDelay time.Duration
}

// Guard は失敗を数え、待ち時間とロックをかける。nil なら何もしない（フィーチャーが動いていない）。
type Guard struct {
	Cache  port.EphemeralStore
	Clock  clock.Clock
	Config Config
}

// Lock は Failed がかけたロック。
type Lock struct {
	Until time.Time
	// Level は続けてロックされた回数（1 から）。
	Level int
}

// Status は対象の今の状態（運営者の API）。
type Status struct {
	Failures    int
	Level       int
	LockedUntil *time.Time
	WaitUntil   *time.Time
}

// Locked はロックか待ち時間の間か。
func (s Status) Locked() bool { return s.LockedUntil != nil || s.WaitUntil != nil }

func key(realmID, scope, subject, kind string) string {
	return "lockout:v1:" + realmID + ":" + scope + ":" + subject + ":" + kind
}

const (
	kindFailures = "f"
	kindWait     = "w"
	kindLock     = "l"
	kindLevel    = "n"
)

// until は時刻を置いたキーを読む。過ぎていれば ok=false。
func (g *Guard) until(ctx context.Context, k string, now time.Time) (time.Time, bool, error) {
	b, ok, err := g.Cache.Get(ctx, k)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		// 読めない値は、いちばん長いロックとして扱う（fail-closed。キーは期限で消える）。
		return now.Add(g.Config.MaxLockDuration), true, nil
	}
	t := time.Unix(0, n)
	return t, now.Before(t), nil
}

func (g *Guard) setUntil(ctx context.Context, k string, until, now time.Time) error {
	return g.Cache.Set(ctx, k, strconv.AppendInt(nil, until.UnixNano(), 10), until.Sub(now)+time.Second)
}

func exceeded(until, now time.Time) error {
	// Retry-After は秒で返すので切り上げる。
	d := until.Sub(now)
	if r := d % time.Second; r != 0 {
		d += time.Second - r
	}
	return &ratelimit.ExceededError{RetryAfter: d}
}

// Check は対象がロックか待ち時間の間なら *ratelimit.ExceededError を返す。照合の前に呼ぶ。
func (g *Guard) Check(ctx context.Context, realmID, scope, subject string) error {
	if g == nil {
		return nil
	}
	now := g.Clock.Now()
	for _, kind := range []string{kindLock, kindWait} {
		t, ok, err := g.until(ctx, key(realmID, scope, subject, kind), now)
		if err != nil {
			return err
		}
		if ok {
			return exceeded(t, now)
		}
	}
	return nil
}

// doubled は base を n 回倍にし、limit で止める。
func doubled(base, limit time.Duration, n int) time.Duration {
	d := base
	for i := 0; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// Failed は照合の失敗を数える。この失敗でロックしたなら Lock を返す。
func (g *Guard) Failed(ctx context.Context, realmID, scope, subject string) (*Lock, error) {
	if g == nil || g.Config.Threshold <= 0 || g.Config.Window <= 0 {
		return nil, nil
	}
	now, c := g.Clock.Now(), g.Config
	n, err := g.Cache.Incr(ctx, key(realmID, scope, subject, kindFailures), c.Window)
	if err != nil {
		return nil, err
	}
	if n >= int64(c.Threshold) {
		lvl, err := g.Cache.Incr(ctx, key(realmID, scope, subject, kindLevel), max(c.MaxLockDuration, c.LockDuration))
		if err != nil {
			return nil, err
		}
		level := int(min(lvl, 64))
		until := now.Add(doubled(c.LockDuration, max(c.MaxLockDuration, c.LockDuration), level-1))
		if err := g.setUntil(ctx, key(realmID, scope, subject, kindLock), until, now); err != nil {
			return nil, err
		}
		// ロックの回数は、このロックが明けてから max_lock_duration の間覚えておく。
		if err := g.Cache.Set(ctx, key(realmID, scope, subject, kindLevel), strconv.AppendInt(nil, lvl, 10),
			until.Sub(now)+max(c.MaxLockDuration, c.LockDuration)); err != nil {
			return nil, err
		}
		// 数え直す（ロックが明けたら threshold 回まで試せる。待ち時間は消す）。
		for _, kind := range []string{kindFailures, kindWait} {
			if err := g.Cache.Delete(ctx, key(realmID, scope, subject, kind)); err != nil {
				return nil, err
			}
		}
		return &Lock{Until: until, Level: level}, nil
	}
	if c.DelayAfter > 0 && n >= int64(c.DelayAfter) && c.BaseDelay > 0 {
		d := doubled(c.BaseDelay, max(c.MaxDelay, c.BaseDelay), int(min(n-int64(c.DelayAfter), 64)))
		if err := g.setUntil(ctx, key(realmID, scope, subject, kindWait), now.Add(d), now); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Succeeded は照合が通ったときに、失敗の回数と待ち時間を消す（ロックの回数は残す）。
func (g *Guard) Succeeded(ctx context.Context, realmID, scope, subject string) error {
	if g == nil {
		return nil
	}
	for _, kind := range []string{kindFailures, kindWait} {
		if err := g.Cache.Delete(ctx, key(realmID, scope, subject, kind)); err != nil {
			return err
		}
	}
	return nil
}

// Status は対象の今の状態を返す。
func (g *Guard) Status(ctx context.Context, realmID, scope, subject string) (Status, error) {
	var st Status
	if g == nil {
		return st, nil
	}
	now := g.Clock.Now()
	for kind, dst := range map[string]**time.Time{kindLock: &st.LockedUntil, kindWait: &st.WaitUntil} {
		t, ok, err := g.until(ctx, key(realmID, scope, subject, kind), now)
		if err != nil {
			return st, err
		}
		if ok {
			*dst = &t
		}
	}
	for kind, dst := range map[string]*int{kindFailures: &st.Failures, kindLevel: &st.Level} {
		b, ok, err := g.Cache.Get(ctx, key(realmID, scope, subject, kind))
		if err != nil {
			return st, err
		}
		if ok {
			n, _ := strconv.Atoi(string(b))
			*dst = n
		}
	}
	return st, nil
}

// Unlock はロック・待ち時間・失敗の回数・ロックの回数を消す（運営者の API）。消す前の状態を返す。
func (g *Guard) Unlock(ctx context.Context, realmID, scope, subject string) (Status, error) {
	st, err := g.Status(ctx, realmID, scope, subject)
	if err != nil || g == nil {
		return st, err
	}
	for _, kind := range []string{kindLock, kindWait, kindFailures, kindLevel} {
		if err := g.Cache.Delete(ctx, key(realmID, scope, subject, kind)); err != nil {
			return st, err
		}
	}
	return st, nil
}

// 監査ログの種類。
const (
	EventLocked   = "account.locked"
	EventUnlocked = "account.unlocked"
)

// RecordLocked はロックを監査ログに残す（アカウントがあるときだけ呼ぶ）。
func RecordLocked(ctx context.Context, tx port.Tx, clk clock.Clock, realmID, userPublicID, scope string, l *Lock, ip, userAgent, requestID string) error {
	_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: EventLocked, Result: audit.ResultSuccess, RealmID: realmID,
		Actor: audit.Actor{Type: "system"}, IP: ip, UserAgent: userAgent, RequestID: requestID,
		Details: map[string]any{"user_id": userPublicID, "scope": scope, "until": l.Until.UTC().Format(time.RFC3339), "level": l.Level}})
	return err
}
