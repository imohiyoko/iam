// Package ratelimit は EphemeralStore のカウンタによるレートリミット（固定窓）を行う（design.md 4.1）。
//
// 複数インスタンスでは共有できる EphemeralStore（redis など）が要る。memory のままでは
// インスタンスごとに数える（server.multi_instance の検査で防ぐ）。
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// Limiter は Window ごとに Limit 回まで許す。Limit が 0 以下なら制限しない。
type Limiter struct {
	Cache  port.EphemeralStore
	Clock  clock.Clock
	Window time.Duration
	Limit  int64
}

// ExceededError は上限を超えたことを表す。
type ExceededError struct {
	RetryAfter time.Duration
	// First は窓の中で初めて超えたか（監査ログに残すのは1回だけにするため）。
	First bool
}

func (e *ExceededError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s", e.RetryAfter)
}

// Allow は key の回数を1つ数え、上限を超えれば *ExceededError を返す。
// key は呼び出し側で個人情報を含まない形にする（メールアドレスならブラインドインデックス）。
func (l *Limiter) Allow(ctx context.Context, key string) error {
	if l == nil || l.Limit <= 0 || l.Window <= 0 {
		return nil
	}
	now := l.Clock.Now()
	win := now.UnixNano() / int64(l.Window)
	end := time.Unix(0, (win+1)*int64(l.Window))
	n, err := l.Cache.Incr(ctx, "rl:v1:"+key+":"+strconv.FormatInt(win, 10), end.Sub(now)+time.Second)
	if err != nil {
		return err
	}
	if n > l.Limit {
		return &ExceededError{RetryAfter: end.Sub(now), First: n == l.Limit+1}
	}
	return nil
}
