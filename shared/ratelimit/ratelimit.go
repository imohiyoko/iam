// Package ratelimit は EphemeralStore のカウンタによるレートリミット（固定窓）を行う（design.md 4.1）。
//
// 複数インスタンスでは共有できる EphemeralStore（redis など）が要る。memory のままでは
// インスタンスごとに数える（server.multi_instance の検査で防ぐ）。
package ratelimit

import (
	"context"
	"fmt"
	"net"
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
	// Total は AllowFrom で、接続元を問わない上限（0 以下なら無い）。
	Total int64
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
	if l == nil {
		return nil
	}
	return l.allow(ctx, key, l.Limit)
}

// AllowFrom は key を接続元 ip（Bucket でまとめる）ごとに Limit 回まで、接続元を問わず Total 回まで許す。アカウントの
// 上限を第三者が使い切って、本人を締め出すのを難しくする（本人の接続元の分は残る）。ip が空なら接続元を問わず Limit 回。
func (l *Limiter) AllowFrom(ctx context.Context, key, ip string) error {
	if l == nil {
		return nil
	}
	if ip == "" {
		return l.allow(ctx, key, l.Limit)
	}
	if err := l.allow(ctx, key+":from:"+Bucket(ip), l.Limit); err != nil {
		return err
	}
	return l.allow(ctx, key, l.Total)
}

// Bucket は接続元を数える単位。IPv6 は利用者が /64 を自由に使えるため、/64 でまとめる。
func Bucket(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (l *Limiter) allow(ctx context.Context, key string, limit int64) error {
	if limit <= 0 || l.Window <= 0 {
		return nil
	}
	now := l.Clock.Now()
	win := now.UnixNano() / int64(l.Window)
	end := time.Unix(0, (win+1)*int64(l.Window))
	n, err := l.Cache.Incr(ctx, "rl:v1:"+key+":"+strconv.FormatInt(win, 10), end.Sub(now)+time.Second)
	if err != nil {
		return err
	}
	if n > limit {
		return &ExceededError{RetryAfter: end.Sub(now), First: n == limit+1}
	}
	return nil
}
