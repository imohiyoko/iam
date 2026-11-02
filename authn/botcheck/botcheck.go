// Package botcheck はログインの入口でのボットの確認（フィーチャー bot_protection。ADR 0105）。
//
// 確かめるのは port.BotVerifier（CAPTCHA・Turnstile などの siteverify）。mode が always ならいつも、suspicious なら接続元
// （IPv6 は /64）の window の内のログインの失敗が after_failures 回以上のときだけ求める。検証の障害でも通さない（fail-closed）。
package botcheck

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Feature はボット対策（既定オフ）。
var Feature = feature.Feature{Name: feature.BotProtection, DataVersion: 1}

// Mode は確認を求める場合。
type Mode string

const (
	ModeAlways     Mode = "always"
	ModeSuspicious Mode = "suspicious"
)

// Header はトークンを受けるリクエストのヘッダー。
const Header = "IAM-Bot-Token"

// maxTokenBytes はトークンの長さの上限（siteverify のトークンは 2KB 程度まで）。
const maxTokenBytes = 4096

// ErrRequired は確認が要り、トークンが無いか通らなかったこと（403 bot_check_required）。
var ErrRequired = errors.New("bot check required")

// Guard は確認を求めるかを決め、トークンを確かめる。nil なら何もしない（フィーチャーが動いていない）。
type Guard struct {
	Verifier      port.BotVerifier
	Cache         port.EphemeralStore
	Clock         clock.Clock
	Mode          Mode
	AfterFailures int
	Window        time.Duration
	Log           *slog.Logger
}

func failuresKey(realmID, ip string, win int64) string {
	return "botcheck:v1:" + realmID + ":" + ratelimit.Bucket(ip) + ":" + strconv.FormatInt(win, 10)
}

func (g *Guard) window(now time.Time) int64 { return now.UnixNano() / int64(g.Window) }

// Required は接続元 ip に確認を求めるか。
func (g *Guard) Required(ctx context.Context, realmID, ip string) (bool, error) {
	if g == nil {
		return false, nil
	}
	if g.Mode == ModeAlways {
		return true, nil
	}
	if g.Window <= 0 || g.AfterFailures <= 0 {
		return false, nil
	}
	b, ok, err := g.Cache.Get(ctx, failuresKey(realmID, ip, g.window(g.Clock.Now())))
	if err != nil || !ok {
		return false, err
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return true, nil // 読めない値は疑わしいとする（fail-closed）
	}
	return n >= g.AfterFailures, nil
}

// Check は確認が要れば token を確かめる。要るのに無い・通らない・確かめられなければ ErrRequired。
func (g *Guard) Check(ctx context.Context, realmID, ip, token string) error {
	need, err := g.Required(ctx, realmID, ip)
	if err != nil {
		return err
	}
	if !need {
		return nil
	}
	if token == "" || len(token) > maxTokenBytes {
		return ErrRequired
	}
	if err := g.Verifier.Verify(ctx, token, ip); err != nil {
		if !errors.Is(err, port.ErrBotRejected) {
			g.logger().WarnContext(ctx, "bot check unavailable", "error", err)
		}
		return ErrRequired
	}
	return nil
}

// Failed は接続元のログインの失敗を数える（mode が suspicious のとき）。
func (g *Guard) Failed(ctx context.Context, realmID, ip string) error {
	if g == nil || g.Mode != ModeSuspicious || g.Window <= 0 {
		return nil
	}
	now := g.Clock.Now()
	win := g.window(now)
	end := time.Unix(0, (win+1)*int64(g.Window))
	_, err := g.Cache.Incr(ctx, failuresKey(realmID, ip, win), end.Sub(now)+time.Second)
	return err
}

func (g *Guard) logger() *slog.Logger {
	if g.Log == nil {
		return slog.Default()
	}
	return g.Log
}
