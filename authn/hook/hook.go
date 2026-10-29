// Package hook はフロー フックを呼ぶ（design.md 11.8、ADR 0081）。
//
// フックは Go のインターフェース（port.FlowHook）か Webhook で実装する。呼び出しにはタイムアウトを付け、失敗（タイムアウト・
// 誤った応答）のときに止めるか（fail-closed）通すか（fail-open）をフックごとに決める。判定のホットパス（セッションの検証、
// 認可の判定）には置かない。
package hook

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー flow_hooks の宣言（features/flowhooks が登録する）。
var Feature = feature.Feature{Name: feature.FlowHooks, DataVersion: 1}

// 既定と上限。
const (
	DefaultTimeout = 2 * time.Second
	MaxTimeout     = 5 * time.Second
)

// DeniedError はフックが止めたこと（本人確認の後の拒否として、理由のコード `hook_denied.<hook>` を返す。4.9）。
// フックの理由（Reason）は含めない。
type DeniedError struct {
	Hook string
}

func (e *DeniedError) Error() string { return "hook denied: " + e.Hook }

// Reasons は拒否理由のコード。
func (e *DeniedError) Reasons() []string { return []string{"hook_denied." + e.Hook} }

// Entry は1つのフック。
type Entry struct {
	Hook     port.FlowHook
	Timeout  time.Duration // 0 なら DefaultTimeout
	FailOpen bool
}

// Runner は設定したフックを呼ぶ。nil か、設定の無いフックは通す。
type Runner struct {
	Entries map[string]Entry
	// Realm は HookInput.Realm に入れる realm の slug。
	Realm string
	Log   *slog.Logger
}

// Has はフックが設定されているかを返す。
func (r *Runner) Has(hook string) bool {
	if r == nil {
		return false
	}
	_, ok := r.Entries[hook]
	return ok
}

// Run はフックを呼ぶ。止められたら *DeniedError（失敗して fail-closed のときも）。設定が無ければ通す。
func (r *Runner) Run(ctx context.Context, in port.HookInput) (port.HookResult, error) {
	if r == nil {
		return port.HookResult{Allow: true}, nil
	}
	e, ok := r.Entries[in.Hook]
	if !ok {
		return port.HookResult{Allow: true}, nil
	}
	in.Realm = r.Realm
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// ctx に従わない実装でも期限で待つのをやめる。期限を過ぎて返った結果は使わない。
	type result struct {
		res port.HookResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.Hook.Call(cctx, in)
		done <- result{res, err}
	}()
	var res port.HookResult
	var err error
	select {
	case out := <-done:
		res, err = out.res, out.err
		if err == nil && cctx.Err() != nil {
			err = cctx.Err()
		}
	case <-cctx.Done():
		err = cctx.Err()
	}
	log := r.Log
	if log == nil {
		log = slog.Default()
	}
	if err != nil {
		// 呼び出し元の取り消し（接続の切断）は、フックの失敗ではない。
		if ctx.Err() != nil {
			return port.HookResult{}, ctx.Err()
		}
		log.Warn("flow hook failed", "hook", in.Hook, "fail_open", e.FailOpen, "timeout", errors.Is(err, context.DeadlineExceeded), "err", err)
		if e.FailOpen {
			return port.HookResult{Allow: true}, nil
		}
		return port.HookResult{}, &DeniedError{Hook: in.Hook}
	}
	if !res.Allow {
		log.Info("flow hook denied", "hook", in.Hook, "reason", res.Reason)
		return res, &DeniedError{Hook: in.Hook}
	}
	return res, nil
}
