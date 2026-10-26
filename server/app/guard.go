package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// loginPrefix はログインの要求のパス。本人確認の前の応答を返しうる。
const loginPrefix = "/v1/login/"

// withLoginGuard はログインの要求に、応答時間の下限と接続元ごとの回数の上限をかける（design.md 4.9、4.1）。
//
// 応答時間の下限：応答を手元に溜め、要求を受けてから下限の時間が経つまで送らない。本人確認の前の
// 処理（アカウントの有無、照合の失敗の段階）による時間の差を、下限の内側に隠す。
func (a *App) withLoginGuard(h http.Handler) http.Handler {
	floor := a.cfg.Security.Login.MinResponseTime.D()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, loginPrefix) {
			h.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		bw := &bufferedWriter{w: w}
		a.limitIP(bw, r, h)
		if wait := floor - time.Since(start); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-r.Context().Done():
				t.Stop()
			}
		}
		bw.flush()
	})
}

func (a *App) limitIP(w http.ResponseWriter, r *http.Request, h http.Handler) {
	c, _ := r.Context().Value(clientKey{}).(client)
	err := a.perIP.Allow(r.Context(), "ip:"+a.realm.ID+":"+ipBucket(c.IP))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		if ex.First {
			a.recordRateLimit(r.Context(), "ip", r.URL.Path)
		}
		writeRateLimited(w, ex)
		return
	}
	if err != nil {
		a.responseError(w, r, err)
		return
	}
	h.ServeHTTP(w, r)
}

// ipBucket は回数を数える単位。IPv6 は利用者が /64 を自由に使えるため、/64 でまとめる。
func ipBucket(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// recordRateLimit は発動を監査ログに残す（窓ごとに1回。6.1）。
func (a *App) recordRateLimit(ctx context.Context, scope, endpoint string) {
	c, _ := ctx.Value(clientKey{}).(client)
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "rate_limit.triggered", Result: audit.ResultFailure, RealmID: a.realm.ID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: requestID(ctx),
			Details: map[string]any{"scope": scope, "endpoint": endpoint},
		})
		return err
	})
	if err != nil {
		a.deps.Logger.WarnContext(ctx, "could not record rate limit", "error", err)
	}
}

func retryAfter(ex *ratelimit.ExceededError) int {
	return max(int((ex.RetryAfter+time.Second-1)/time.Second), 1)
}

func writeRateLimited(w http.ResponseWriter, ex *ratelimit.ExceededError) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter(ex)))
	writeError(w, http.StatusTooManyRequests, codeRateLimited)
}

const codeRateLimited = "rate_limited"

func rateLimited(ex *ratelimit.ExceededError) publicapi.RateLimitedJSONResponse {
	return publicapi.RateLimitedJSONResponse{Body: publicapi.Error{Error: codeRateLimited},
		Headers: publicapi.RateLimitedResponseHeaders{RetryAfter: retryAfter(ex)}}
}

// denied は本人確認の後の拒否（警告、停止など）の応答。理由を返す（4.9）。
func denied(d errs.Denial) publicapi.DeniedJSONResponse {
	reasons := d.Reasons()
	return publicapi.DeniedJSONResponse{Error: reasons[0], Reasons: &reasons}
}

// warningsOut は本人に返す警告。
func warningsOut(ws []warning.Warning) []publicapi.Warning {
	out := make([]publicapi.Warning, 0, len(ws))
	for _, w := range ws {
		pw := publicapi.Warning{Code: w.Code, Severity: publicapi.WarningSeverity(w.Severity), Action: publicapi.WarningAction(w.Action)}
		if w.Params != nil {
			pw.Params = &w.Params
		}
		out = append(out, pw)
	}
	return out
}

// bufferedWriter は応答を溜め、flush で送る。ヘッダーは元の ResponseWriter のものを使う
// （ハンドラが context 経由で Cookie を足すため）。
type bufferedWriter struct {
	w      http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header { return b.w.Header() }

func (b *bufferedWriter) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *bufferedWriter) flush() {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	b.w.WriteHeader(b.status)
	_, _ = b.w.Write(b.body.Bytes())
}
