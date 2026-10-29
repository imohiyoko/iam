package hook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// maxResponse はフックの応答の上限（バイト）。
const maxResponse = 64 << 10

// Webhook はフックを HTTPS の POST で呼ぶ（port.FlowHook）。本文は HookInput の JSON、応答は 200 と HookResult の JSON。
//
// 署名：X-IAM-Signature: t=<UNIX 秒>,v1=<hex(HMAC-SHA-256(secret, "<t>." + body))>（通知の Webhook と同じ形）。
// 受け取る側は時刻のずれ（5 分など）と署名を確かめる。
type Webhook struct {
	URL    string
	Secret []byte
	Client *http.Client // nil なら転送に従わない既定のクライアント
	Clock  clock.Clock
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// Call は Webhook を呼ぶ。2xx 以外・本文の誤りは誤りとして返す（fail-open / closed は Runner が決める）。
func (w *Webhook) Call(ctx context.Context, in port.HookInput) (port.HookResult, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return port.HookResult{}, err
	}
	clk := w.Clock
	if clk == nil {
		clk = clock.System{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return port.HookResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAM-Signature", sign(w.Secret, body, clk.Now()))
	req.Header.Set("X-IAM-Hook", in.Hook)
	c := w.Client
	if c == nil {
		c = noRedirect
	}
	resp, err := c.Do(req) // #nosec G704 -- 運営者が設定した宛先
	if err != nil {
		return port.HookResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return port.HookResult{}, fmt.Errorf("hook %s: status %d", in.Hook, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return port.HookResult{}, err
	}
	if len(b) > maxResponse {
		return port.HookResult{}, fmt.Errorf("hook %s: response too large", in.Hook)
	}
	var out port.HookResult
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return port.HookResult{}, fmt.Errorf("hook %s: %w", in.Hook, err)
	}
	return out, nil
}
