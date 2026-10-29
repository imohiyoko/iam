// Package webhook は監査イベントを HTTP の POST で送る EventSink のアダプタ（design.md 6.3、ADR 0071）。
//
// 項目：
//   - url：送り先。必須。開発ビルドと localhost のほかは https
//   - secret_env：署名の鍵を持つ環境変数の名前。あれば X-IAM-Signature に t=<unix 秒>,v1=<HMAC-SHA-256(鍵, "<t>.<本文>") の16進> を付ける
//   - sinkfmt.Options（format、pii、pseudonym_key_env）
//
// 本文は {"events": [...]}。2xx 以外は失敗で、次の送出でまた送る（受け取る側はイベント ID で重複を除く）。
package webhook

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
	"os"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

// SignatureHeader は署名のヘッダー。
const SignatureHeader = "X-IAM-Signature"

const (
	timeout          = 10 * time.Second
	maxResponseBytes = 1 << 16
)

func init() {
	plugin.RegisterEventSink("webhook", func(_ context.Context, cfg plugin.Config) (port.EventSink, error) {
		if err := cfg.CheckOptions(append([]string{"url", "secret_env"}, sinkfmt.Options...)...); err != nil {
			return nil, err
		}
		enc, err := sinkfmt.New(cfg)
		if err != nil {
			return nil, err
		}
		u, err := sinkfmt.CheckURL(cfg, cfg.Option("url", ""))
		if err != nil {
			return nil, fmt.Errorf("eventsink webhook: url: %w", err)
		}
		s := &Sink{URL: u, enc: enc}
		if name := cfg.Option("secret_env", ""); name != "" {
			if s.Secret = []byte(os.Getenv(name)); len(s.Secret) < 32 {
				return nil, fmt.Errorf("eventsink webhook: %s must hold a secret of at least 32 bytes", name)
			}
		}
		return s, nil
	})
}

// Sink は URL に POST する。
type Sink struct {
	URL    string
	Secret []byte
	HTTP   *http.Client
	Now    func() time.Time
	enc    *sinkfmt.Encoder
}

// NewSink は送り先と Encoder から Sink を作る（テスト用）。
func NewSink(url string, secret []byte, enc *sinkfmt.Encoder) *Sink {
	return &Sink{URL: url, Secret: secret, enc: enc}
}

// Sign は署名のヘッダーの値を返す。
func Sign(secret []byte, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// Emit はまとめて1回の要求で送る。
func (s *Sink) Emit(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	vs := make([]json.RawMessage, 0, len(events))
	for _, e := range events {
		v, err := s.enc.Value(e)
		if err != nil {
			return err
		}
		vs = append(vs, v)
	}
	body, err := json.Marshal(map[string]any{"events": vs})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(s.Secret) > 0 {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		req.Header.Set(SignatureHeader, Sign(s.Secret, now(), body))
	}
	resp, err := sinkfmt.Client(s.HTTP).Do(req) // #nosec G704 -- 送り先は運営者が設定した url
	if err != nil {
		return fmt.Errorf("eventsink webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("eventsink webhook: status %d", resp.StatusCode)
	}
	return nil
}
