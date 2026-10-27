// Package sinkfmt は EventSink のアダプタが共通に使う、出力の形式と個人情報の出し方（design.md 6.3、ADR 0071）。
//
// 形式は独自の JSON（iam。audit.Event の形）か OCSF。個人情報（監査ログに残す切り詰めた IP と User-Agent の大分類）は
// 出力先ごとに、そのまま（raw）・仮名化（pseudonymize。鍵があれば既定）・出さない（omit）を選ぶ。全文の暗号文（client）はどれでも出さない。
// 仮名化は鍵つきの HMAC で、同じ鍵の間は同じ値が同じ仮名になる（相関はできるが、元の値には戻せない）。
package sinkfmt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
)

// 形式。
const (
	FormatIAM  = "iam"
	FormatOCSF = "ocsf"
)

// 個人情報の出し方。
const (
	PIIRaw          = "raw"
	PIIPseudonymize = "pseudonymize"
	PIIOmit         = "omit"
)

// Options はすべての EventSink のアダプタが受け付ける項目。
var Options = []string{"format", "pii", "pseudonym_key_env"}

// Encoder はイベントを出力の形にする。
type Encoder struct {
	Format string
	PII    string
	key    []byte
}

// New は cfg の format・pii・pseudonym_key_env から Encoder を作る。pii を省けば、仮名化の鍵（pseudonym_key_env）があれば
// 仮名化、無ければ出さない。pseudonymize を指定して鍵が無ければエラー。鍵は 32 バイト以上で、16進か base64。
func New(cfg plugin.Config) (*Encoder, error) {
	keyEnv := cfg.Option("pseudonym_key_env", "")
	def := PIIOmit
	if keyEnv != "" {
		def = PIIPseudonymize
	}
	e := &Encoder{Format: cfg.Option("format", FormatIAM), PII: cfg.Option("pii", def)}
	switch e.Format {
	case FormatIAM, FormatOCSF:
	default:
		return nil, fmt.Errorf("eventsink: unknown format %q (known: iam, ocsf)", e.Format)
	}
	switch e.PII {
	case PIIRaw, PIIOmit:
	case PIIPseudonymize:
		if keyEnv == "" {
			return nil, fmt.Errorf("eventsink: pii pseudonymize needs pseudonym_key_env")
		}
		key, err := decodeKey(os.Getenv(keyEnv))
		if err != nil {
			return nil, fmt.Errorf("eventsink: pseudonym key in %s: %w", keyEnv, err)
		}
		e.key = key
	default:
		return nil, fmt.Errorf("eventsink: unknown pii %q (known: raw, pseudonymize, omit)", e.PII)
	}
	return e, nil
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		if b, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("not hex or base64")
		}
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("must be at least 32 bytes")
	}
	return b, nil
}

// Pseudonym は v の仮名（"p_" + HMAC-SHA-256 の先頭 16 バイトの16進）。空なら空。
func (e *Encoder) Pseudonym(v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, e.key)
	m.Write([]byte(v))
	return "p_" + hex.EncodeToString(m.Sum(nil)[:16])
}

// Redact は個人情報の出し方に従ったイベントを返す。全文の暗号文（client）は常に外す。
func (e *Encoder) Redact(ev audit.Event) audit.Event {
	ev.Client = ""
	switch e.PII {
	case PIIRaw:
	case PIIPseudonymize:
		ev.IP = e.Pseudonym(ev.IP)
	default:
		ev.IP, ev.UserAgent = "", ""
	}
	return ev
}

// Encode はイベントを1件の JSON にする。
func (e *Encoder) Encode(ev audit.Event) ([]byte, error) {
	ev = e.Redact(ev)
	if e.Format == FormatOCSF {
		return json.Marshal(OCSF(ev))
	}
	return json.Marshal(ev)
}

// Value はイベントを JSON の値（map）にする。配列にまとめて送るアダプタ用。
func (e *Encoder) Value(ev audit.Event) (json.RawMessage, error) {
	b, err := e.Encode(ev)
	return json.RawMessage(b), err
}

// CheckURL は送り先の URL を確かめる。開発ビルドと localhost（127.0.0.1、::1）のほかは https に限る。
func CheckURL(cfg plugin.Config, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return "", fmt.Errorf("invalid URL")
	}
	if u.Scheme == "http" && !cfg.Dev {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return "", fmt.Errorf("must be https")
		}
	}
	return u.String(), nil
}

// Client は c（nil なら10秒で打ち切り、転送を追わないクライアント）を返す。
func Client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
