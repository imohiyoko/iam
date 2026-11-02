// Package twilio は Twilio の REST API で SMS と音声のコードを送る SMSSender（フィーチャー sms_otp。ADR 0104）。
//
// SMS は Programmable Messaging（POST /2010-04-01/Accounts/{sid}/Messages.json）、音声は Voice
// （POST …/Calls.json に TwiML の <Say> を渡す）。0031 の例外として、宛先の番号と、コードを入れた本文だけを渡す。本文は設定の
// テンプレート（{code} を必ず含む）で、IAM は利用者ごとの文面を作らない。
//
// 設定（sms_sender.options）：
//
//	account_sid           Twilio の Account SID（必須）
//	auth_token_env        Auth Token（api_key_sid があれば API Key の Secret）を持つ環境変数の名前（必須。読んだ後に消す）
//	api_key_sid           API Key の SID（任意。あれば Basic 認証のユーザー名にする）
//	from                  送信元の番号（E.164）。messaging_service_sid とどちらかが要る（音声は from が要る）
//	messaging_service_sid Messaging Service の SID（任意）
//	sms_body              SMS の本文（既定 "Your verification code is {code}"）
//	voice_text            音声で読み上げる文（既定 "Your verification code is {code}"。コードは 1 桁ずつ 2 回読む）
//	voice_language        読み上げの言語（既定 en-US）
//	base_url              API の URL（既定 https://api.twilio.com。http は開発モードだけ）
//	timeout               呼び出しのタイムアウト（既定 10 秒、30 秒以下）
package twilio

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

var (
	sidRE  = regexp.MustCompile(`^(AC|SK|MG)[0-9a-fA-F]{32}$`)
	fromRE = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	langRE = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)
)

const defaultText = "Your verification code is {code}"

func init() {
	plugin.RegisterSMSSender("twilio", func(_ context.Context, cfg plugin.Config) (port.SMSSender, error) {
		if err := cfg.CheckOptions("account_sid", "auth_token_env", "api_key_sid", "from", "messaging_service_sid", "sms_body", "voice_text",
			"voice_language", "base_url", "timeout"); err != nil {
			return nil, err
		}
		c := Config{
			AccountSID: cfg.Option("account_sid", ""), APIKeySID: cfg.Option("api_key_sid", ""), From: cfg.Option("from", ""),
			MessagingServiceSID: cfg.Option("messaging_service_sid", ""), SMSBody: cfg.Option("sms_body", defaultText),
			VoiceText: cfg.Option("voice_text", defaultText), VoiceLanguage: cfg.Option("voice_language", "en-US"),
			BaseURL: cfg.Option("base_url", "https://api.twilio.com"), Timeout: 10 * time.Second, Dev: cfg.Dev,
		}
		env := cfg.Option("auth_token_env", "")
		c.Secret = os.Getenv(env)
		if env == "" || c.Secret == "" {
			return nil, errors.New("sms_sender twilio: auth_token_env must name an environment variable holding the auth token")
		}
		_ = os.Unsetenv(env)
		if v := cfg.Option("timeout", ""); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 || d > 30*time.Second {
				return nil, fmt.Errorf("sms_sender twilio: invalid timeout %q", v)
			}
			c.Timeout = d
		}
		return New(c)
	})
}

// Config は Twilio の送信の設定。
type Config struct {
	AccountSID, APIKeySID, Secret string
	From, MessagingServiceSID     string
	SMSBody, VoiceText            string
	VoiceLanguage                 string
	BaseURL                       string
	Timeout                       time.Duration
	// Dev は開発モード（base_url に http を許す）。
	Dev bool
}

// Sender は Twilio の SMSSender。
type Sender struct {
	cfg    Config
	base   string
	client *http.Client
}

// New は設定を確かめて Sender を返す。
func New(c Config) (*Sender, error) {
	switch {
	case !sidRE.MatchString(c.AccountSID) || !strings.HasPrefix(c.AccountSID, "AC"):
		return nil, errors.New("sms_sender twilio: account_sid must be an Account SID (AC…)")
	case c.APIKeySID != "" && (!sidRE.MatchString(c.APIKeySID) || !strings.HasPrefix(c.APIKeySID, "SK")):
		return nil, errors.New("sms_sender twilio: api_key_sid must be an API Key SID (SK…)")
	case c.MessagingServiceSID != "" && (!sidRE.MatchString(c.MessagingServiceSID) || !strings.HasPrefix(c.MessagingServiceSID, "MG")):
		return nil, errors.New("sms_sender twilio: messaging_service_sid must be a Messaging Service SID (MG…)")
	case c.From != "" && !fromRE.MatchString(c.From):
		return nil, errors.New("sms_sender twilio: from must be an E.164 number")
	case c.From == "" && c.MessagingServiceSID == "":
		return nil, errors.New("sms_sender twilio: from or messaging_service_sid is required")
	case !strings.Contains(c.SMSBody, "{code}") || !strings.Contains(c.VoiceText, "{code}"):
		return nil, errors.New("sms_sender twilio: sms_body and voice_text must contain {code}")
	case len(c.SMSBody) > 300 || len(c.VoiceText) > 300:
		return nil, errors.New("sms_sender twilio: sms_body and voice_text must be at most 300 bytes")
	case !langRE.MatchString(c.VoiceLanguage):
		return nil, errors.New("sms_sender twilio: invalid voice_language")
	case c.Secret == "":
		return nil, errors.New("sms_sender twilio: the auth token is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(c.Dev && u.Scheme == "http")) {
		return nil, errors.New("sms_sender twilio: base_url must be an https URL (http only in development mode)")
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	return &Sender{cfg: c, base: strings.TrimRight(u.String(), "/"), client: &http.Client{
		Timeout: c.Timeout,
		// 転送先を検証していない宛先には送らない（資格情報を渡さない）。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

var codeRE = regexp.MustCompile(`^[0-9]{4,10}$`)

// Send は SMS か音声でコードを送る。2xx 以外はエラー（届かなかったとみなす）。応答の本文は読まない（番号を含むため）。
func (s *Sender) Send(ctx context.Context, m port.SMSMessage) error {
	if !fromRE.MatchString(m.To) || !codeRE.MatchString(m.Code) {
		return errors.New("sms_sender twilio: invalid message")
	}
	form := url.Values{"To": {m.To}}
	var path string
	switch m.Channel {
	case "sms":
		path = "/Messages.json"
		form.Set("Body", strings.ReplaceAll(s.cfg.SMSBody, "{code}", m.Code))
		if s.cfg.MessagingServiceSID != "" {
			form.Set("MessagingServiceSid", s.cfg.MessagingServiceSID)
		} else {
			form.Set("From", s.cfg.From)
		}
	case "voice":
		if s.cfg.From == "" {
			return errors.New("sms_sender twilio: voice needs from")
		}
		path = "/Calls.json"
		form.Set("From", s.cfg.From)
		form.Set("Twiml", TwiML(s.cfg.VoiceText, s.cfg.VoiceLanguage, m.Code))
	default:
		return fmt.Errorf("sms_sender twilio: unknown channel %q", m.Channel)
	}
	endpoint := s.base + "/2010-04-01/Accounts/" + s.cfg.AccountSID + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	user := s.cfg.AccountSID
	if s.cfg.APIKeySID != "" {
		user = s.cfg.APIKeySID
	}
	req.SetBasicAuth(user, s.cfg.Secret)
	resp, err := s.client.Do(req) // #nosec G704 -- 宛先は運用者が設定した URL
	if err != nil {
		return fmt.Errorf("sms_sender twilio: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sms_sender twilio: %s returned %d", path, resp.StatusCode)
	}
	return nil
}

// TwiML は音声で読み上げる TwiML を返す。コードは 1 桁ずつ区切り、2 回読む。
func TwiML(text, lang, code string) string {
	spaced := strings.Join(strings.Split(code, ""), ", ")
	say := strings.ReplaceAll(text, "{code}", spaced)
	var b bytes.Buffer
	b.WriteString(`<Response><Say language="`)
	_ = xml.EscapeText(&b, []byte(lang))
	b.WriteString(`">`)
	_ = xml.EscapeText(&b, []byte(say))
	b.WriteString(`</Say><Pause length="1"/><Say language="`)
	_ = xml.EscapeText(&b, []byte(lang))
	b.WriteString(`">`)
	_ = xml.EscapeText(&b, []byte(say))
	b.WriteString(`</Say></Response>`)
	return b.String()
}
