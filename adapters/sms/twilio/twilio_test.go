package twilio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

// sid は試験用の SID（実在しない。秘密の検査に掛からないよう組み立てる）。
var sid = "AC" + strings.Repeat("0", 32)

func TestSendSMSAndVoice(t *testing.T) {
	var got []url.Values
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != sid || p != "token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(401)
			return
		}
		_ = r.ParseForm()
		got, paths = append(got, r.PostForm), append(paths, r.URL.Path)
		w.WriteHeader(201)
	}))
	defer srv.Close()
	s, err := New(Config{AccountSID: sid, Secret: "token", From: "+15005550006", SMSBody: "Code: {code}", VoiceText: "Your code is {code}",
		VoiceLanguage: "ja-JP", BaseURL: srv.URL, Dev: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Send(ctx, port.SMSMessage{To: "+819012345678", Channel: "sms", Code: "123456", ExpiresAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, port.SMSMessage{To: "+819012345678", Channel: "voice", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/2010-04-01/Accounts/"+sid+"/Messages.json" || got[0].Get("Body") != "Code: 123456" || got[0].Get("To") != "+819012345678" ||
		got[0].Get("From") != "+15005550006" {
		t.Fatalf("sms: %s %v", paths[0], got[0])
	}
	if paths[1] != "/2010-04-01/Accounts/"+sid+"/Calls.json" || !strings.Contains(got[1].Get("Twiml"), `<Say language="ja-JP">Your code is 1, 2, 3, 4, 5, 6</Say>`) {
		t.Fatalf("voice: %s %v", paths[1], got[1])
	}
	// 2xx 以外・知らない経路・形の誤った宛先はエラー。
	bad, _ := New(Config{AccountSID: sid, Secret: "wrong", From: "+15005550006", SMSBody: "{code}", VoiceText: "{code}", VoiceLanguage: "en",
		BaseURL: srv.URL, Dev: true})
	if err := bad.Send(ctx, port.SMSMessage{To: "+819012345678", Channel: "sms", Code: "123456"}); err == nil {
		t.Fatal("401 accepted")
	}
	for _, m := range []port.SMSMessage{{To: "+819012345678", Channel: "fax", Code: "123456"}, {To: "0901234", Channel: "sms", Code: "123456"},
		{To: "+819012345678", Channel: "sms", Code: "12a"}} {
		if err := s.Send(ctx, m); err == nil {
			t.Fatalf("accepted %+v", m)
		}
	}
}

func TestTwiMLEscapes(t *testing.T) {
	x := TwiML(`<b>"{code}"</b>`, "en-US", "12")
	if strings.Contains(x, "<b>") || !strings.Contains(x, "&lt;b&gt;") {
		t.Fatalf("not escaped: %s", x)
	}
}

func TestConfig(t *testing.T) {
	ok := Config{AccountSID: sid, Secret: "t", From: "+15005550006", SMSBody: "{code}", VoiceText: "{code}", VoiceLanguage: "en-US",
		BaseURL: "https://api.twilio.com"}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Config){
		"sid":      func(c *Config) { c.AccountSID = "SK" + strings.Repeat("0", 32) },
		"from":     func(c *Config) { c.From = "" },
		"template": func(c *Config) { c.SMSBody = "no code" },
		"http":     func(c *Config) { c.BaseURL = "http://api.twilio.com" },
		"userinfo": func(c *Config) { c.BaseURL = "https://u:p@api.twilio.com" },
		"lang":     func(c *Config) { c.VoiceLanguage = "<x>" },
		"secret":   func(c *Config) { c.Secret = "" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	t.Setenv("TWILIO_TEST_TOKEN", "tok")
	f, err := plugin.SMSSender("twilio")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"account_sid": sid, "auth_token_env": "TWILIO_TEST_TOKEN",
		"from": "+15005550006"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"account_sid": sid, "nosuch": "x"}}); err == nil {
		t.Fatal("unknown option accepted")
	}
}
