package siteverify_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/botcheck/siteverify"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func server(t *testing.T, status int, body string) (*httptest.Server, *url.Values) {
	t.Helper()
	got := &url.Values{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_ = r.ParseForm()
		*got = r.PostForm
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s, got
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	s, form := server(t, http.StatusOK, `{"success":true,"hostname":"login.example.com"}`)
	v := siteverify.New(s.URL, "sekret", "login.example.com", time.Second)
	if err := v.Verify(ctx, "tok", "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	if form.Get("secret") != "sekret" || form.Get("response") != "tok" || form.Get("remoteip") != "203.0.113.1" {
		t.Errorf("form = %v", form)
	}
	if err := siteverify.New(s.URL, "sekret", "other.example.com", time.Second).Verify(ctx, "tok", ""); !errors.Is(err, port.ErrBotRejected) {
		t.Errorf("hostname mismatch = %v", err)
	}
	for body, rejected := range map[string]bool{
		`{"success":false,"error-codes":["invalid-input-response"]}`: true,
		`{"hostname":"login.example.com"}`:                           false, // success が無い
		`not json`:                                                   false,
	} {
		s, _ := server(t, http.StatusOK, body)
		err := siteverify.New(s.URL, "sekret", "", time.Second).Verify(ctx, "tok", "")
		if err == nil || errors.Is(err, port.ErrBotRejected) != rejected {
			t.Errorf("%s: err = %v", body, err)
		}
	}
	s, _ = server(t, http.StatusInternalServerError, `{"success":true}`)
	if err := siteverify.New(s.URL, "sekret", "", time.Second).Verify(ctx, "tok", ""); err == nil || errors.Is(err, port.ErrBotRejected) {
		t.Errorf("5xx = %v", err)
	}
	s, _ = server(t, http.StatusFound, `{"success":true}`)
	if err := siteverify.New(s.URL, "sekret", "", time.Second).Verify(ctx, "tok", ""); err == nil {
		t.Error("redirect accepted")
	}
}

func TestPlugin(t *testing.T) {
	f, err := plugin.BotCheck("siteverify")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Setenv("IAM_TEST_BOT_SECRET", "s")
	for name, opts := range map[string]map[string]string{
		"http url":       {"url": "http://x.example.com", "secret_env": "IAM_TEST_BOT_SECRET"},
		"no secret_env":  {"url": "https://x.example.com"},
		"empty secret":   {"url": "https://x.example.com", "secret_env": "IAM_TEST_BOT_SECRET_MISSING"},
		"unknown option": {"url": "https://x.example.com", "secret_env": "IAM_TEST_BOT_SECRET", "x": "y"},
		"bad timeout":    {"url": "https://x.example.com", "secret_env": "IAM_TEST_BOT_SECRET", "timeout": "1m"},
	} {
		t.Setenv("IAM_TEST_BOT_SECRET", "s") // 読んだ後に消すので、毎回置き直す
		if _, err := f(ctx, plugin.Config{Options: opts}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	t.Setenv("IAM_TEST_BOT_SECRET", "s")
	if _, err := f(ctx, plugin.Config{Options: map[string]string{"url": "https://x.example.com", "secret_env": "IAM_TEST_BOT_SECRET"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("IAM_TEST_BOT_SECRET"); ok {
		t.Error("secret_env is kept in the environment")
	}
}
