package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	notifier "github.com/imohiyoko/iam/adapters/notifier/webhook"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func TestSendSigned(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	clk := clock.NewFake(time.Unix(1_800_000_000, 0))
	var got Body
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-IAM-Signature") != notifier.Sign(secret, b, clk.Now()) {
			w.WriteHeader(401)
			return
		}
		raw = string(b)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	m := port.PushMessage{Token: "tok", Platform: "fcm", ChallengeID: "chal", DeviceID: "dev_1", ExpiresAt: clk.Now().Add(time.Minute)}
	if err := New(srv.URL, secret, time.Second, clk).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if got.Type != "iam.push.challenge" || got.Token != "tok" || got.ChallengeID != "chal" || got.DeviceID != "dev_1" {
		t.Fatalf("body: %+v", got)
	}
	// 番号もユーザーの ID も入れない。
	var all map[string]any
	_ = json.Unmarshal([]byte(raw), &all)
	for _, k := range []string{"number", "user_id", "email"} {
		if _, ok := all[k]; ok {
			t.Fatalf("payload has %s: %s", k, raw)
		}
	}
	if err := New(srv.URL, []byte("wrong-secret-wrong-secret-wrong!"), time.Second, clk).Send(context.Background(), m); err == nil {
		t.Fatal("non-2xx accepted")
	}
}

func TestFactory(t *testing.T) {
	f, err := plugin.PushSender("webhook")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUSH_TEST_SECRET", "0123456789abcdef0123456789abcdef")
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"url": "http://relay.example", "secret_env": "PUSH_TEST_SECRET"}}); err == nil {
		t.Fatal("http accepted outside development mode")
	}
	t.Setenv("PUSH_TEST_SECRET", "short")
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"url": "https://relay.example", "secret_env": "PUSH_TEST_SECRET"}}); err == nil {
		t.Fatal("short secret accepted")
	}
	t.Setenv("PUSH_TEST_SECRET", "0123456789abcdef0123456789abcdef")
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"url": "https://relay.example", "secret_env": "PUSH_TEST_SECRET"}}); err != nil {
		t.Fatal(err)
	}
}
