package hook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type hookFunc func(context.Context, port.HookInput) (port.HookResult, error)

func (f hookFunc) Call(ctx context.Context, in port.HookInput) (port.HookResult, error) {
	return f(ctx, in)
}

func TestRunner(t *testing.T) {
	ctx := context.Background()
	var nilRunner *Runner
	if nilRunner.Has(port.HookPreToken) {
		t.Fatal("nil runner has hooks")
	}
	if res, err := nilRunner.Run(ctx, port.HookInput{Hook: port.HookPreToken}); err != nil || !res.Allow {
		t.Fatalf("nil runner: %v %v", res, err)
	}
	down := hookFunc(func(context.Context, port.HookInput) (port.HookResult, error) {
		return port.HookResult{}, errors.New("down")
	})
	wait := hookFunc(func(ctx context.Context, _ port.HookInput) (port.HookResult, error) {
		<-ctx.Done()
		return port.HookResult{}, ctx.Err()
	})
	var got port.HookInput
	deny := hookFunc(func(_ context.Context, in port.HookInput) (port.HookResult, error) {
		got = in
		return port.HookResult{Allow: false, Reason: "no"}, nil
	})
	r := &Runner{Realm: "acme", Entries: map[string]Entry{
		port.HookPreRegistration:    {Hook: deny},
		port.HookPostAuthentication: {Hook: down},
		port.HookPreMembershipEnd:   {Hook: down, FailOpen: true},
		port.HookPreToken:           {Hook: wait, Timeout: 10 * time.Millisecond},
	}}
	for _, c := range []struct {
		hook  string
		allow bool
	}{
		{port.HookPreRegistration, false}, {port.HookPostAuthentication, false}, {port.HookPreMembershipEnd, true}, {port.HookPreToken, false},
	} {
		res, err := r.Run(ctx, port.HookInput{Hook: c.hook})
		var d *DeniedError
		if c.allow != (err == nil) || (!c.allow && !errors.As(err, &d)) || res.Allow != c.allow {
			t.Fatalf("%s: %v %v", c.hook, res, err)
		}
		if !c.allow {
			var den errs.Denial
			if !errors.As(err, &den) || den.Reasons()[0] != "hook_denied."+c.hook {
				t.Fatalf("%s reasons: %v", c.hook, err)
			}
		}
	}
	if got.Realm != "acme" {
		t.Fatalf("realm not set: %+v", got)
	}
	// 呼び出し元の取り消しはフックの失敗ではない。
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.Run(cctx, port.HookInput{Hook: port.HookPreToken}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestWebhook(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Unix(1_700_000_000, 0)
	status, reply := http.StatusOK, `{"allow":true,"claims":{"n":12345678901234567890}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte("1700000000."))
		m.Write(body)
		var in port.HookInput
		if r.Header.Get("X-IAM-Signature") != "t=1700000000,v1="+hex.EncodeToString(m.Sum(nil)) || r.Header.Get("X-IAM-Hook") != port.HookPreToken ||
			json.Unmarshal(body, &in) != nil || in.ClientID != "app" {
			http.Error(w, "bad", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	defer srv.Close()
	h := &Webhook{URL: srv.URL, Secret: secret, Clock: clock.NewFake(now)}
	in := port.HookInput{Hook: port.HookPreToken, ClientID: "app"}
	res, err := h.Call(context.Background(), in)
	if err != nil || !res.Allow || res.Claims["n"] != json.Number("12345678901234567890") {
		t.Fatalf("call: %+v %v", res, err)
	}
	for _, c := range []struct {
		status int
		reply  string
	}{
		{http.StatusAccepted, `{"allow":true}`}, {http.StatusOK, `not json`}, {http.StatusOK, `{"allow":true,"x":"` + strings.Repeat("a", maxResponse) + `"}`},
	} {
		status, reply = c.status, c.reply
		if _, err := h.Call(context.Background(), in); err == nil {
			t.Fatalf("status %d reply %.20q: no error", c.status, c.reply)
		}
	}
	// 転送には従わない。
	redirect := httptest.NewServer(http.RedirectHandler(srv.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()
	if _, err := (&Webhook{URL: redirect.URL, Secret: secret}).Call(context.Background(), in); err == nil {
		t.Fatal("followed a redirect")
	}
}
