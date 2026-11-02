package sms

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

type fakeStore struct{ cs []port.MethodCredential }

func (f *fakeStore) List(_ context.Context, userID string) ([]port.MethodCredential, error) {
	var out []port.MethodCredential
	for _, c := range f.cs {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) FindByLookup(context.Context, string) (port.MethodCredential, error) {
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

func (f *fakeStore) Create(_ context.Context, userID, _ string, data []byte) (port.MethodCredential, error) {
	c := port.MethodCredential{ID: "c" + string(rune('0'+len(f.cs))), PublicID: "crd_" + string(rune('0'+len(f.cs))), UserID: userID, Data: data,
		Sealed: data}
	f.cs = append(f.cs, c)
	return c, nil
}

func (f *fakeStore) Update(context.Context, port.MethodCredential, []byte) (port.MethodCredential, error) {
	return port.MethodCredential{}, errors.New("not used")
}

type outbox struct{ sent []port.SMSMessage }

func (o *outbox) Send(_ context.Context, m port.SMSMessage) error {
	o.sent = append(o.sent, m)
	return nil
}

func setup(t *testing.T, opts map[string]string) (Method, *outbox, *clock.Fake) {
	t.Helper()
	k := testkit.New(t)
	clk := k.Clock
	o := &outbox{}
	a, err := Method{}.Setup(context.Background(), port.MethodSetup{Options: opts, SMS: o, Clock: clk,
		Ephemeral: method.Scoped(k.Cache, Name, "r1"),
		Blind:     func(_ context.Context, v string) (string, error) { return "b:" + v, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return a.(Method), o, clk
}

func env(s *fakeStore, clk clock.Clock) port.MethodEnv {
	return port.MethodEnv{RealmID: "r1", UserID: "u1", Credentials: s, Now: clk.Now(), ClientIP: "192.0.2.1"}
}

func payload(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func deliver(t *testing.T, ch port.MethodChallenge) {
	t.Helper()
	if ch.Deliver == nil {
		t.Fatal("no delivery")
	}
	if err := ch.Deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInfo(t *testing.T) {
	if err := method.Check(Method{}); err != nil {
		t.Fatal(err)
	}
	i := Method{}.Info()
	if i.AAL != 2 || i.Kind != port.FactorPossession || !slices.Equal(i.Usages, []port.MethodUsage{port.UsageSecondFactor}) || i.OutOfBand {
		t.Fatalf("info: %+v", i)
	}
}

func TestNotConfiguredFailsClosed(t *testing.T) {
	m, s := Method{}, &fakeStore{}
	e := port.MethodEnv{UserID: "u1", Credentials: s}
	if _, err := m.EnrollBegin(context.Background(), e, port.MethodRequest{}); !errors.Is(err, errNotConfigured) {
		t.Fatalf("enroll-begin: %v", err)
	}
	if _, err := m.Begin(context.Background(), e, port.MethodRequest{}); !errors.Is(err, errNotConfigured) {
		t.Fatalf("begin: %v", err)
	}
	if _, err := (Method{}).Setup(context.Background(), port.MethodSetup{}); err == nil {
		t.Fatal("setup without a sender")
	}
}

func TestOptions(t *testing.T) {
	o, err := parseOptions(map[string]string{"channels": "voice, sms", "allowed_country_codes": "+81,1", "digits": "8", "code_ttl": "3m"})
	if err != nil || !slices.Equal(o.Channels, []string{"voice", "sms"}) || !slices.Equal(o.Countries, []string{"81", "1"}) || o.Digits != 8 ||
		o.CodeTTL != 3*time.Minute {
		t.Fatalf("options: %+v %v", o, err)
	}
	for _, bad := range []map[string]string{{"x": "1"}, {"digits": "5"}, {"digits": "9"}, {"code_ttl": "20m"}, {"channels": "fax"},
		{"channels": ""}, {"allowed_country_codes": "0"}, {"per_user": "0"}, {"rate_window": "1s"}, {"resend_interval": "1h"}} {
		if _, err := parseOptions(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestNormalizeAndMask(t *testing.T) {
	for in, want := range map[string]string{"+81 90-1234-5678": "+819012345678", "+1 (555) 555.0100": "+15555550100"} {
		if got, ok := NormalizeNumber(in); !ok || got != want {
			t.Fatalf("NormalizeNumber(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "0901234567", "+0123456789", "+12345", "+1234567890123456", "+81abc12345", "+81 90\n1234"} {
		if _, ok := NormalizeNumber(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got := Mask("+819012345678"); got != "+**********78" {
		t.Fatalf("Mask = %q", got)
	}
}

func TestEnrollAndLogin(t *testing.T) {
	m, out, clk := setup(t, map[string]string{"channels": "sms,voice"})
	s := &fakeStore{}
	ctx := context.Background()
	ch, err := m.EnrollBegin(ctx, env(s, clk), port.MethodRequest{Payload: payload(map[string]any{"phone_number": "+15555550100"})})
	if err != nil {
		t.Fatal(err)
	}
	// 状態にコードを平文で置かない。
	deliver(t, ch)
	code := out.sent[0].Code
	if strings.Contains(string(ch.State), code) {
		t.Fatal("code stored in the flow state")
	}
	if _, err := m.EnrollComplete(ctx, env(s, clk), port.MethodRequest{State: ch.State, Payload: payload(map[string]any{"code": "x"})}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("wrong code: %v", err)
	}
	en, err := m.EnrollComplete(ctx, env(s, clk), port.MethodRequest{State: ch.State, Payload: payload(map[string]any{"code": code})})
	if err != nil {
		t.Fatal(err)
	}
	// 同じコードは2度使えない。
	if _, err := m.EnrollComplete(ctx, env(s, clk), port.MethodRequest{State: ch.State, Payload: payload(map[string]any{"code": code})}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reused enrollment code: %v", err)
	}

	clk.Advance(time.Minute)
	ch, err = m.Begin(ctx, env(s, clk), port.MethodRequest{Payload: payload(map[string]any{"channel": "voice"})})
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, ch)
	if len(ch.Events) != 1 || ch.Events[0].Type != "code_sent" || ch.Events[0].Details["credential_id"] != en.Credential.PublicID {
		t.Fatalf("events: %+v", ch.Events)
	}
	r, err := m.Complete(ctx, env(s, clk), port.MethodRequest{State: ch.State, Payload: payload(map[string]any{"code": out.sent[1].Code})})
	if err != nil || r.Credential.ID != en.Credential.ID || !slices.Equal(r.AMR, []string{"tel"}) {
		t.Fatalf("complete: %+v %v", r, err)
	}
	// 許していない経路は拒否する。
	clk.Advance(time.Minute)
	if _, err := m.Begin(ctx, env(s, clk), port.MethodRequest{Payload: payload(map[string]any{"channel": "fax"})}); !errors.Is(err, errs.Invalid) {
		t.Fatalf("unknown channel: %v", err)
	}
	// 1要素目には使えない。
	e := env(s, clk)
	e.UserID = ""
	if _, err := m.Begin(ctx, e, port.MethodRequest{}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("first factor: %v", err)
	}
}

func TestResendAndRateLimits(t *testing.T) {
	m, _, clk := setup(t, map[string]string{"per_number": "2", "per_ip": "3", "resend_interval": "10s"})
	ctx := context.Background()
	begin := func(user, ip string) error {
		e := env(&fakeStore{}, clk)
		e.UserID, e.ClientIP = user, ip
		_, err := m.EnrollBegin(ctx, e, port.MethodRequest{Payload: payload(map[string]any{"phone_number": "+15555550100"})})
		return err
	}
	if err := begin("u1", "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := errors.AsType[*ratelimit.ExceededError](begin("u1", "a")); !ok {
		t.Fatal("resend within the interval accepted")
	}
	// 番号ごとの上限（別のユーザーから同じ番号へ）。
	if err := begin("u2", "b"); err != nil {
		t.Fatal(err)
	}
	if _, ok := errors.AsType[*ratelimit.ExceededError](begin("u3", "c")); !ok {
		t.Fatal("per number limit not applied")
	}
}

func FuzzNormalizeNumber(f *testing.F) {
	for _, s := range []string{"+819012345678", "+1 (555) 555-0100", "", "+", "++1", "+１２３"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := NormalizeNumber(s)
		if ok && !e164RE.MatchString(n) {
			t.Fatalf("NormalizeNumber(%q) = %q not E.164", s, n)
		}
		if ok {
			if m := Mask(n); len(m) != len(n) || m[len(m)-2:] != n[len(n)-2:] {
				t.Fatalf("Mask(%q) = %q", n, m)
			}
		}
	})
}

func (f *fakeStore) Revoke(context.Context, port.MethodCredential, string) error { return nil }
