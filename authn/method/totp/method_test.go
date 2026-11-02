package totp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/methodtest"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func env(s *methodtest.Store, now time.Time) port.MethodEnv {
	return port.MethodEnv{RealmID: "rlm_1", UserID: "usr_1", Usage: port.UsageSecondFactor, Credentials: s, Now: now,
		Issuer: "Example", Account: "a@example.com"}
}

func code(t *testing.T, c string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]string{"code": c})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMethodInfo(t *testing.T) {
	i := (Method{}).Info()
	if err := method.Check(Method{}); err != nil || i.Feature != "" || i.Supports(port.UsageFirstFactor) || !i.Supports(port.UsageSecondFactor) ||
		i.Kind != port.FactorPossession || i.AAL != 2 || len(i.AMR) != 1 || i.AMR[0] != "otp" {
		t.Fatalf("info = %+v, %v", i, err)
	}
}

func TestEnrollAndComplete(t *testing.T) {
	ctx := context.Background()
	m, s := Method{}, &methodtest.Store{}
	now := time.Unix(1_800_000_000, 0)
	// 登録していなければ2要素目を始められない（本人確認の後なので 404 に区別してよい）。
	if _, err := m.Begin(ctx, env(s, now), port.MethodRequest{}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("begin without totp = %v", err)
	}
	ch, err := m.EnrollBegin(ctx, env(s, now), port.MethodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Secret, URI string }
	if err := json.Unmarshal(ch.Payload, &out); err != nil || out.URI != URI(mustDecode(t, out.Secret), "Example", "a@example.com") {
		t.Fatalf("enroll payload = %s, %v", ch.Payload, err)
	}
	secret := mustDecode(t, out.Secret)
	if _, err := m.EnrollComplete(ctx, env(s, now), port.MethodRequest{Payload: code(t, "000000x"), State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("wrong code = %v", err)
	}
	en, err := m.EnrollComplete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, Step(now))), State: ch.State})
	if err != nil {
		t.Fatal(err)
	}
	// 1人に1つ。
	if _, err := m.EnrollBegin(ctx, env(s, now), port.MethodRequest{}); !errors.Is(err, ErrTOTPExists) {
		t.Fatalf("second enrollment = %v", err)
	}
	if _, err := m.EnrollComplete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, Step(now))), State: ch.State}); !errors.Is(err, ErrTOTPExists) {
		t.Fatalf("second enrollment complete = %v", err)
	}
	if _, err := m.Begin(ctx, env(s, now), port.MethodRequest{}); err != nil {
		t.Fatal(err)
	}
	// 登録に使った窓のコードは再利用できない。
	if _, err := m.Complete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, Step(now)))}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reuse of the enrollment code = %v", err)
	}
	now = now.Add(30 * time.Second)
	r, err := m.Complete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, Step(now)))})
	if err != nil || r.Credential.ID != en.Credential.ID {
		t.Fatalf("complete = %+v, %v", r, err)
	}
	// 同じ窓と前の窓は通らない。
	for _, step := range []int64{Step(now), Step(now) - 1} {
		if _, err := m.Complete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, step))}); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("step %d reused = %v", step, err)
		}
	}
	// 別のユーザー・1要素目・壊れた入力は通らない。
	other := env(s, now.Add(30*time.Second))
	other.UserID = "usr_2"
	if _, err := m.Complete(ctx, other, port.MethodRequest{Payload: code(t, Code(secret, Step(other.Now)))}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("other user = %v", err)
	}
	first := env(s, now)
	first.UserID = ""
	if _, err := m.Complete(ctx, first, port.MethodRequest{Payload: code(t, Code(secret, Step(now)+1))}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("first factor = %v", err)
	}
	for _, p := range []string{"", "null", "[]", `{"code": 1}`} {
		if _, err := m.Complete(ctx, env(s, now), port.MethodRequest{Payload: json.RawMessage(p)}); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("payload %q = %v", p, err)
		}
	}
}

// 同じコードを同時に使ったときは、記録の比較と交換で1つしか通らない（読んだ後に書き換わっていれば拒む）。
func TestCompleteRejectsConcurrentUse(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	secret := []byte("12345678901234567890")
	raw, _ := json.Marshal(Data{Secret: secret, LastStep: Step(now) - 5})
	s := &methodtest.Store{}
	if _, err := s.Create(ctx, "usr_1", "", raw); err != nil {
		t.Fatal(err)
	}
	e := env(s, now)
	e.Credentials = conflictStore{s}
	if _, err := (Method{}).Complete(ctx, e, port.MethodRequest{Payload: code(t, Code(secret, Step(now)))}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("conflicting update = %v", err)
	}
	if _, err := (Method{}).Complete(ctx, env(s, now), port.MethodRequest{Payload: code(t, Code(secret, Step(now)))}); err != nil {
		t.Fatalf("complete = %v", err)
	}
}

// conflictStore は Update を常に競合にする。
type conflictStore struct{ *methodtest.Store }

func (conflictStore) Update(context.Context, port.MethodCredential, []byte) (port.MethodCredential, error) {
	return port.MethodCredential{}, errs.New(errs.KindConflict, "changed")
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b32.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
