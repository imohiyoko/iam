package password_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/methodtest"
	password "github.com/imohiyoko/iam/authn/method/password"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// users は LoginUser のテスト用の実装。
type users struct {
	m     map[string]string
	err   error
	calls int
}

func (u *users) LoginUser(_ context.Context, id string) (string, error) {
	u.calls++
	if u.err != nil {
		return "", u.err
	}
	if v, ok := u.m[strings.ToLower(id)]; ok {
		return v, nil
	}
	return "", errs.New(errs.KindNotFound, "user")
}

type breach map[string]bool

func (b breach) Breached(_ context.Context, h string) (bool, error) { return b[h], nil }

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const good = "a long and memorable passphrase"

func enrollEnv(s *methodtest.Store) port.MethodEnv {
	return port.MethodEnv{RealmID: "rlm_1", UserID: "usr_1", Credentials: s, Now: time.Now(), RecentAuth: true}
}

func set(t *testing.T, m *password.Method, e port.MethodEnv, in map[string]string) error {
	t.Helper()
	ctx := context.Background()
	ch, err := m.EnrollBegin(ctx, e, port.MethodRequest{Payload: raw(t, in)})
	if err != nil {
		return err
	}
	_, err = m.EnrollComplete(ctx, e, port.MethodRequest{State: ch.State})
	return err
}

func TestMethodInfo(t *testing.T) {
	m := &password.Method{}
	i := m.Info()
	if err := method.Check(m); err != nil || i.Feature != "password" || i.Kind != port.FactorKnowledge || i.AAL != 1 ||
		!i.Supports(port.UsageFirstFactor) || i.Supports(port.UsageSecondFactor) || i.AMR[0] != "pwd" {
		t.Fatalf("info = %+v, %v", i, err)
	}
}

func TestEnrollRules(t *testing.T) {
	m, s := &password.Method{Params: fast, Breach: breach{}}, &methodtest.Store{}
	e := enrollEnv(s)
	for pw, want := range map[string]error{"short": password.ErrTooShort, strings.Repeat("x", password.MaxLength+1): password.ErrTooLong,
		strings.Repeat("a", password.MaxInputBytes+1): password.ErrTooLong} {
		if err := set(t, m, e, map[string]string{"password": pw}); !errors.Is(err, want) {
			t.Errorf("set %d chars = %v, want %v", len(pw), err, want)
		}
	}
	if _, err := m.EnrollBegin(context.Background(), e, port.MethodRequest{Payload: json.RawMessage("[]")}); !errors.Is(err, errs.Invalid) {
		t.Errorf("bad payload = %v", err)
	}
	stale := e
	stale.RecentAuth = false
	if err := set(t, m, stale, map[string]string{"password": good}); !errors.Is(err, password.ErrReauthRequired) {
		t.Fatalf("first set without recent auth = %v", err)
	}
	if err := set(t, m, e, map[string]string{"password": good}); err != nil {
		t.Fatal(err)
	}
	// 置き換えには今のパスワードが要る。直近の認証の代わりになる。
	if err := set(t, m, stale, map[string]string{"password": "another long passphrase", "current_password": "wrong"}); !errors.Is(err, password.ErrCurrentPassword) {
		t.Fatalf("change with wrong current = %v", err)
	}
	if err := set(t, m, stale, map[string]string{"password": "another long passphrase", "current_password": good}); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.List(context.Background(), "usr_1"); len(active) != 1 || len(s.Revoked) != 1 {
		t.Fatalf("after change: %d active, revoked %v", len(active), s.Revoked)
	}
	// 復旧専用のセッションでは今のパスワードを求めない。
	rec := stale
	rec.Usage = port.UsageRecovery
	if err := set(t, m, rec, map[string]string{"password": "a third long passphrase"}); err != nil {
		t.Fatal(err)
	}
	// 始めと完了の間に別の操作で変わっていれば拒む。
	ctx := context.Background()
	ch, err := m.EnrollBegin(ctx, rec, port.MethodRequest{Payload: raw(t, map[string]string{"password": "a fourth long passphrase"})})
	if err != nil {
		t.Fatal(err)
	}
	if err := set(t, m, rec, map[string]string{"password": "a fifth long passphrase"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnrollComplete(ctx, rec, port.MethodRequest{State: ch.State}); !errors.Is(err, password.ErrChanged) {
		t.Fatalf("complete after a concurrent change = %v", err)
	}
	// 漏洩済みは拒む。
	bm := &password.Method{Params: fast, Breach: breach{sha("password1234567890"): true}}
	if err := set(t, bm, enrollEnv(&methodtest.Store{}), map[string]string{"password": "password1234567890"}); !errors.Is(err, password.ErrBreached) {
		t.Fatalf("breached = %v", err)
	}
}

func TestComplete(t *testing.T) {
	ctx := context.Background()
	m, s := &password.Method{Params: fast, Breach: breach{sha(good): true}}, &methodtest.Store{}
	// 古いパラメータで作ったハッシュは、照合が通れば作り直す。
	old, err := password.Hash(password.Normalize(good), password.Params{Memory: 16, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.Create(ctx, "usr_1", "", raw(t, password.Data{Hash: old}))
	u := &users{m: map[string]string{"alice@example.com": "usr_1", "bob@example.com": "usr_2"}}
	e := port.MethodEnv{RealmID: "rlm_1", Usage: port.UsageFirstFactor, Credentials: s, Users: u, Now: time.Now()}
	login := func(email, pw string) (port.MethodResult, error) {
		return m.Complete(ctx, e, port.MethodRequest{Payload: raw(t, map[string]string{"email": email, "password": pw})})
	}
	r, err := login("Alice@Example.com", "ａ long and memorable passphrase") // NFKC で同じ
	if err != nil || r.Credential.ID != c.ID || r.KnowledgeBreached == nil || !*r.KnowledgeBreached {
		t.Fatalf("login = %+v, %v", r, err)
	}
	if h, _ := password.HashOf(s.Creds[0]); h == old || !strings.Contains(h, "m=8,") {
		t.Fatalf("not rehashed: %s", h)
	}
	for name, in := range map[string][2]string{"wrong": {"alice@example.com", "wrong password here"}, "no user": {"nobody@example.com", good},
		"no password": {"bob@example.com", good}, "too long": {"alice@example.com", strings.Repeat("a", password.MaxInputBytes+1)}} {
		if _, err := login(in[0], in[1]); !errors.Is(err, errs.AuthenticationFailed) {
			t.Errorf("%s = %v", name, err)
		}
	}
	// 回数の上限は引き当てで数え、そのまま返す（照合の失敗に隠さない）。
	u.err = &ratelimit.ExceededError{}
	if _, err := login("alice@example.com", good); !errors.As(err, new(*ratelimit.ExceededError)) {
		t.Fatalf("rate limited = %v", err)
	}
	u.err = errors.New("down")
	if _, err := login("alice@example.com", good); err == nil || errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("infrastructure error = %v", err)
	}
	// 2要素目・引き当てが無い呼び出し・壊れた入力は通らない。
	u.err = nil
	second := e
	second.Usage, second.UserID = port.UsageSecondFactor, "usr_1"
	if _, err := m.Complete(ctx, second, port.MethodRequest{Payload: raw(t, map[string]string{"email": "alice@example.com", "password": good})}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("second factor = %v", err)
	}
	if _, err := m.Begin(ctx, second, port.MethodRequest{}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("begin second factor = %v", err)
	}
	if _, err := m.Complete(ctx, e, port.MethodRequest{Payload: json.RawMessage(`{"email": 1}`)}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("bad payload = %v", err)
	}
}
