package hotp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// rfcSecret と rfcCodes は RFC 4226 付録 D のテストベクタ。
var (
	rfcSecret = []byte("12345678901234567890")
	rfcCodes  = []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
)

func TestCodeRFC4226(t *testing.T) {
	for i, want := range rfcCodes {
		if got := Code(rfcSecret, uint64(i), 6); got != want {
			t.Errorf("Code(count=%d) = %s, want %s", i, got, want)
		}
	}
	// 付録 D の切り詰めた値（10進）の下 8 桁。
	if got := Code(rfcSecret, 0, 8); got != "84755224" {
		t.Errorf("Code(count=0, 8 digits) = %s", got)
	}
}

func TestVerifyWindow(t *testing.T) {
	// 次に期待するカウンターから LookAhead 個まで。
	if c, ok := Verify(rfcSecret, rfcCodes[3], 0, LookAhead, 6); !ok || c != 3 {
		t.Fatalf("Verify ahead = %d, %v", c, ok)
	}
	// 前のカウンター（使ったもの）は受け入れない。
	if _, ok := Verify(rfcSecret, rfcCodes[3], 4, LookAhead, 6); ok {
		t.Fatal("used counter accepted")
	}
	// 窓の外は受け入れない。
	if _, ok := Verify(rfcSecret, rfcCodes[9], 0, 5, 6); ok {
		t.Fatal("code outside the window accepted")
	}
	for _, bad := range []string{"", "75522", "7552240", "abcdef"} {
		if _, ok := Verify(rfcSecret, bad, 0, LookAhead, 6); ok {
			t.Fatalf("Verify(%q) accepted", bad)
		}
	}
}

func TestResync(t *testing.T) {
	// 窓の外でも、続けて出した2つのコードなら再同期できる（最後に使ったカウンターを返す）。
	if c, ok := Resync(rfcSecret, rfcCodes[7], rfcCodes[8], 0, ResyncWindow, 6); !ok || c != 8 {
		t.Fatalf("Resync = %d, %v", c, ok)
	}
	// 続いていない2つは受け入れない。
	if _, ok := Resync(rfcSecret, rfcCodes[7], rfcCodes[9], 0, ResyncWindow, 6); ok {
		t.Fatal("non-consecutive codes accepted")
	}
	if _, ok := Resync(rfcSecret, rfcCodes[2], rfcCodes[3], 3, ResyncWindow, 6); ok {
		t.Fatal("resync to a used counter accepted")
	}
}

func TestURI(t *testing.T) {
	u, err := url.Parse(URI(rfcSecret, "Example", "a@example.com", 6, 0))
	if err != nil || u.Scheme != "otpauth" || u.Host != "hotp" || u.Query().Get("counter") != "0" || u.Query().Get("secret") != b32.EncodeToString(rfcSecret) {
		t.Fatalf("URI = %v, %v", u, err)
	}
}

// fakeStore は CredentialStore のテスト用の実装（暗号化せず、比較つきの置き換えを持つ）。
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
	c := port.MethodCredential{ID: fmt.Sprintf("crd_%d", len(f.cs)), UserID: userID, Data: data, Sealed: bytes.Clone(data)}
	f.cs = append(f.cs, c)
	return c, nil
}

func (f *fakeStore) Update(_ context.Context, c port.MethodCredential, data []byte) (port.MethodCredential, error) {
	for i, x := range f.cs {
		if x.ID == c.ID {
			if !bytes.Equal(x.Sealed, c.Sealed) {
				return port.MethodCredential{}, errs.New(errs.KindConflict, "changed")
			}
			x.Data, x.Sealed = data, bytes.Clone(data)
			f.cs[i] = x
			return x, nil
		}
	}
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

func env(s *fakeStore) port.MethodEnv {
	return port.MethodEnv{RealmID: "rlm_1", UserID: "usr_1", Credentials: s, Now: time.Now(), Issuer: "Example", Account: "a@example.com"}
}

func payload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMethodInfo(t *testing.T) {
	if err := method.Check(Method{}); err != nil {
		t.Fatal(err)
	}
	if i := (Method{}).Info(); i.Supports(port.UsageFirstFactor) || !i.Supports(port.UsageSecondFactor) {
		t.Fatalf("usages = %v", i.Usages)
	}
}

func TestEnrollAndLogin(t *testing.T) {
	ctx := context.Background()
	m, s := Method{}, &fakeStore{}
	// 秘密を取り込む（RFC のベクタの種）。
	ch, err := m.EnrollBegin(ctx, env(s), port.MethodRequest{Payload: payload(t, map[string]any{"secret": b32.EncodeToString(rfcSecret)})})
	if err != nil {
		t.Fatal(err)
	}
	var out enrollOutput
	if err := json.Unmarshal(ch.Payload, &out); err != nil || out.Secret != b32.EncodeToString(rfcSecret) || out.Digits != 6 {
		t.Fatalf("enroll output = %+v, %v", out, err)
	}
	if _, err := m.EnrollComplete(ctx, env(s), port.MethodRequest{State: ch.State, Payload: payload(t, codeInput{Code: "000000"})}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("wrong enrollment code: %v", err)
	}
	en, err := m.EnrollComplete(ctx, env(s), port.MethodRequest{State: ch.State, Payload: payload(t, codeInput{Code: rfcCodes[1]})})
	if err != nil || en.Credential.ID == "" {
		t.Fatalf("EnrollComplete = %+v, %v", en, err)
	}
	login := func(in codeInput) error {
		_, err := m.Complete(ctx, env(s), port.MethodRequest{Payload: payload(t, in)})
		return err
	}
	// 登録に使ったコードと、それより前のコードは使えない。
	for _, c := range []string{rfcCodes[0], rfcCodes[1]} {
		if err := login(codeInput{Code: c}); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("reused code %s: %v", c, err)
		}
	}
	if err := login(codeInput{Code: rfcCodes[3]}); err != nil {
		t.Fatalf("code in the window: %v", err)
	}
	if err := login(codeInput{Code: rfcCodes[3]}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("same code twice: %v", err)
	}
	// 窓の外（カウンター 4 から 10 個より先）は、続けて出した2つで再同期する。
	far := func(n uint64) string { return Code(rfcSecret, n, 6) }
	if err := login(codeInput{Code: far(30)}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("code outside the window: %v", err)
	}
	if err := login(codeInput{Code: far(30), NextCode: far(31)}); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if err := login(codeInput{Code: far(31)}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("code before resync point: %v", err)
	}
	if err := login(codeInput{Code: far(32)}); err != nil {
		t.Fatalf("code after resync: %v", err)
	}
}

func TestCompleteConcurrentUpdateRejected(t *testing.T) {
	ctx := context.Background()
	m, s := Method{}, &fakeStore{}
	raw, _ := json.Marshal(data{Secret: rfcSecret, Counter: 0, Digits: 6})
	if _, err := s.Create(ctx, "usr_1", "", raw); err != nil {
		t.Fatal(err)
	}
	// 別の照合が先に書き込んだ（比較の失敗）ら、再利用として拒否する。
	stale := &staleStore{fakeStore: s}
	_, err := m.Complete(ctx, env(s), port.MethodRequest{Payload: payload(t, codeInput{Code: rfcCodes[0]})})
	if err != nil {
		t.Fatal(err)
	}
	e := env(s)
	e.Credentials = stale
	if _, err := m.Complete(ctx, e, port.MethodRequest{Payload: payload(t, codeInput{Code: rfcCodes[1]})}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("conflicting update: %v", err)
	}
}

// staleStore は、List で返した後に別の書き込みがあった状態を作る。
type staleStore struct{ fakeStore *fakeStore }

func (s *staleStore) List(ctx context.Context, userID string) ([]port.MethodCredential, error) {
	cs, err := s.fakeStore.List(ctx, userID)
	for i := range cs {
		cs[i].Sealed = []byte("older")
	}
	return cs, err
}

func (s *staleStore) FindByLookup(ctx context.Context, l string) (port.MethodCredential, error) {
	return s.fakeStore.FindByLookup(ctx, l)
}

func (s *staleStore) Create(ctx context.Context, u, l string, d []byte) (port.MethodCredential, error) {
	return s.fakeStore.Create(ctx, u, l, d)
}

func (s *staleStore) Update(ctx context.Context, c port.MethodCredential, d []byte) (port.MethodCredential, error) {
	return s.fakeStore.Update(ctx, c, d)
}

func TestEnrollBeginRejects(t *testing.T) {
	ctx := context.Background()
	m, s := Method{}, &fakeStore{}
	for name, p := range map[string]any{
		"short secret": map[string]any{"secret": b32.EncodeToString(make([]byte, 10))},
		"not base32":   map[string]any{"secret": "!!!"},
		"digits":       map[string]any{"digits": 9},
	} {
		if _, err := m.EnrollBegin(ctx, env(s), port.MethodRequest{Payload: payload(t, p)}); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for range MaxCredentials {
		if _, err := s.Create(ctx, "usr_1", "", []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.EnrollBegin(ctx, env(s), port.MethodRequest{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	if _, err := m.Begin(ctx, port.MethodEnv{Credentials: s}, port.MethodRequest{}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("first factor: %v", err)
	}
}
