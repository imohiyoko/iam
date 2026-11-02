package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func spki(t testing.TB, k any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func TestParsePublicKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, alg, err := ParsePublicKey(spki(t, &ec.PublicKey)); err != nil || alg != AlgES256 {
		t.Fatalf("p256: %s %v", alg, err)
	}
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, alg, err := ParsePublicKey(spki(t, ed)); err != nil || alg != AlgEd25519 {
		t.Fatalf("ed25519: %s %v", alg, err)
	}
	// P-384・RSA・壊れた値は受けない（ADR 0005）。
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- 拒否されることを確かめるだけ
	for name, b64 := range map[string]string{"p384": spki(t, &p384.PublicKey), "rsa": spki(t, &rk.PublicKey), "garbage": "AAAA", "empty": "",
		"padding": spki(t, ed) + "=="} {
		if _, _, err := ParsePublicKey(b64); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestVerify(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg, ok := Message("respond", "chal", "dev_x", "approve", "42")
	if !ok {
		t.Fatal("message")
	}
	h := sha256.Sum256([]byte(msg))
	sig, _ := ecdsa.SignASN1(rand.Reader, ec, h[:])
	b64 := base64.RawURLEncoding.EncodeToString(sig)
	if !Verify(&ec.PublicKey, msg, b64) {
		t.Fatal("valid es256 signature rejected")
	}
	if Verify(&ec.PublicKey, msg+"x", b64) || Verify(&ec.PublicKey, msg, "") || Verify(&ec.PublicKey, msg, "!!") {
		t.Fatal("invalid es256 signature accepted")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	es := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	if !Verify(pub, msg, es) || Verify(pub, msg+"x", es) || Verify(&ec.PublicKey, msg, es) {
		t.Fatal("ed25519 verification")
	}
	// 区切り（|）を含む項目は署名する文字列にしない。
	if _, ok := Message("respond", "a|b"); ok {
		t.Fatal("separator accepted in a field")
	}
}

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

func (f *fakeStore) FindByLookup(_ context.Context, l string) (port.MethodCredential, error) {
	for _, c := range f.cs {
		var d data
		_ = json.Unmarshal(c.Data, &d)
		if d.DeviceID == l {
			return c, nil
		}
	}
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

func (f *fakeStore) Create(_ context.Context, userID, _ string, d []byte) (port.MethodCredential, error) {
	c := port.MethodCredential{ID: "c" + string(rune('0'+len(f.cs))), PublicID: "crd_" + string(rune('0'+len(f.cs))), UserID: userID, Data: d, Sealed: d}
	f.cs = append(f.cs, c)
	return c, nil
}

func (f *fakeStore) Update(_ context.Context, c port.MethodCredential, d []byte) (port.MethodCredential, error) {
	for i := range f.cs {
		if f.cs[i].ID == c.ID {
			f.cs[i].Data, f.cs[i].Sealed = d, d
			return f.cs[i], nil
		}
	}
	return c, errs.New(errs.KindConflict, "credential")
}

type outbox struct{ sent []port.PushMessage }

func (o *outbox) Send(_ context.Context, m port.PushMessage) error {
	o.sent = append(o.sent, m)
	return nil
}

func setup(t *testing.T) (Method, *outbox, *clock.Fake) {
	t.Helper()
	k := testkit.New(t)
	o := &outbox{}
	a, err := Method{}.Setup(context.Background(), port.MethodSetup{SMS: nil, Push: o, Clock: k.Clock,
		Ephemeral: method.Scoped(k.Cache, Name, "r1"), Options: map[string]string{"deny_limit": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	return a.(Method), o, k.Clock
}

func TestInfoAndSetup(t *testing.T) {
	if err := method.Check(Method{}); err != nil {
		t.Fatal(err)
	}
	if !(Method{}).Info().OutOfBand {
		t.Fatal("push must be out of band")
	}
	if _, err := (Method{}).Setup(context.Background(), port.MethodSetup{}); err == nil {
		t.Fatal("setup without a sender")
	}
	if _, err := (Method{}).Begin(context.Background(), port.MethodEnv{UserID: "u"}, port.MethodRequest{}); !errors.Is(err, errNotConfigured) {
		t.Fatalf("unconfigured: %v", err)
	}
	for _, bad := range []map[string]string{{"x": "1"}, {"challenge_ttl": "10m"}, {"deny_limit": "0"}, {"rate_window": "1s"}} {
		if _, err := parseOptions(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestEnrollRespondComplete(t *testing.T) {
	m, out, clk := setup(t)
	s := &fakeStore{}
	ctx := context.Background()
	env := func(user string) port.MethodEnv {
		return port.MethodEnv{RealmID: "r1", UserID: user, Credentials: s, Now: clk.Now()}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk := spki(t, pub)
	sign := func(kind string, fields ...string) string {
		msg, _ := Message(kind, fields...)
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	}
	ch, err := m.EnrollBegin(ctx, env("u1"), port.MethodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var st enrollState
	_ = json.Unmarshal(ch.State, &st)
	for name, p := range map[string]map[string]any{
		"bad token":  {"public_key": pk, "push_token": "has space", "signature": sign("enroll", st.Nonce, pk, TokenHash("has space"))},
		"bad name":   {"public_key": pk, "push_token": "t", "name": "a\nb", "signature": sign("enroll", st.Nonce, pk, TokenHash("t"))},
		"bad key":    {"public_key": "AAAA", "push_token": "t", "signature": sign("enroll", st.Nonce, "AAAA", TokenHash("t"))},
		"bad format": {"public_key": 1},
	} {
		raw, _ := json.Marshal(p)
		if _, err := m.EnrollComplete(ctx, env("u1"), port.MethodRequest{State: ch.State, Payload: raw}); !errors.Is(err, errs.Invalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	raw, _ := json.Marshal(map[string]any{"public_key": pk, "push_token": "tok", "signature": sign("enroll", st.Nonce, pk, TokenHash("tok"))})
	en, err := m.EnrollComplete(ctx, env("u1"), port.MethodRequest{State: ch.State, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(en.Payload, &dev)

	ch, err = m.Begin(ctx, env("u1"), port.MethodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	var shown struct{ Number string }
	_ = json.Unmarshal(ch.Payload, &shown)
	msg := out.sent[0]
	if msg.DeviceID != dev.DeviceID || msg.Token != "tok" {
		t.Fatalf("push: %+v", msg)
	}
	if _, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State}); !errors.Is(err, port.ErrMethodPending) {
		t.Fatalf("pending: %v", err)
	}
	respond := func(decision, number string) error {
		raw, _ := json.Marshal(map[string]any{"action": "respond", "device_id": dev.DeviceID, "challenge_id": msg.ChallengeID,
			"decision": decision, "number": number, "signature": sign("respond", msg.ChallengeID, dev.DeviceID, decision, number)})
		_, err := m.Callback(ctx, env(""), port.MethodRequest{Payload: raw})
		return err
	}
	// 別のユーザーの端末からは応答できない。
	s.cs[0].UserID = "u2"
	if err := respond("approve", shown.Number); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("other user's device: %v", err)
	}
	s.cs[0].UserID = "u1"
	if err := respond("approve", shown.Number); err != nil {
		t.Fatal(err)
	}
	r, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State})
	if err != nil || r.Credential.ID != en.Credential.ID {
		t.Fatalf("complete: %+v %v", r, err)
	}
	// 結果は1回だけ。期限の後は失敗。
	clk.Advance(3 * time.Minute)
	if _, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("second complete: %v", err)
	}

	// 拒否が deny_limit に達すると送らない。
	for range 2 {
		ch, err = m.Begin(ctx, env("u1"), port.MethodRequest{})
		if err != nil {
			t.Fatal(err)
		}
		_ = ch.Deliver(ctx)
		msg = out.sent[len(out.sent)-1]
		if err := respond("deny", "00"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("denied: %v", err)
		}
	}
	if _, err := m.Begin(ctx, env("u1"), port.MethodRequest{}); err == nil {
		t.Fatal("challenge sent after repeated denies")
	} else if _, ok := errors.AsType[*ratelimit.ExceededError](err); !ok {
		t.Fatalf("lockout: %v", err)
	}
}

// TestBackchannel は CIBA のチャレンジ（ADR 0114）：番号は無く、端末は context で中身を取り、"00" に署名して承認する。
// ログインのチャレンジを "00" で承認しても番号の違いになる。
func TestBackchannel(t *testing.T) {
	m, out, clk := setup(t)
	s := &fakeStore{}
	ctx := context.Background()
	env := func(user string) port.MethodEnv {
		return port.MethodEnv{RealmID: "r1", UserID: user, Credentials: s, Now: clk.Now()}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk := spki(t, pub)
	sign := func(kind string, fields ...string) string {
		msg, _ := Message(kind, fields...)
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	}
	ch, _ := m.EnrollBegin(ctx, env("u1"), port.MethodRequest{})
	var st enrollState
	_ = json.Unmarshal(ch.State, &st)
	raw, _ := json.Marshal(map[string]any{"public_key": pk, "push_token": "tok", "signature": sign("enroll", st.Nonce, pk, TokenHash("tok"))})
	en, err := m.EnrollComplete(ctx, env("u1"), port.MethodRequest{State: ch.State, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(en.Payload, &dev)
	req := port.BackchannelRequest{ClientName: "Bank", BindingMessage: "W4SCT", Scopes: []string{"openid"}, ExpiresAt: clk.Now().Add(5 * time.Minute)}

	// 端末が無い本人は NotFound。中身が不正なら Invalid。
	if _, err := m.BeginBackchannel(ctx, env("u9"), req); !errors.Is(err, errs.NotFound) {
		t.Fatalf("no device: %v", err)
	}
	bad := req
	bad.BindingMessage = "a\nb"
	if _, err := m.BeginBackchannel(ctx, env("u1"), bad); !errors.Is(err, errs.Invalid) {
		t.Fatalf("bad binding message: %v", err)
	}

	call := func(p map[string]any) (port.MethodCallbackResult, error) {
		raw, _ := json.Marshal(p)
		return m.Callback(ctx, env(""), port.MethodRequest{Payload: raw})
	}
	ch, err = m.BeginBackchannel(ctx, env("u1"), req)
	if err != nil || ch.Ref == "" {
		t.Fatalf("begin: %+v %v", ch, err)
	}
	if strings.Contains(string(ch.Payload), "number") {
		t.Fatalf("backchannel challenge has a number: %s", ch.Payload)
	}
	if err := ch.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	msg := out.sent[len(out.sent)-1]
	if msg.ChallengeID != ch.Ref {
		t.Fatalf("ref %q != challenge %q", ch.Ref, msg.ChallengeID)
	}
	// 中身は本人の端末の署名でだけ読める。
	if _, err := call(map[string]any{"action": "context", "device_id": dev.DeviceID, "challenge_id": msg.ChallengeID, "signature": sign("context", "x", dev.DeviceID)}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("context with a bad signature: %v", err)
	}
	res, err := call(map[string]any{"action": "context", "device_id": dev.DeviceID, "challenge_id": msg.ChallengeID, "signature": sign("context", msg.ChallengeID, dev.DeviceID)})
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Kind           string `json:"kind"`
		Client         string `json:"client"`
		BindingMessage string `json:"binding_message"`
	}
	_ = json.Unmarshal(res.Payload, &shown)
	if shown.Kind != "backchannel" || shown.Client != "Bank" || shown.BindingMessage != "W4SCT" {
		t.Fatalf("context: %s", res.Payload)
	}
	if _, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State}); !errors.Is(err, port.ErrMethodPending) {
		t.Fatalf("pending: %v", err)
	}
	res, err = call(map[string]any{"action": "respond", "device_id": dev.DeviceID, "challenge_id": msg.ChallengeID, "decision": "approve",
		"number": "00", "signature": sign("respond", msg.ChallengeID, dev.DeviceID, "approve", "00")})
	if err != nil || res.Ref != ch.Ref {
		t.Fatalf("respond: %+v %v", res, err)
	}
	r, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: ch.State})
	if err != nil || r.Credential.ID != en.Credential.ID {
		t.Fatalf("complete: %+v %v", r, err)
	}

	// ログインのチャレンジは "00" の承認では通らない（番号の違い）。応答の Ref は空。
	lch, err := m.Begin(ctx, env("u1"), port.MethodRequest{})
	if err != nil || lch.Ref != "" {
		t.Fatalf("login begin: %+v %v", lch, err)
	}
	_ = lch.Deliver(ctx)
	lmsg := out.sent[len(out.sent)-1]
	res, err = call(map[string]any{"action": "respond", "device_id": dev.DeviceID, "challenge_id": lmsg.ChallengeID, "decision": "approve",
		"number": "00", "signature": sign("respond", lmsg.ChallengeID, dev.DeviceID, "approve", "00")})
	if err != nil || res.Ref != "" {
		t.Fatalf("login respond: %+v %v", res, err)
	}
	if _, err := m.Complete(ctx, env("u1"), port.MethodRequest{State: lch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("login approved with 00: %v", err)
	}
	// 期限は要求の期限で、10 分を超えない。
	long := req
	long.ExpiresAt = clk.Now().Add(time.Hour)
	ch, err = m.BeginBackchannel(ctx, env("u1"), long)
	if err != nil {
		t.Fatal(err)
	}
	var ls loginState
	_ = json.Unmarshal(ch.State, &ls)
	if !ls.ExpiresAt.Equal(clk.Now().Add(maxBackchannelTTL)) {
		t.Fatalf("expiry: %v", ls.ExpiresAt)
	}
}

func FuzzParsePublicKey(f *testing.F) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	f.Add(spki(f, &ec.PublicKey), "c2ln")
	f.Add(spki(f, ed), "")
	f.Add("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE", "MEUCIQ")
	f.Fuzz(func(t *testing.T, key, sig string) {
		k, alg, err := ParsePublicKey(key)
		if err != nil {
			return
		}
		if alg != AlgES256 && alg != AlgEd25519 {
			t.Fatalf("unexpected alg %q", alg)
		}
		_ = Verify(k, "iam-push-v1|respond|a|b|approve|42", sig)
	})
}

func FuzzCallbackPayload(f *testing.F) {
	f.Add([]byte(`{"action":"respond","device_id":"dev_AAAAAAAAAAAAAAAAAAAAAA","challenge_id":"x","decision":"approve","number":"42","signature":"AA"}`))
	f.Add([]byte(`{"action":"token","device_id":"dev_AAAAAAAAAAAAAAAAAAAAAA","push_token":"t","timestamp":1,"signature":"AA"}`))
	f.Add([]byte(`{"action":"context","device_id":"dev_AAAAAAAAAAAAAAAAAAAAAA","challenge_id":"x","signature":"AA"}`))
	f.Add([]byte(`null`))
	k := testkit.New(f)
	a, err := Method{}.Setup(context.Background(), port.MethodSetup{Push: &outbox{}, Clock: k.Clock, Ephemeral: method.Scoped(k.Cache, Name, "r1")})
	if err != nil {
		f.Fatal(err)
	}
	m := a.(Method)
	f.Fuzz(func(t *testing.T, raw []byte) {
		// 署名の無い要求はどれも通らない（パニックせず、失敗で返す）。
		_, err := m.Callback(context.Background(), port.MethodEnv{RealmID: "r1", Credentials: &fakeStore{}, Now: k.Clock.Now()},
			port.MethodRequest{Payload: raw})
		if err == nil {
			t.Fatalf("callback accepted %q", raw)
		}
	})
}

func (f *fakeStore) Revoke(context.Context, port.MethodCredential, string) error { return nil }
