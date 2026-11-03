package ssf_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	issuer  = "https://iam.example.com/realms/test"
	txIss   = "https://signals.example.net"
	rpAud   = "https://iam.example.com/ssf/receiver"
	account = "sva_receiver"
)

// signer は SET を ES256 で署名するテスト用の鍵。
type signer struct {
	key  jwk.Key
	jwks []byte
}

func newSigner(t testing.TB, kid string) *signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := jwk.Import[jwk.Key](priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if kid != "" {
		_ = sk.Set(jwk.KeyIDKey, kid)
		_ = pk.Set(jwk.KeyIDKey, kid)
	}
	set := jwk.NewSet()
	_ = set.AddKey(pk)
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: sk, jwks: b}
}

func (s *signer) sign(t testing.TB, typ string, claims any) []byte {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.raw(typ, b)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

func (s *signer) raw(typ string, payload []byte) (string, error) {
	h := jws.NewHeaders()
	if err := h.Set(jws.TypeKey, typ); err != nil {
		return "", err
	}
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), s.key, jws.WithProtectedHeaders(h)))
	return string(out), err
}

// Sign は ssf.Signer（realm の鍵の代わり）。
func (s *signer) Sign(_ context.Context, _ port.Tx, _, _, typ string, claims []byte) (string, error) {
	return s.raw(typ, claims)
}

func (s *signer) keys(t testing.TB) jwk.Set {
	t.Helper()
	set, err := ssf.PublicKeys(s.jwks)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// directory は確認済みのメールの代わり。
type directory map[string]port.UserEmail

func (d directory) FindByEmail(_ context.Context, _ port.Tx, _, email string) (port.UserEmail, error) {
	e, ok := d[email]
	if !ok {
		return port.UserEmail{}, errs.NotFound
	}
	return e, nil
}

// effects は受けたイベントの動作を数える。
type effects struct {
	mu      sync.Mutex
	calls   []string
	fail    error
	refuse  bool
	applied int
}

func (e *effects) do(name string, u port.User) (func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		err := e.fail
		e.fail = nil
		return nil, err
	}
	e.calls = append(e.calls, name+":"+u.PublicID)
	return func() { e.mu.Lock(); e.applied++; e.mu.Unlock() }, nil
}

func (e *effects) RevokeSessions(_ context.Context, _ port.Tx, _ string, u port.User, _ audit.Actor, _ string) (func(), error) {
	return e.do("revoke_sessions", u)
}

func (e *effects) RevokePassword(_ context.Context, _ port.Tx, _ string, u port.User, _ audit.Actor, _ string) (func(), error) {
	return e.do("revoke_password", u)
}

func (e *effects) Suspend(_ context.Context, _ port.Tx, _ string, u port.User, _, _ string, _ audit.Actor, _ string) (func(), error) {
	if e.refuse {
		return nil, ssf.ErrNotApplied
	}
	return e.do("suspend", u)
}

type rxEnv struct {
	k     *testkit.Kit
	r     *ssf.Receiver
	fx    *effects
	key   *signer
	tid   string
	token string
	user  port.User
}

func newRxEnv(t *testing.T, actions ...string) *rxEnv {
	t.Helper()
	k := testkit.New(t)
	u := k.SeedUser(t)
	verified := testkit.T0
	unverified := k.SeedUser(t)
	dir := directory{
		"alice@example.com": {UserID: u.ID, VerifiedAt: &verified},
		"bob@example.com":   {UserID: unverified.ID},
	}
	fx := &effects{}
	r := &ssf.Receiver{Storage: k.Storage, Replay: k.Cache, Clock: k.Clock, Directory: dir, Effects: fx}
	key := newSigner(t, "tx-1")
	env := &rxEnv{k: k, r: r, fx: fx, key: key, user: u}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		tr, tok, err := r.CreateTransmitter(ctx, tx, k.RealmID, ssf.TransmitterInput{Name: "idp", Issuer: txIss, Enabled: true,
			TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks, Audience: []string{rpAud}, AllowedActions: actions}},
			audit.Actor{Type: "user", ID: "usr_op"}, "req_1")
		env.tid, env.token = tr.ID, tok
		return err
	})
	return env
}

func (e *rxEnv) claims(event string, sub any, payload map[string]any, edit func(map[string]any)) map[string]any {
	c := map[string]any{"iss": txIss, "aud": rpAud, "iat": e.k.Clock.Now().Unix(), "jti": "jti-" + event + time.Now().String(),
		"sub_id": sub, "events": map[string]any{event: payload}}
	if edit != nil {
		edit(c)
	}
	return c
}

func (e *rxEnv) receive(t *testing.T, body []byte) (ssf.Received, error) {
	t.Helper()
	return e.r.Receive(context.Background(), e.k.RealmID, e.tid, e.token, body, "req_rx")
}

var alice = map[string]any{"format": "email", "email": "Alice@Example.com"}

func rejected(t *testing.T, err error, status int, code string) {
	t.Helper()
	var re *ssf.ReceiveError
	if !errors.As(err, &re) || re.Status != status || re.Code != code {
		t.Fatalf("err = %v, want %d %s", err, status, code)
	}
}

func TestReceiveAppliesOnceAndRejectsReplay(t *testing.T) {
	e := newRxEnv(t, ssf.ActionRevokeSessions)
	body := e.key.sign(t, ssf.SETType, e.claims(ssf.EventSessionRevoked, alice, map[string]any{"event_timestamp": e.k.Clock.Now().Unix()}, nil))
	got, err := e.receive(t, body)
	if err != nil || got.Outcome != ssf.OutcomeApplied || got.Duplicate {
		t.Fatalf("receive = %+v, %v", got, err)
	}
	// 同じ jti は2度目に動かさない。
	got, err = e.receive(t, body)
	if err != nil || !got.Duplicate {
		t.Fatalf("replay = %+v, %v", got, err)
	}
	if len(e.fx.calls) != 1 || e.fx.calls[0] != "revoke_sessions:"+e.user.PublicID || e.fx.applied != 1 {
		t.Fatalf("calls = %v applied=%d", e.fx.calls, e.fx.applied)
	}
	var logged []audit.Event
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, e.k.RealmID, 0, 100)
		for _, r := range rs {
			ev, _ := audit.Unmarshal(r.Payload)
			if ev.Type == ssf.AuditSignalReceived {
				logged = append(logged, ev)
			}
		}
		return err
	})
	if len(logged) != 1 || logged[0].Details["outcome"] != ssf.OutcomeApplied || logged[0].Details["user_id"] != e.user.PublicID {
		t.Fatalf("audit = %+v", logged)
	}
}

func TestReceiveNegative(t *testing.T) {
	e := newRxEnv(t, ssf.ActionRevokeSessions)
	now := e.k.Clock.Now()
	other := newSigner(t, "tx-1")
	ev := map[string]any{}
	set := func(edit func(map[string]any)) []byte {
		return e.key.sign(t, ssf.SETType, e.claims(ssf.EventSessionRevoked, alice, ev, edit))
	}
	cases := []struct {
		name   string
		body   []byte
		token  string
		status int
		code   string
	}{
		{"bad signature", other.sign(t, ssf.SETType, e.claims(ssf.EventSessionRevoked, alice, ev, nil)), "", 400, "invalid_key"},
		{"wrong aud", set(func(c map[string]any) { c["aud"] = "https://other.example.com" }), "", 400, "invalid_audience"},
		{"aud list without ours", set(func(c map[string]any) { c["aud"] = []string{"a", "b"} }), "", 400, "invalid_audience"},
		{"missing aud", set(func(c map[string]any) { delete(c, "aud") }), "", 400, "invalid_audience"},
		{"wrong iss", set(func(c map[string]any) { c["iss"] = "https://evil.example.com" }), "", 400, "invalid_issuer"},
		{"too old", set(func(c map[string]any) { c["iat"] = now.Add(-25 * time.Hour).Unix() }), "", 400, "invalid_request"},
		{"future", set(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }), "", 400, "invalid_request"},
		{"expired", set(func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }), "", 400, "invalid_request"},
		{"no jti", set(func(c map[string]any) { delete(c, "jti") }), "", 400, "invalid_request"},
		{"two events", set(func(c map[string]any) {
			c["events"] = map[string]any{ssf.EventSessionRevoked: ev, ssf.EventCredentialChange: ev}
		}), "", 400, "invalid_request"},
		{"no subject", set(func(c map[string]any) { delete(c, "sub_id") }), "", 400, "invalid_request"},
		{"bad subject", set(func(c map[string]any) { c["sub_id"] = map[string]any{"format": "email"} }), "", 400, "invalid_request"},
		{"wrong typ", e.key.sign(t, "JWT", e.claims(ssf.EventSessionRevoked, alice, ev, nil)), "", 400, "invalid_request"},
		{"not a JWS", []byte("not.a.jws"), "", 400, "invalid_request"},
		{"alg none", []byte("eyJhbGciOiJub25lIiwidHlwIjoic2VjZXZlbnQrand0In0.e30."), "", 400, "invalid_key"},
		{"bad token", set(nil), "ssfpt_wrong", 401, "authentication_failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := e.token
			if c.token != "" {
				tok = c.token
			}
			_, err := e.r.Receive(context.Background(), e.k.RealmID, e.tid, tok, c.body, "req")
			rejected(t, err, c.status, c.code)
		})
	}
	if _, err := e.r.Receive(context.Background(), e.k.RealmID, "stx_unknown", e.token, set(nil), "req"); err == nil {
		t.Fatal("unknown transmitter accepted")
	} else {
		rejected(t, err, 401, "authentication_failed")
	}
	if len(e.fx.calls) != 0 {
		t.Fatalf("rejected SETs had effects: %v", e.fx.calls)
	}
	// 止めた登録は受けない。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		tr, err := tx.SSFTransmitters().Get(ctx, e.k.RealmID, e.tid)
		if err != nil {
			return err
		}
		cfg, _ := ssf.ConfigOf(tr)
		_, _, err = e.r.UpdateTransmitter(ctx, tx, e.k.RealmID, e.tid, ssf.TransmitterInput{Name: tr.Name, Issuer: tr.Issuer, Enabled: false,
			TransmitterConfig: cfg}, false, audit.Actor{Type: "user", ID: "usr_op"}, "req")
		return err
	})
	_, err := e.receive(t, set(nil))
	rejected(t, err, 401, "authentication_failed")
}

func TestReceiveOutcomes(t *testing.T) {
	e := newRxEnv(t, ssf.ActionRevokeSessions, ssf.ActionRecordDevicePosture, ssf.ActionSuspendUser)
	ev := map[string]any{}
	n := 0
	send := func(event string, sub any, payload map[string]any) (ssf.Received, error) {
		n++
		c := e.claims(event, sub, payload, func(c map[string]any) { c["jti"] = "j" + string(rune('a'+n)) })
		return e.receive(t, e.key.sign(t, ssf.SETType, c))
	}
	for name, sub := range map[string]any{
		"unknown email":              map[string]any{"format": "email", "email": "nobody@example.com"},
		"unverified email":           map[string]any{"format": "email", "email": "bob@example.com"},
		"iss_sub without connection": map[string]any{"format": "iss_sub", "iss": txIss, "sub": e.user.PublicID},
		"opaque":                     map[string]any{"format": "opaque", "id": e.user.PublicID},
	} {
		got, err := send(ssf.EventSessionRevoked, sub, ev)
		if err != nil || got.Outcome != ssf.OutcomeUnknownSubject {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// 許していない動作はしない（パスワードの無効化）。password 以外の credential-compromise は動作が無い。
	if got, err := send(ssf.EventCredentialCompromise, alice, map[string]any{"credential_type": "password"}); err != nil || got.Outcome != ssf.OutcomeNotAllowed {
		t.Errorf("not allowed: %+v, %v", got, err)
	}
	if got, err := send(ssf.EventCredentialCompromise, alice, map[string]any{"credential_type": "fido2-roaming"}); err != nil || got.Outcome != ssf.OutcomeIgnored {
		t.Errorf("other credential: %+v, %v", got, err)
	}
	if got, err := send("https://schemas.example.com/unknown", alice, ev); err != nil || got.Outcome != ssf.OutcomeIgnored {
		t.Errorf("unknown event: %+v, %v", got, err)
	}
	// 最後の所有者などで止められないときは refused。
	e.fx.refuse = true
	if got, err := send(ssf.EventAccountDisabled, alice, ev); err != nil || got.Outcome != ssf.OutcomeRefused {
		t.Errorf("refused: %+v, %v", got, err)
	}
	e.fx.refuse = false
	if got, err := send(ssf.EventAccountDisabled, alice, map[string]any{"reason": "hijacking"}); err != nil || got.Outcome != ssf.OutcomeApplied {
		t.Errorf("suspend: %+v, %v", got, err)
	}
	if !slices.Equal(e.fx.calls, []string{"suspend:" + e.user.PublicID}) {
		t.Fatalf("calls = %v", e.fx.calls)
	}

	// 動作に失敗した SET は、送り直しで動かす（jti を覚えない）。
	e.fx.fail = errors.New("boom")
	body := e.key.sign(t, ssf.SETType, e.claims(ssf.EventSessionRevoked, alice, ev, func(c map[string]any) { c["jti"] = "retry" }))
	if _, err := e.receive(t, body); err == nil {
		t.Fatal("effects failure not reported")
	}
	if got, err := e.receive(t, body); err != nil || got.Outcome != ssf.OutcomeApplied || got.Duplicate {
		t.Fatalf("retry = %+v, %v", got, err)
	}

	// 端末の状態：新しい知らせで上書きし、古い知らせでは上書きしない。端末の無い対象は読めない。
	t0 := e.k.Clock.Now()
	device := func(status string, at time.Time) (ssf.Received, error) {
		return send(ssf.EventDeviceComplianceChange, map[string]any{"format": "complex",
			"user":   map[string]any{"format": "email", "email": "alice@example.com"},
			"device": map[string]any{"format": "opaque", "id": "laptop-1"}},
			map[string]any{"current_status": status, "previous_status": "compliant", "event_timestamp": at.Unix()})
	}
	if got, err := device("not-compliant", t0); err != nil || got.Outcome != ssf.OutcomeApplied {
		t.Fatalf("posture: %+v, %v", got, err)
	}
	if got, err := device("compliant", t0.Add(-time.Minute)); err != nil || got.Outcome != ssf.OutcomeStale {
		t.Fatalf("stale posture: %+v, %v", got, err)
	}
	if got, err := device("unknown-status", t0); err != nil || got.Outcome != ssf.OutcomeUnknownSubject {
		t.Fatalf("bad posture: %+v, %v", got, err)
	}
	if got, err := send(ssf.EventDeviceComplianceChange, alice, map[string]any{"current_status": "compliant"}); err != nil || got.Outcome != ssf.OutcomeUnknownSubject {
		t.Fatalf("posture without device: %+v, %v", got, err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		p, err := tx.DevicePostures().Get(ctx, e.k.RealmID, e.user.ID, "laptop-1")
		if err != nil {
			return err
		}
		if p.Status != port.DeviceNotCompliant || p.Source != e.tid || !p.EventAt.Equal(t0.Truncate(time.Second)) {
			t.Errorf("posture = %+v", p)
		}
		return nil
	})
	// 登録を消すと、その送信側からの端末の状態も消える。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := e.r.DeleteTransmitter(ctx, tx, e.k.RealmID, e.tid, audit.Actor{Type: "user", ID: "usr_op"}, "req"); err != nil {
			return err
		}
		if _, err := tx.DevicePostures().Get(ctx, e.k.RealmID, e.user.ID, "laptop-1"); !errors.Is(err, errs.NotFound) {
			t.Errorf("posture after delete: %v", err)
		}
		return nil
	})
}

func TestTransmitterRegistration(t *testing.T) {
	k := testkit.New(t)
	r := &ssf.Receiver{Storage: k.Storage, Replay: k.Cache, Clock: k.Clock}
	key := newSigner(t, "")
	op := audit.Actor{Type: "user", ID: "usr_op"}
	priv, _ := json.Marshal(map[string]any{"keys": []any{json.RawMessage(mustPrivate(t))}})
	for name, in := range map[string]ssf.TransmitterInput{
		"no keys":      {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{Audience: []string{rpAud}}},
		"both keys":    {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks, JWKSURI: "https://idp.example.com/jwks", Audience: []string{rpAud}}},
		"http jwks":    {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKSURI: "http://idp.example.com/jwks", Audience: []string{rpAud}}},
		"private jwks": {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKSURI: "https://10.0.0.1/jwks", Audience: []string{rpAud}}},
		"private key":  {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: priv, Audience: []string{rpAud}}},
		"no audience":  {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks}},
		"bad action":   {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks, Audience: []string{rpAud}, AllowedActions: []string{"delete_user"}}},
		"no name":      {Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks, Audience: []string{rpAud}}},
		"bad connection": {Name: "x", Issuer: txIss, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks, Audience: []string{rpAud},
			SubjectConnection: "nope"}},
	} {
		k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			if _, _, err := r.CreateTransmitter(ctx, tx, k.RealmID, in, op, "req"); !errors.Is(err, errs.Invalid) {
				t.Errorf("%s: %v, want Invalid", name, err)
			}
			return nil
		})
	}
	in := ssf.TransmitterInput{Name: "idp", Issuer: txIss, Enabled: true, TransmitterConfig: ssf.TransmitterConfig{JWKS: key.jwks,
		Audience: []string{rpAud}, AllowedActions: []string{ssf.ActionSuspendUser, ssf.ActionRevokeSessions, ssf.ActionSuspendUser}}}
	var tid, tok string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		tr, tk, err := r.CreateTransmitter(ctx, tx, k.RealmID, in, op, "req")
		if err != nil {
			return err
		}
		tid, tok = tr.ID, tk
		cfg, _ := ssf.ConfigOf(tr)
		if !slices.Equal(cfg.AllowedActions, []string{ssf.ActionRevokeSessions, ssf.ActionSuspendUser}) {
			t.Errorf("allowed_actions = %v", cfg.AllowedActions)
		}
		if _, _, err := r.CreateTransmitter(ctx, tx, k.RealmID, in, op, "req"); !errors.Is(err, errs.Conflict) {
			t.Errorf("duplicate issuer: %v", err)
		}
		return nil
	})
	// 作り直した push の値だけが通る。
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, tk, err := r.UpdateTransmitter(ctx, tx, k.RealmID, tid, in, true, op, "req")
		if tk == "" || tk == tok {
			t.Errorf("rotate returned %q", tk)
		}
		tok = tk
		return err
	})
	body := key.sign(t, ssf.SETType, map[string]any{"iss": txIss, "aud": rpAud, "iat": k.Clock.Now().Unix(), "jti": "1",
		"sub_id": alice, "events": map[string]any{"https://schemas.example.com/x": map[string]any{}}})
	if got, err := r.Receive(context.Background(), k.RealmID, tid, tok, body, "req"); err != nil || got.Outcome != ssf.OutcomeIgnored {
		t.Fatalf("receive = %+v, %v", got, err)
	}
}

func mustPrivate(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReceiveJWKSURI(t *testing.T) {
	key := newSigner(t, "k1")
	var fetches int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fetches++
		mu.Unlock()
		_, _ = w.Write(key.jwks)
	}))
	defer srv.Close()
	k := testkit.New(t)
	r := &ssf.Receiver{Storage: k.Storage, Replay: k.Cache, Clock: k.Clock, Dev: true, AllowPrivateNetworks: true, HTTP: srv.Client(), Effects: &effects{}}
	var tid, tok string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		tr, tk, err := r.CreateTransmitter(ctx, tx, k.RealmID, ssf.TransmitterInput{Name: "idp", Issuer: txIss, Enabled: true,
			TransmitterConfig: ssf.TransmitterConfig{JWKSURI: srv.URL + "/jwks", Audience: []string{rpAud}}}, audit.Actor{Type: "user", ID: "u"}, "r")
		tid, tok = tr.ID, tk
		return err
	})
	for i := range 3 {
		body := key.sign(t, ssf.SETType, map[string]any{"iss": txIss, "aud": []string{rpAud}, "iat": k.Clock.Now().Unix(),
			"jti": string(rune('a' + i)), "sub_id": alice, "events": map[string]any{ssf.EventSessionRevoked: map[string]any{}}})
		if got, err := r.Receive(context.Background(), k.RealmID, tid, tok, body, "req"); err != nil || got.Outcome != ssf.OutcomeUnknownSubject {
			t.Fatalf("receive %d = %+v, %v", i, got, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("jwks fetched %d times, want 1 (cached)", fetches)
	}
	// 知らない kid は、取り直したばかりの鍵では確かめない（取り直しは1分に1度まで）。
	other := newSigner(t, "k2")
	body := other.sign(t, ssf.SETType, map[string]any{"iss": txIss, "aud": rpAud, "iat": k.Clock.Now().Unix(), "jti": "z",
		"sub_id": alice, "events": map[string]any{ssf.EventSessionRevoked: map[string]any{}}})
	_, err := r.Receive(context.Background(), k.RealmID, tid, tok, body, "req")
	rejected(t, err, 400, "invalid_key")
}

func TestParseClaims(t *testing.T) {
	now := testkit.T0
	ok := map[string]any{"iss": txIss, "aud": rpAud, "iat": now.Unix(), "jti": "1", "txn": "t",
		"events": map[string]any{ssf.EventAccountDisabled: map[string]any{"subject": map[string]any{"format": "email", "email": "a@example.com"}}}}
	b, _ := json.Marshal(ok)
	set, err := ssf.ParseClaims(b, now, time.Hour)
	if err != nil || set.Subject == nil || set.Subject.Email != "a@example.com" || set.Event != ssf.EventAccountDisabled || !slices.Equal(set.Audience, []string{rpAud}) {
		t.Fatalf("legacy subject: %+v, %v", set, err)
	}
	if !set.EventTime().Equal(now) {
		t.Errorf("EventTime = %v", set.EventTime())
	}
	for _, bad := range []string{
		`{}`, `[]`, `{"iss":"x"} {}`,
		`{"iss":"x","aud":"a","iat":1,"jti":"1","sub_id":{"format":"opaque","id":"1"},"events":{"e":{}}}`,
		`{"iss":"x","aud":"a","iat":"now","jti":"1","sub_id":{"format":"opaque","id":"1"},"events":{"e":{}}}`,
		`{"iss":"x","aud":1,"iat":` + itoa(now.Unix()) + `,"jti":"1","sub_id":{"format":"opaque","id":"1"},"events":{"e":{}}}`,
		`{"iss":"x","aud":"a","iat":` + itoa(now.Unix()) + `,"jti":"1","sub_id":{"format":"opaque","id":"1"},"events":{"e":null}}`,
		`{"iss":"x","aud":"a","iat":` + itoa(now.Unix()) + `,"jti":"1","sub_id":{"format":"complex","user":{"format":"complex","user":{"format":"opaque","id":"1"}}},"events":{"e":{}}}`,
		`{"iss":"x","aud":"a","iat":` + itoa(now.Unix()) + `,"jti":"1","sub_id":{"format":"bogus","id":"1"},"events":{"e":{}}}`,
	} {
		if _, err := ssf.ParseClaims([]byte(bad), now, time.Hour); err == nil {
			t.Errorf("ParseClaims(%s) accepted", bad)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// ----------------------------------------------------------------------------
// 送信側

var receiver = ssf.Caller{AccountID: account, RequestID: "req_rx"}

type txEnv struct {
	k   *testkit.Kit
	tr  *ssf.Transmitter
	key *signer
}

func newTxEnv(t *testing.T) *txEnv {
	k := testkit.New(t)
	key := newSigner(t, "")
	return &txEnv{k: k, key: key, tr: &ssf.Transmitter{Crypter: k.Crypter, Clock: k.Clock, Keys: key, Dev: true, AllowPrivateNetworks: true}}
}

func (e *txEnv) record(t *testing.T, ev audit.Event) {
	t.Helper()
	ev.RealmID, ev.Result = e.k.RealmID, audit.ResultSuccess
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, e.k.Clock, ev)
		return err
	})
}

func (e *txEnv) poll(t *testing.T, streamID string, req ssf.PollRequest) ssf.PollResponse {
	t.Helper()
	var out ssf.PollResponse
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = e.tr.Poll(ctx, tx, e.k.RealmID, issuer, receiver, streamID, req, nil)
		return err
	})
	return out
}

// decode は SET を確かめて読む。
func (e *txEnv) decode(t *testing.T, compact string) ssf.SET {
	t.Helper()
	h, err := ssf.ParseHeader([]byte(compact))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ssf.VerifySignature([]byte(compact), h, e.key.keys(t))
	if err != nil {
		t.Fatal(err)
	}
	set, err := ssf.ParseClaims(payload, e.k.Clock.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func events(t *testing.T, e *txEnv, sets map[string]string) map[string]ssf.SET {
	t.Helper()
	out := map[string]ssf.SET{}
	for jti, s := range sets {
		set := e.decode(t, s)
		if set.JTI != jti {
			t.Fatalf("jti %s != %s", set.JTI, jti)
		}
		out[set.Event] = set
	}
	return out
}

func TestTransmitterPoll(t *testing.T) {
	e := newTxEnv(t)
	u, v := e.k.SeedUser(t), e.k.SeedUser(t)
	reqd := []string{ssf.EventSessionRevoked, ssf.EventCredentialChange, ssf.EventAccountPurged, "https://schemas.example.com/x"}
	var s port.SSFStream
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		s, err = e.tr.Create(ctx, tx, e.k.RealmID, receiver, ssf.StreamInput{Delivery: &ssf.Delivery{Method: ssf.DeliveryPollURN}, EventsRequested: &reqd})
		if err != nil {
			return err
		}
		if len(s.EventsDelivered) != 3 || slices.Contains(s.EventsDelivered, "https://schemas.example.com/x") {
			t.Errorf("events_delivered = %v", s.EventsDelivered)
		}
		// ほかの受信側には見えない。
		if _, err := e.tr.Get(ctx, tx, e.k.RealmID, ssf.Caller{AccountID: "sva_other"}, s.ID); !errors.Is(err, errs.NotFound) {
			t.Errorf("other receiver: %v", err)
		}
		if err := e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatIssSub, Iss: issuer, Sub: u.PublicID}); err != nil {
			return err
		}
		if err := e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatIssSub, Iss: issuer, Sub: "usr_nobody"}); !errors.Is(err, errs.NotFound) {
			t.Errorf("unknown subject: %v", err)
		}
		if err := e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatIssSub, Iss: "https://other", Sub: u.PublicID}); !errors.Is(err, errs.NotFound) {
			t.Errorf("foreign iss: %v", err)
		}
		if err := e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatEmail}); !errors.Is(err, errs.Invalid) {
			t.Errorf("invalid subject: %v", err)
		}
		return nil
	})
	// 対象の出来事だけ、求めたイベントだけを送る。入れ替えによる失効は送らない。
	e.record(t, audit.Event{Type: "session.revoked", Actor: audit.Actor{Type: "user", ID: "usr_admin"}, Details: map[string]any{"user_id": u.PublicID, "reason": "admin"}})
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": u.PublicID, "reason": "rotated"}})
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": v.PublicID}})
	e.record(t, audit.Event{Type: "passkey.registered", Actor: audit.Actor{Type: "user", ID: u.PublicID}})
	e.record(t, audit.Event{Type: "user.suspended", Details: map[string]any{"user_id": u.PublicID, "starts_at": e.k.Clock.Now().Format(time.RFC3339Nano)}})

	got := e.poll(t, s.ID, ssf.PollRequest{})
	if len(got.Sets) != 2 || got.MoreAvailable {
		t.Fatalf("poll = %+v", got)
	}
	sets := events(t, e, got.Sets)
	sr := sets[ssf.EventSessionRevoked]
	if sr.Issuer != issuer || !slices.Equal(sr.Audience, []string{account}) || sr.Subject.Format != ssf.FormatIssSub || sr.Subject.Sub != u.PublicID {
		t.Fatalf("session-revoked = %+v", sr)
	}
	if sr.Payload["initiating_entity"] != "admin" {
		t.Errorf("initiating_entity = %v", sr.Payload["initiating_entity"])
	}
	cc := sets[ssf.EventCredentialChange]
	if cc.String("credential_type") != "fido2-platform" || cc.String("change_type") != "create" {
		t.Errorf("credential-change = %+v", cc.Payload)
	}
	// 確認するまでは同じ SET を返す。maxEvents で絞れる。
	one := 1
	again := e.poll(t, s.ID, ssf.PollRequest{MaxEvents: &one})
	if len(again.Sets) != 1 || !again.MoreAvailable {
		t.Fatalf("poll again = %+v", again)
	}
	var acks []string
	for jti := range got.Sets {
		acks = append(acks, jti)
	}
	errsIn := map[string]ssf.SetError{acks[1]: {Err: "invalid_key"}}
	if after := e.poll(t, s.ID, ssf.PollRequest{Ack: acks[:1], SetErrs: errsIn}); len(after.Sets) != 0 {
		t.Fatalf("after ack = %+v", after)
	}

	// 検証のイベント（state を返す）。止めている間は積まず、paused から戻すとその間の出来事も送る。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := e.tr.RequestVerification(ctx, tx, e.k.RealmID, receiver, s.ID, "st-1"); err != nil {
			return err
		}
		_, err := e.tr.SetStatus(ctx, tx, e.k.RealmID, receiver, ssf.StreamStatus{StreamID: s.ID, Status: port.SSFStatusPaused})
		return err
	})
	e.record(t, audit.Event{Type: "password.removed", Details: map[string]any{"user_id": u.PublicID}})
	if paused := e.poll(t, s.ID, ssf.PollRequest{}); len(paused.Sets) != 0 {
		t.Fatalf("paused poll = %+v", paused)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.tr.SetStatus(ctx, tx, e.k.RealmID, receiver, ssf.StreamStatus{StreamID: s.ID, Status: port.SSFStatusEnabled})
		return err
	})
	resumed := events(t, e, e.poll(t, s.ID, ssf.PollRequest{}).Sets)
	vf, ok := resumed[ssf.EventVerification]
	if !ok || vf.String("state") != "st-1" || vf.Subject.Format != ssf.FormatOpaque || vf.Subject.ID != s.ID {
		t.Fatalf("verification = %+v", resumed)
	}
	if _, ok := resumed[ssf.EventCredentialChange]; !ok {
		t.Fatalf("event during pause lost: %v", resumed)
	}
	// paused と enabled の2つの stream-updated（同じイベントの名前なので、ここではどちらかを見る）。
	if su, ok := resumed[ssf.EventStreamUpdated]; !ok || (su.String("status") != port.SSFStatusEnabled && su.String("status") != port.SSFStatusPaused) {
		t.Fatalf("stream-updated = %+v", resumed)
	}

	// account-purged を送ると、対象から外す。
	e.record(t, audit.Event{Type: "user.deleted", Details: map[string]any{"user_id": u.PublicID}})
	purged := events(t, e, e.poll(t, s.ID, ssf.PollRequest{}).Sets)
	if _, ok := purged[ssf.EventAccountPurged]; !ok {
		t.Fatalf("account-purged = %v", purged)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if ok, err := tx.SSFStreams().HasSubject(ctx, e.k.RealmID, s.ID, u.PublicID); err != nil || ok {
			t.Errorf("subject kept after purge: %v %v", ok, err)
		}
		return nil
	})
}

func TestTransmitterLimitsAndValidation(t *testing.T) {
	e := newTxEnv(t)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for name, in := range map[string]ssf.StreamInput{
			"no delivery":    {},
			"bad method":     {Delivery: &ssf.Delivery{Method: "urn:example:x"}},
			"http push":      {Delivery: &ssf.Delivery{Method: ssf.DeliveryPushURN, EndpointURL: "ftp://x"}},
			"poll auth":      {Delivery: &ssf.Delivery{Method: ssf.DeliveryPollURN, AuthorizationHeader: "Bearer x"}},
			"header newline": {Delivery: &ssf.Delivery{Method: ssf.DeliveryPushURN, EndpointURL: "https://rp.example.com/", AuthorizationHeader: "a\r\nb"}},
		} {
			if _, err := e.tr.Create(ctx, tx, e.k.RealmID, receiver, in); !errors.Is(err, errs.Invalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		strict := &ssf.Transmitter{Crypter: e.k.Crypter, Clock: e.k.Clock, Keys: e.key}
		for _, u := range []string{"http://rp.example.com/", "https://127.0.0.1/", "https://169.254.169.254/"} {
			if _, err := strict.Create(ctx, tx, e.k.RealmID, receiver, ssf.StreamInput{Delivery: &ssf.Delivery{Method: ssf.DeliveryPushURN, EndpointURL: u}}); !errors.Is(err, errs.Invalid) {
				t.Errorf("push to %s: %v", u, err)
			}
		}
		for i := range ssf.MaxStreamsPerReceiver + 1 {
			_, err := e.tr.Create(ctx, tx, e.k.RealmID, receiver, ssf.StreamInput{Delivery: &ssf.Delivery{Method: ssf.DeliveryPollURN}})
			if i < ssf.MaxStreamsPerReceiver && err != nil {
				return err
			}
			if i == ssf.MaxStreamsPerReceiver && !errors.Is(err, errs.Conflict) {
				t.Errorf("limit: %v", err)
			}
		}
		return nil
	})
}

func TestPushDelivery(t *testing.T) {
	e := newTxEnv(t)
	u := e.k.SeedUser(t)
	var mu sync.Mutex
	var bodies []string
	var auths []string
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Content-Type") != "application/secevent+jwt" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		bodies, auths = append(bodies, string(b)), append(auths, r.Header.Get("Authorization"))
		w.WriteHeader(status)
		if status == http.StatusBadRequest {
			_, _ = w.Write([]byte(`{"err":"invalid_audience","description":"x"}`))
		}
	}))
	defer srv.Close()
	d := &ssf.Deliverer{Storage: e.k.Storage, Transmitter: e.tr, Clock: e.k.Clock, Interval: time.Second, HTTP: srv.Client(),
		Issuer: func(context.Context, port.Tx, string) (string, error) { return issuer, nil }}
	reqd := []string{ssf.EventSessionRevoked}
	var s port.SSFStream
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		s, err = e.tr.Create(ctx, tx, e.k.RealmID, receiver, ssf.StreamInput{EventsRequested: &reqd,
			Delivery: &ssf.Delivery{Method: ssf.DeliveryPushURN, EndpointURL: srv.URL + "/events", AuthorizationHeader: "Bearer rx-secret"}})
		if err != nil {
			return err
		}
		return e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatIssSub, Iss: issuer, Sub: u.PublicID})
	})
	stream := func() port.SSFStream {
		var got port.SSFStream
		e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			var err error
			got, err = tx.SSFStreams().Get(ctx, e.k.RealmID, s.ID)
			return err
		})
		return got
	}
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": u.PublicID}})
	if n, err := d.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("flush = %d, %v", n, err)
	}
	if len(bodies) != 1 || auths[0] != "Bearer rx-secret" {
		t.Fatalf("pushed %d, auth %v", len(bodies), auths)
	}
	first := e.decode(t, bodies[0])
	if first.Event != ssf.EventSessionRevoked || first.Subject.Sub != u.PublicID {
		t.Fatalf("pushed SET = %+v", first)
	}

	// 送れなければ位置を進めず、時間を置いて同じ jti で送り直す。
	status = http.StatusServiceUnavailable
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": u.PublicID}})
	e.k.Clock.Advance(2 * time.Second)
	if n, err := d.Flush(context.Background()); err != nil || n != 0 {
		t.Fatalf("failing flush = %d, %v", n, err)
	}
	st := stream()
	if st.Failures != 1 || st.LastError == "" || st.NextAttemptAt == nil || !st.NextAttemptAt.After(e.k.Clock.Now()) {
		t.Fatalf("after failure = %+v", st.SSFStreamDelivery)
	}
	if n, _ := d.Flush(context.Background()); n != 0 || len(bodies) != 2 {
		t.Fatalf("retried before backoff: %d", len(bodies))
	}
	status = http.StatusAccepted
	e.k.Clock.Advance(time.Minute)
	if n, err := d.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("retry flush = %d, %v", n, err)
	}
	if e.decode(t, bodies[1]).JTI != e.decode(t, bodies[2]).JTI {
		t.Fatal("retry changed the jti")
	}
	if st := stream(); st.Failures != 0 || st.LastError != "" {
		t.Fatalf("after retry = %+v", st.SSFStreamDelivery)
	}

	// 400 は送り直さない。
	status = http.StatusBadRequest
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": u.PublicID}})
	e.k.Clock.Advance(2 * time.Second)
	if _, err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := stream(); st.Failures != 0 || st.LastError != "rejected_invalid_audience" {
		t.Fatalf("after 400 = %+v", st.SSFStreamDelivery)
	}
	e.k.Clock.Advance(2 * time.Second)
	before := len(bodies)
	if _, err := d.Flush(context.Background()); err != nil || len(bodies) != before {
		t.Fatalf("rejected SET resent: %v", err)
	}
}

// TestRoundTrip は送信側が push した SET を、同じ鍵を登録した受信側で受ける。
func TestRoundTrip(t *testing.T) {
	e := newTxEnv(t)
	u := e.k.SeedUser(t)
	fx := &effects{}
	verified := testkit.T0
	rx := &ssf.Receiver{Storage: e.k.Storage, Replay: e.k.Cache, Clock: e.k.Clock, Effects: fx,
		Directory: directory{"alice@example.com": {UserID: u.ID, VerifiedAt: &verified}}}
	var tid, tok string
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		tr, tk, err := rx.CreateTransmitter(ctx, tx, e.k.RealmID, ssf.TransmitterInput{Name: "self", Issuer: issuer, Enabled: true,
			TransmitterConfig: ssf.TransmitterConfig{JWKS: e.key.jwks, Audience: []string{account}, AllowedActions: []string{ssf.ActionRevokeSessions}}},
			audit.Actor{Type: "user", ID: "u"}, "r")
		tid, tok = tr.ID, tk
		return err
	})
	var outcomes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bearer := r.Header.Get("Authorization")[len("Bearer "):]
		got, err := rx.Receive(r.Context(), e.k.RealmID, tid, bearer, b, "req")
		if err != nil {
			t.Errorf("receive: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		outcomes = append(outcomes, got.Outcome)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	reqd := []string{ssf.EventSessionRevoked}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		s, err := e.tr.Create(ctx, tx, e.k.RealmID, receiver, ssf.StreamInput{EventsRequested: &reqd,
			Delivery: &ssf.Delivery{Method: ssf.DeliveryPushURN, EndpointURL: srv.URL, AuthorizationHeader: "Bearer " + tok}})
		if err != nil {
			return err
		}
		return e.tr.AddSubject(ctx, tx, e.k.RealmID, issuer, receiver, s.ID, &ssf.Subject{Format: ssf.FormatIssSub, Iss: issuer, Sub: u.PublicID})
	})
	e.record(t, audit.Event{Type: "session.revoked", Details: map[string]any{"user_id": u.PublicID}})
	d := &ssf.Deliverer{Storage: e.k.Storage, Transmitter: e.tr, Clock: e.k.Clock, Interval: time.Second, HTTP: srv.Client(),
		Issuer: func(context.Context, port.Tx, string) (string, error) { return issuer, nil }}
	if n, err := d.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("flush = %d, %v", n, err)
	}
	// 受信側は外の送信側の iss_sub を connection なしには結び付けない。
	if !slices.Equal(outcomes, []string{ssf.OutcomeUnknownSubject}) {
		t.Fatalf("outcomes = %v", outcomes)
	}
}
