package openid4vp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt/sdjwttest"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	base = "https://id.example/realms/r1"
	vct  = "urn:eudi:pid:1"
)

// store は検索キーを持つ port.CredentialStore のテスト用の実装（暗号化しない）。
type store struct {
	creds   []port.MethodCredential
	lookups map[string]string // lookup → ID
	n       int
}

func (s *store) List(_ context.Context, userID string) ([]port.MethodCredential, error) {
	var out []port.MethodCredential
	for _, c := range s.creds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *store) FindByLookup(_ context.Context, lookup string) (port.MethodCredential, error) {
	for _, c := range s.creds {
		if s.lookups[lookup] == c.ID {
			return c, nil
		}
	}
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

func (s *store) Create(_ context.Context, userID, lookup string, data []byte) (port.MethodCredential, error) {
	if s.lookups == nil {
		s.lookups = map[string]string{}
	}
	if _, dup := s.lookups[lookup]; dup {
		return port.MethodCredential{}, errs.New(errs.KindConflict, "credential")
	}
	s.n++
	c := port.MethodCredential{ID: fmt.Sprintf("crd_%d", s.n), PublicID: fmt.Sprintf("crd_pub%d", s.n), UserID: userID, Data: bytes.Clone(data),
		Sealed: bytes.Clone(data)}
	s.lookups[lookup] = c.ID
	s.creds = append(s.creds, c)
	return c, nil
}

func (s *store) Update(_ context.Context, c port.MethodCredential, data []byte) (port.MethodCredential, error) {
	for i, x := range s.creds {
		if x.ID == c.ID {
			if !bytes.Equal(x.Sealed, c.Sealed) {
				return port.MethodCredential{}, errs.New(errs.KindConflict, "changed")
			}
			x.Data, x.Sealed = bytes.Clone(data), bytes.Clone(data)
			s.creds[i] = x
			return x, nil
		}
	}
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

func (s *store) Revoke(context.Context, port.MethodCredential, string) error { return nil }

type users map[string]string // email → user

func (u users) LoginUser(_ context.Context, email string) (string, error) {
	if id, ok := u[email]; ok {
		return id, nil
	}
	return "", errs.New(errs.KindNotFound, "user")
}

type fixture struct {
	t      *testing.T
	m      Method
	clk    *clock.Fake
	store  *store
	issuer *sdjwttest.Issuer
	holder *sdjwttest.Holder
}

func realmConfig(iss *sdjwttest.Issuer) RealmConfig {
	return RealmConfig{SameDeviceRedirectURI: "https://app.example/wallet", VCTValues: []string{vct}, SubjectClaim: []any{"sub"},
		Attributes: map[string][]any{"given_name": {"given_name"}},
		Issuers:    []IssuerConfig{{ISS: iss.ISS, JWKS: iss.JWKS()}}}
}

// setupWith は rc（YAML を経て読む。設定ファイルと同じ）で方式を作る。
func setupWith(t *testing.T, edit func(*RealmConfig, *sdjwttest.Issuer)) *fixture {
	t.Helper()
	k := testkit.New(t)
	iss := sdjwttest.NewIssuer("https://pid.example", "k1")
	rc := realmConfig(iss)
	if edit != nil {
		edit(&rc, iss)
	}
	src, err := yaml.Marshal(Config{Realms: map[string]RealmConfig{"r1": rc}})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(v any) error {
		dec := yaml.NewDecoder(bytes.NewReader(src))
		dec.KnownFields(true)
		return dec.Decode(v)
	}
	a, err := Method{}.Setup(context.Background(), port.MethodSetup{RealmSlug: "r1", Decode: decode, BaseURL: base + "/", Clock: k.Clock,
		Ephemeral: method.Scoped(k.Cache, Name, "r1")})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, m: a.(Method), clk: k.Clock, store: &store{}, issuer: iss, holder: sdjwttest.NewHolder()}
}

func (f *fixture) env(user string, u port.MethodUsage) port.MethodEnv {
	return port.MethodEnv{RealmID: "r1", UserID: user, Usage: u, Credentials: f.store, Now: f.clk.Now()}
}

// request はウォレットとして要求を読む（署名した要求は request_uri から取り、x5c の鍵で確かめる）。
type request struct {
	ClientID       string          `json:"client_id"`
	ResponseURI    string          `json:"response_uri"`
	ResponseType   string          `json:"response_type"`
	ResponseMode   string          `json:"response_mode"`
	Nonce          string          `json:"nonce"`
	State          string          `json:"state"`
	DCQL           json.RawMessage `json:"dcql_query"`
	ClientMetadata json.RawMessage `json:"client_metadata"`
	Aud            string          `json:"aud"`
}

func (f *fixture) read(ch port.MethodChallenge) (request, map[string]any) {
	f.t.Helper()
	var p map[string]any
	if err := json.Unmarshal(ch.Payload, &p); err != nil {
		f.t.Fatal(err)
	}
	u, err := url.Parse(p["authorization_request"].(string))
	if err != nil || u.Scheme != "openid4vp" {
		f.t.Fatalf("authorization_request = %v", p["authorization_request"])
	}
	q := u.Query()
	if ru := q.Get("request_uri"); ru != "" {
		ruu, _ := url.Parse(ru)
		if !strings.HasPrefix(ru, base+"/v1/login/methods/openid4vp/endpoints/request?") {
			f.t.Fatalf("request_uri = %s", ru)
		}
		resp, err := f.m.Endpoint(context.Background(), port.MethodEnv{}, port.MethodHTTPRequest{Endpoint: EndpointRequest, HTTPMethod: http.MethodGet,
			Query: ruu.Query()})
		if err != nil || resp.ContentType != "application/oauth-authz-req+jwt" {
			f.t.Fatalf("request object: %v", err)
		}
		jws, err := jose.ParseSignedCompact(string(resp.Body), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			f.t.Fatal(err)
		}
		h := jws.Signatures[0].Protected
		if h.ExtraHeaders[jose.HeaderType] != "oauth-authz-req+jwt" {
			f.t.Fatalf("typ = %v", h.ExtraHeaders[jose.HeaderType])
		}
		roots := x509.NewCertPool()
		roots.AddCert(f.m.rt.p.leaf)
		chains, err := h.Certificates(x509.VerifyOptions{Roots: roots, CurrentTime: f.clk.Now()})
		if err != nil {
			f.t.Fatal(err)
		}
		body, err := jws.Verify(chains[0][0].PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		var r request
		if err := json.Unmarshal(body, &r); err != nil {
			f.t.Fatal(err)
		}
		if r.ClientID != q.Get("client_id") || r.Aud != selfIssuedAudience {
			f.t.Fatalf("request object: %+v", r)
		}
		return r, p
	}
	r := request{ClientID: q.Get("client_id"), ResponseURI: q.Get("response_uri"), ResponseType: q.Get("response_type"),
		ResponseMode: q.Get("response_mode"), Nonce: q.Get("nonce"), State: q.Get("state"), DCQL: json.RawMessage(q.Get("dcql_query")),
		ClientMetadata: json.RawMessage(q.Get("client_metadata"))}
	return r, p
}

// post はウォレットとして direct_post で提示を送る。
func (f *fixture) post(form url.Values) (port.MethodHTTPResponse, error) {
	return f.m.Endpoint(context.Background(), port.MethodEnv{}, port.MethodHTTPRequest{Endpoint: EndpointResponse, HTTPMethod: http.MethodPost, Form: form})
}

func (f *fixture) present(r request, claims map[string]any) url.Values {
	c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "subject-1"}, claims, f.clk.Now())
	vp, _ := json.Marshal(map[string]any{QueryID: []string{f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now())}})
	return url.Values{"state": {r.State}, "vp_token": {string(vp)}}
}

func payload(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestCrossDeviceEnrollAndLogin(t *testing.T) {
	f := setupWith(t, nil)
	ctx := context.Background()
	ch, err := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.read(ch)
	if r.ClientID != "redirect_uri:"+base+"/v1/login/methods/openid4vp/endpoints/response" || r.ResponseURI != base+"/v1/login/methods/openid4vp/endpoints/response" ||
		r.ResponseType != "vp_token" || r.ResponseMode != "direct_post" || r.Nonce == "" || r.State == "" {
		t.Fatalf("request = %+v", r)
	}
	var q map[string]any
	if err := json.Unmarshal(r.DCQL, &q); err != nil {
		t.Fatal(err)
	}
	cred := q["credentials"].([]any)[0].(map[string]any)
	if cred["id"] != QueryID || cred["format"] != "dc+sd-jwt" || len(cred["claims"].([]any)) != 2 {
		t.Fatalf("dcql = %s", r.DCQL)
	}
	// 届く前は pending。
	if _, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State}); !errors.Is(err, port.ErrMethodPending) {
		t.Fatalf("before response: %v", err)
	}
	resp, err := f.post(f.present(r, map[string]any{"given_name": "Pat"}))
	if err != nil || resp.Status != http.StatusOK || string(resp.Body) != "{}" || resp.Events[0].Type != "presentation_received" {
		t.Fatalf("response: %v %+v", err, resp)
	}
	// 同じ state の応答は 2 度受けない。
	if _, err := f.post(f.present(r, nil)); !errors.Is(err, errs.NotFound) {
		t.Fatalf("replayed response: %v", err)
	}
	en, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(en.Payload), `"given_name":"Pat"`) || strings.Contains(string(en.Payload), "subject-1") {
		t.Fatalf("enroll payload = %s", en.Payload)
	}
	// 結果は 1 回だけ使える。
	if _, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("reused result: %v", err)
	}

	// ログイン（1要素目）。
	ch, err = f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.read(ch)
	if _, err := f.m.Complete(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{State: ch.State}); !errors.Is(err, port.ErrMethodPending) {
		t.Fatalf("pending: %v", err)
	}
	if _, err := f.post(f.present(r, map[string]any{"given_name": "Patricia"})); err != nil {
		t.Fatal(err)
	}
	res, err := f.m.Complete(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{State: ch.State})
	if err != nil || res.Credential.UserID != "u1" {
		t.Fatalf("login: %v %+v", err, res)
	}
	// 属性は新しい提示の値で置き換わる。
	if !strings.Contains(string(f.store.creds[0].Data), "Patricia") {
		t.Fatalf("attributes not refreshed: %s", f.store.creds[0].Data)
	}
	// 2要素目は本人の結び付けに限る。
	f.store.creds = append(f.store.creds, port.MethodCredential{ID: "other", UserID: "u2"})
	ch, err = f.m.Begin(ctx, f.env("u2", port.UsageSecondFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.read(ch)
	if _, err := f.post(f.present(r, map[string]any{"given_name": "Pat"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Complete(ctx, f.env("u2", port.UsageSecondFactor), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("another user's credential as second factor: %v", err)
	}
	// 結び付けの無い利用者の2要素目は始められない。
	if _, err := f.m.Begin(ctx, f.env("u3", port.UsageSecondFactor), port.MethodRequest{}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("second factor without credential: %v", err)
	}
}

func TestSameDeviceNeedsResponseCode(t *testing.T) {
	f := setupWith(t, nil)
	ctx := context.Background()
	if _, err := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{}); err != nil {
		t.Fatal(err)
	}
	// 既定の流れは flows の先頭（same_device）。
	ch, err := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	r, p := f.read(ch)
	if p["flow"] != FlowSameDevice {
		t.Fatalf("flow = %v", p["flow"])
	}
	resp, err := f.post(f.present(r, map[string]any{"given_name": "Pat"}))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	_ = json.Unmarshal(resp.Body, &body)
	ru, ok := strings.CutPrefix(body["redirect_uri"], "https://app.example/wallet#response_code=")
	if !ok || ru == "" {
		t.Fatalf("redirect_uri = %q", body["redirect_uri"])
	}
	for _, bad := range []any{nil, map[string]string{"response_code": "x"}, map[string]string{"response_code": ""}} {
		if _, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State, Payload: payload(bad)}); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("response_code %v accepted: %v", bad, err)
		}
	}
	if _, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State, Payload: payload(map[string]string{"response_code": ru})}); err != nil {
		t.Fatal(err)
	}
	// 知らない流れは受けない。
	if _, err := f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": "other"})}); !errors.Is(err, errs.Invalid) {
		t.Fatalf("unknown flow: %v", err)
	}
}

// loginRejected は、ログインの提示が応答で拒まれ（400）、complete でも失敗することを確かめる。
func (f *fixture) loginRejected(t *testing.T, form func(request) url.Values) {
	t.Helper()
	ctx := context.Background()
	ch, err := f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.read(ch)
	resp, err := f.post(form(r))
	if err != nil || resp.Status != http.StatusBadRequest || resp.Events[0].Type != "presentation_rejected" || !resp.Events[0].Failure {
		t.Fatalf("response: %v %+v", err, resp)
	}
	t.Log(resp.Events[0].Details["reason"])
	if _, err := f.m.Complete(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("complete after rejection: %v", err)
	}
}

func TestPresentationRejected(t *testing.T) {
	f := setupWith(t, nil)
	other := sdjwttest.NewIssuer("https://other.example", "k1")
	vp := func(raw string) string {
		b, _ := json.Marshal(map[string]any{QueryID: []string{raw}})
		return string(b)
	}
	cases := map[string]func(r request) url.Values{
		"wallet error": func(r request) url.Values { return url.Values{"state": {r.State}, "error": {"access_denied"}} },
		"no vp_token":  func(r request) url.Values { return url.Values{"state": {r.State}} },
		"wrong nonce": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, "other", f.clk.Now()))}}
		},
		"wrong audience": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, "redirect_uri:https://evil.example/cb", r.Nonce, f.clk.Now()))}}
		},
		"untrusted issuer": func(r request) url.Values {
			c := other.Issue(vct, f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now()))}}
		},
		"other vct": func(r request) url.Values {
			c := f.issuer.Issue("urn:other", f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now()))}}
		},
		"status reference": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s", "status": map[string]any{"status_list": map[string]any{"idx": 1, "uri": "https://s"}}},
				map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now()))}}
		},
		"attribute not disclosed": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P", "x": 1}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now(), "x"))}}
		},
		"subject not a scalar": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": map[string]any{"a": 1}}, map[string]any{"given_name": "P"}, f.clk.Now())
			return url.Values{"state": {r.State}, "vp_token": {vp(f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now()))}}
		},
		"two presentations": func(r request) url.Values {
			c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s"}, map[string]any{"given_name": "P"}, f.clk.Now())
			p := f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now())
			b, _ := json.Marshal(map[string]any{QueryID: []string{p, p}})
			return url.Values{"state": {r.State}, "vp_token": {string(b)}}
		},
		"duplicate vp_token": func(r request) url.Values {
			v := f.present(r, map[string]any{"given_name": "P"})
			v.Add("vp_token", v.Get("vp_token"))
			return v
		},
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) { f.loginRejected(t, form) })
	}
	// 結び付けの無い提示は、確かめが通っても complete で拒む。
	ctx := context.Background()
	ch, _ := f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	r, _ := f.read(ch)
	if _, err := f.post(f.present(r, map[string]any{"given_name": "P"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Complete(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("not enrolled: %v", err)
	}
}

func TestStatusIgnoreAndExpiry(t *testing.T) {
	f := setupWith(t, func(rc *RealmConfig, _ *sdjwttest.Issuer) {
		rc.Status = "ignore"
		rc.Flows = []string{FlowCrossDevice}
		rc.SameDeviceRedirectURI = ""
	})
	ctx := context.Background()
	ch, err := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.read(ch)
	c := f.issuer.Issue(vct, f.holder, map[string]any{"sub": "s", "status": map[string]any{"status_list": map[string]any{"idx": 1}}},
		map[string]any{"given_name": "P"}, f.clk.Now())
	vp, _ := json.Marshal(map[string]any{QueryID: []string{f.holder.Present(c, r.ClientID, r.Nonce, f.clk.Now())}})
	if resp, err := f.post(url.Values{"state": {r.State}, "vp_token": {string(vp)}}); err != nil || resp.Status != http.StatusOK {
		t.Fatalf("status ignore: %v %+v", err, resp)
	}
	// 期限を過ぎて応答の無いフローは失敗にする。
	ch, _ = f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{})
	r, _ = f.read(ch)
	f.clk.Advance(6 * time.Minute)
	if _, err := f.m.Complete(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{State: ch.State}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := f.post(f.present(r, map[string]any{"given_name": "P"})); !errors.Is(err, errs.NotFound) {
		t.Fatalf("response after expiry: %v", err)
	}
}

func TestLinkByEmail(t *testing.T) {
	f := setupWith(t, func(rc *RealmConfig, iss *sdjwttest.Issuer) { rc.Issuers[0].LinkByEmail = true })
	ctx := context.Background()
	login := func(email string, u users) (port.MethodResult, error) {
		ch, err := f.m.Begin(ctx, f.env("", port.UsageFirstFactor), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := f.read(ch)
		var q map[string]any
		_ = json.Unmarshal(r.DCQL, &q)
		if !strings.Contains(string(r.DCQL), `["email"]`) {
			t.Fatalf("dcql without email: %s", r.DCQL)
		}
		if _, err := f.post(f.present(r, map[string]any{"given_name": "P", "email": email})); err != nil {
			t.Fatal(err)
		}
		env := f.env("", port.UsageFirstFactor)
		env.Users = u
		return f.m.Complete(ctx, env, port.MethodRequest{State: ch.State})
	}
	if _, err := login("nobody@example.com", users{}); !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("unknown email: %v", err)
	}
	res, err := login("pat@example.com", users{"pat@example.com": "u9"})
	if err != nil || res.Credential.UserID != "u9" || len(f.store.creds) != 1 {
		t.Fatalf("link: %v %+v", err, res)
	}
	// 2 回目からは結び付けで引く（メールは見ない）。
	if res, err := login("changed@example.com", users{}); err != nil || res.Credential.UserID != "u9" {
		t.Fatalf("second login: %v", err)
	}
}

// testCA は要求に署名する鍵と証明書を作る。
func testCA(t *testing.T, dns string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC) // testkit の時計
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSignedRequest(t *testing.T) {
	for _, prefix := range []string{PrefixX509Hash, PrefixX509SANDNS} {
		t.Run(prefix, func(t *testing.T) {
			key, cert := testCA(t, "id.example")
			f := setupWith(t, func(rc *RealmConfig, _ *sdjwttest.Issuer) {
				rc.ClientIDPrefix, rc.SigningKey, rc.CertificateChain = prefix, key, cert
			})
			ctx := context.Background()
			ch, err := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
			if err != nil {
				t.Fatal(err)
			}
			r, _ := f.read(ch)
			want := "x509_san_dns:id.example"
			if prefix == PrefixX509Hash {
				h := sha256.Sum256(f.m.rt.p.leaf.Raw)
				want = "x509_hash:" + base64.RawURLEncoding.EncodeToString(h[:])
			}
			if r.ClientID != want {
				t.Fatalf("client_id = %s", r.ClientID)
			}
			if resp, err := f.post(f.present(r, map[string]any{"given_name": "P"})); err != nil || resp.Status != http.StatusOK {
				t.Fatalf("response: %v", err)
			}
			if _, err := f.m.EnrollComplete(ctx, f.env("u1", ""), port.MethodRequest{State: ch.State}); err != nil {
				t.Fatal(err)
			}
		})
	}
	// 知らない要求の ID は 404。
	f := setupWith(t, nil)
	if _, err := f.m.Endpoint(context.Background(), port.MethodEnv{}, port.MethodHTTPRequest{Endpoint: EndpointRequest, HTTPMethod: http.MethodGet,
		Query: url.Values{"id": {"x"}}}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown request: %v", err)
	}
	if _, err := f.m.Endpoint(context.Background(), port.MethodEnv{}, port.MethodHTTPRequest{Endpoint: "other", HTTPMethod: http.MethodGet}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown endpoint: %v", err)
	}
}

func TestIssuerX5C(t *testing.T) {
	key, cert := testCA(t, "pid.example")
	blk, _ := pem.Decode([]byte(key))
	k, _ := x509.ParsePKCS8PrivateKey(blk.Bytes)
	cblk, _ := pem.Decode([]byte(cert))
	c, _ := x509.ParseCertificate(cblk.Bytes)
	f := setupWith(t, func(rc *RealmConfig, iss *sdjwttest.Issuer) {
		rc.Issuers = []IssuerConfig{{ISS: iss.ISS, TrustAnchors: []string{cert}}}
		iss.Key, iss.KID, iss.Chain = k.(*ecdsa.PrivateKey), "", []*x509.Certificate{c}
	})
	ctx := context.Background()
	ch, _ := f.m.EnrollBegin(ctx, f.env("u1", ""), port.MethodRequest{Payload: payload(map[string]string{"flow": FlowCrossDevice})})
	r, _ := f.read(ch)
	if resp, err := f.post(f.present(r, map[string]any{"given_name": "P"})); err != nil || resp.Status != http.StatusOK {
		t.Fatalf("x5c issuer: %v %s %v", err, resp.Body, resp.Events)
	}
	// 別の CA の x5c は受けない。
	other, otherCert := testCA(t, "pid.example")
	blk, _ = pem.Decode([]byte(other))
	k2, _ := x509.ParsePKCS8PrivateKey(blk.Bytes)
	cblk, _ = pem.Decode([]byte(otherCert))
	c2, _ := x509.ParseCertificate(cblk.Bytes)
	f.issuer.Key, f.issuer.Chain = k2.(*ecdsa.PrivateKey), []*x509.Certificate{c2}
	f.loginRejected(t, func(r request) url.Values { return f.present(r, map[string]any{"given_name": "P"}) })
}

func TestSetup(t *testing.T) {
	if err := method.Check(Method{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (Method{}).Begin(context.Background(), port.MethodEnv{}, port.MethodRequest{}); !errors.Is(err, errNotConfigured) {
		t.Fatalf("unconfigured: %v", err)
	}
	k := testkit.New(t)
	iss := sdjwttest.NewIssuer("https://pid.example", "k1")
	setup := func(slug, baseURL string, realms map[string]RealmConfig) (port.Authenticator, error) {
		src, _ := yaml.Marshal(Config{Realms: realms})
		return Method{}.Setup(context.Background(), port.MethodSetup{RealmSlug: slug, BaseURL: baseURL, Clock: k.Clock,
			Ephemeral: method.Scoped(k.Cache, Name, "r1"), Decode: func(v any) error {
				dec := yaml.NewDecoder(bytes.NewReader(src))
				dec.KnownFields(true)
				return dec.Decode(v)
			}})
	}
	good := realmConfig(iss)
	if a, err := setup("r1", base, nil); a != nil || err != nil {
		t.Fatalf("no settings: %v %v", a, err)
	}
	if a, err := setup("r2", base, map[string]RealmConfig{"r1": good}); a != nil || err != nil {
		t.Fatalf("other realm: %v %v", a, err)
	}
	if _, err := setup("r1", "", map[string]RealmConfig{"r1": good}); err == nil {
		t.Fatal("no public_url")
	}
	if _, err := setup("r1", "http://id.example", map[string]RealmConfig{"r1": good}); err == nil {
		t.Fatal("http public_url outside dev")
	}
	key, cert := testCA(t, "other.example")
	bad := map[string]func(*RealmConfig){
		"prefix":           func(rc *RealmConfig) { rc.ClientIDPrefix = "did" },
		"x509 without key": func(rc *RealmConfig) { rc.ClientIDPrefix = PrefixX509Hash },
		"san mismatch": func(rc *RealmConfig) {
			rc.ClientIDPrefix, rc.SigningKey, rc.CertificateChain = PrefixX509SANDNS, key, cert
		},
		"key with redirect": func(rc *RealmConfig) { rc.SigningKey = key },
		"flows":             func(rc *RealmConfig) { rc.Flows = []string{"qr"} },
		"no redirect":       func(rc *RealmConfig) { rc.SameDeviceRedirectURI = "" },
		"redirect fragment": func(rc *RealmConfig) { rc.SameDeviceRedirectURI = "https://app.example/#x" },
		"no vct":            func(rc *RealmConfig) { rc.VCTValues = nil },
		"no subject":        func(rc *RealmConfig) { rc.SubjectClaim = nil },
		"null path":         func(rc *RealmConfig) { rc.SubjectClaim = []any{"a", nil} },
		"negative path":     func(rc *RealmConfig) { rc.Attributes = map[string][]any{"a": {"a", -1}} },
		"no issuers":        func(rc *RealmConfig) { rc.Issuers = nil },
		"issuer no keys":    func(rc *RealmConfig) { rc.Issuers = []IssuerConfig{{ISS: iss.ISS}} },
		"issuer bad jwks":   func(rc *RealmConfig) { rc.Issuers = []IssuerConfig{{ISS: iss.ISS, JWKS: `{"keys":[]}`}} },
		"private jwks": func(rc *RealmConfig) {
			b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: iss.Key}}})
			rc.Issuers = []IssuerConfig{{ISS: iss.ISS, JWKS: string(b)}}
		},
		"issuer vct":    func(rc *RealmConfig) { rc.Issuers[0].VCTValues = []string{"urn:other"} },
		"duplicate iss": func(rc *RealmConfig) { rc.Issuers = append(rc.Issuers, rc.Issuers[0]) },
		"status":        func(rc *RealmConfig) { rc.Status = "check" },
		"ttl":           func(rc *RealmConfig) { rc.RequestTTL = "1h" },
		"max":           func(rc *RealmConfig) { rc.MaxCredentials = 1000 },
		"endpoint":      func(rc *RealmConfig) { rc.AuthorizationEndpoint = "openid4vp://?x=1" },
	}
	for name, edit := range bad {
		t.Run(name, func(t *testing.T) {
			rc := realmConfig(iss)
			edit(&rc)
			if _, err := setup("r1", base, map[string]RealmConfig{"r1": rc}); err == nil {
				t.Fatal("accepted")
			}
			// 他の realm の誤りでも起動を止める。
			if _, err := setup("r2", base, map[string]RealmConfig{"r1": rc}); err == nil {
				t.Fatal("accepted in another realm")
			}
		})
	}
}

func FuzzParseVPToken(f *testing.F) {
	f.Add(`{"credential":["a.b.c~"]}`)
	f.Add(`{"credential":"x"}`)
	f.Add(`{"credential":["a"],"credential":["b"]}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseVPToken(s)
		if err != nil {
			return
		}
		if p == "" {
			t.Fatal("empty presentation accepted")
		}
		var m map[string][]string
		if json.Unmarshal([]byte(s), &m) != nil || len(m) != 1 || len(m[QueryID]) != 1 || m[QueryID][0] != p {
			t.Fatalf("parse broke its contract: %q", s)
		}
	})
}
