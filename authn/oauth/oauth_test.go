package oauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	clientID     = "client-123"
	clientSecret = "secret-456"
	redirect     = "https://iam.example.com/v1/login/oauth/callback"
)

// provider は偽のプロバイダ（トークンエンドポイント）。
type provider struct {
	mu     sync.Mutex
	grants map[string]grant
	srv    *httptest.Server
}

type grant struct {
	claims    map[string]any
	challenge string
}

func newProvider(t *testing.T) *provider {
	p := &provider{grants: map[string]grant{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.token))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	p.mu.Lock()
	g, ok := p.grants[r.PostForm.Get("code")]
	delete(p.grants, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != clientSecret ||
		r.PostForm.Get("redirect_uri") != redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, 400)
		return
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	idToken := enc(map[string]string{"alg": "RS256"}) + "." + enc(g.claims) + ".c2ln"
	_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken, "access_token": "at", "token_type": "Bearer"})
}

type env struct {
	k   *testkit.Kit
	svc *oauth.Service
	p   *provider
}

func setup(t *testing.T) *env {
	t.Helper()
	k := testkit.New(t)
	p := newProvider(t)
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	svc := &oauth.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Sessions: sm, HTTP: p.srv.Client(),
		Accounts: &account.Service{Crypter: k.Crypter, Clock: k.Clock,
			VerifiedVia: []port.VerifiedVia{port.VerifiedViaCode, port.VerifiedViaOAuthProvider}}}
	oauth.Presets["test"] = oauth.Config{Issuers: []string{"https://issuer.example"}, AuthURL: "https://issuer.example/auth?hd=x",
		TokenURL: p.srv.URL + "/token", Scopes: []string{"openid", "email"}}
	t.Cleanup(func() { delete(oauth.Presets, "test") })
	c, err := svc.NewConnection(context.Background(), k.RealmID, "test", "test", clientID, clientSecret, []string{redirect})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c.Config, []byte(clientSecret)) {
		t.Fatal("client secret stored in plaintext")
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Connections().Create(ctx, c) })
	return &env{k: k, svc: svc, p: p}
}

// authorize はプロバイダでのログインを模し、Complete の入力を返す。edit でクレームを書き換えられる。
func (e *env) authorize(t *testing.T, sub, email string, verified bool, edit ...func(map[string]any)) oauth.Complete {
	t.Helper()
	return e.authorizeSlug(t, "test", sub, email, verified, edit...)
}

// authorizeSlug は connection（slug）を指定する authorize。
func (e *env) authorizeSlug(t *testing.T, slug, sub, email string, verified bool, edit ...func(map[string]any)) oauth.Complete {
	t.Helper()
	st, err := e.svc.Start(context.Background(), e.k.RealmID, slug, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(st.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("hd") != "x" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != redirect || q.Get("client_id") != clientID {
		t.Fatalf("authorization url = %s", st.AuthorizationURL)
	}
	now := e.k.Clock.Now()
	claims := map[string]any{"iss": "https://issuer.example", "aud": clientID, "sub": sub, "email": email,
		"email_verified": verified, "nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for _, f := range edit {
		f(claims)
	}
	code := "code-" + q.Get("state")[:8]
	e.p.mu.Lock()
	e.p.grants[code] = grant{claims: claims, challenge: q.Get("code_challenge")}
	e.p.mu.Unlock()
	return oauth.Complete{FlowID: st.FlowID, State: q.Get("state"), Code: code}
}

func (e *env) complete(t *testing.T, in oauth.Complete) (oauth.Result, error) {
	t.Helper()
	return e.svc.Complete(context.Background(), e.k.RealmID, in)
}

func TestSignupThenLogin(t *testing.T) {
	e := setup(t)
	first, err := e.complete(t, e.authorize(t, "sub-1", "Alice@Example.com", true))
	if err != nil || !first.Created {
		t.Fatalf("signup = %+v, %v", first, err)
	}
	if _, err := e.svc.Sessions.Validate(context.Background(), e.k.RealmID, first.Session.Token); err != nil {
		t.Fatal(err)
	}
	// メールは「プロバイダが確認済み」として登録される。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, e.k.RealmID, first.UserID)
		if err != nil {
			return err
		}
		es, err := tx.Emails().ListByUser(ctx, e.k.RealmID, u.ID)
		if err != nil || len(es) != 1 || es[0].VerifiedVia != port.VerifiedViaOAuthProvider || !es[0].IsPrimary {
			t.Fatalf("emails = %+v, %v", es, err)
		}
		return nil
	})
	// 同じ外部 ID なら、メールが変わっていても同じユーザーでログインする（識別は (connection, sub)）。
	second, err := e.complete(t, e.authorize(t, "sub-1", "other@example.com", true))
	if err != nil || second.Created || second.UserID != first.UserID {
		t.Fatalf("login = %+v, %v (first %+v)", second, err, first)
	}
}

// 不変条件：未ログインでメールが一致しても自動リンクしない（4.2）。
func TestNoAutoLinkByEmail(t *testing.T) {
	e := setup(t)
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.svc.Accounts.CreateWithEmail(ctx, tx, e.k.RealmID, "alice@example.com", port.VerifiedViaCode, audit.Actor{Type: "system"}, "")
		return err
	})
	_, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", true))
	if !errors.Is(err, oauth.ErrAccountExists) {
		t.Fatalf("want ErrAccountExists, got %v", err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cs, _ := tx.Connections().List(ctx, e.k.RealmID)
		if _, err := tx.Identities().GetBySubject(ctx, e.k.RealmID, cs[0].ID, "sub-1"); !errors.Is(err, errs.NotFound) {
			t.Fatalf("identity was linked: %v", err)
		}
		return nil
	})
}

func TestUnverifiedEmailCannotSignUp(t *testing.T) {
	e := setup(t)
	if _, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", false)); !errors.Is(err, oauth.ErrEmailUnverified) {
		t.Fatalf("want ErrEmailUnverified, got %v", err)
	}
	// 文字列の "true" も確認済みとして読む。
	if _, err := e.complete(t, e.authorize(t, "sub-2", "bob@example.com", true, func(c map[string]any) { c["email_verified"] = "true" })); err != nil {
		t.Fatal(err)
	}
}

func TestStateIsOneTimeAndBoundToFlow(t *testing.T) {
	e := setup(t)
	in := e.authorize(t, "sub-1", "alice@example.com", true)
	other := in
	other.FlowID = "someone-elses-flow"
	if _, err := e.complete(t, other); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("other flow: %v", err)
	}
	// 別のフローで使われた state は捨てられ、本来のフローでも使えない（1回限り）。
	if _, err := e.complete(t, in); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("replay: %v", err)
	}
	in = e.authorize(t, "sub-1", "alice@example.com", true)
	if _, err := e.complete(t, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.complete(t, in); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("replay after success: %v", err)
	}
}

func TestFlowExpires(t *testing.T) {
	e := setup(t)
	in := e.authorize(t, "sub-1", "alice@example.com", true)
	e.k.Clock.Advance(11 * time.Minute)
	if _, err := e.complete(t, in); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("expired flow: %v", err)
	}
}

func TestIDTokenClaimsChecked(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong iss":        func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong aud":        func(c map[string]any) { c["aud"] = "other-client" },
		"aud without azp":  func(c map[string]any) { c["aud"] = []string{clientID, "other"} },
		"wrong azp":        func(c map[string]any) { c["azp"] = "other" },
		"wrong nonce":      func(c map[string]any) { c["nonce"] = "x" },
		"no nonce":         func(c map[string]any) { delete(c, "nonce") },
		"expired":          func(c map[string]any) { c["exp"] = c["iat"] },
		"issued in future": func(c map[string]any) { c["iat"] = c["exp"] },
		"no sub":           func(c map[string]any) { c["sub"] = "" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			if _, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", true, edit)); !errors.Is(err, oauth.ErrAuthFailed) {
				t.Fatalf("want ErrAuthFailed, got %v", err)
			}
		})
	}
	// aud が複数でも azp が自分なら通る。
	e := setup(t)
	if _, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", true, func(c map[string]any) {
		c["aud"], c["azp"] = []string{clientID, "other"}, clientID
	})); err != nil {
		t.Fatal(err)
	}
}

// PKCE：プロバイダは verifier が challenge に合わなければコードを交換しない（偽のプロバイダで確かめる）。
func TestCodeRejectedByProvider(t *testing.T) {
	e := setup(t)
	in := e.authorize(t, "sub-1", "alice@example.com", true)
	in.Code = "unknown"
	if _, err := e.complete(t, in); !errors.Is(err, oauth.ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestRedirectURIMustBeAllowed(t *testing.T) {
	e := setup(t)
	if _, err := e.svc.Start(context.Background(), e.k.RealmID, "test", "https://evil.example/cb"); !errors.Is(err, errs.Invalid) {
		t.Fatalf("want invalid, got %v", err)
	}
	if _, err := e.svc.Start(context.Background(), e.k.RealmID, "missing", ""); !errors.Is(err, errs.NotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestConfigRequiresHTTPS(t *testing.T) {
	c := oauth.Presets["google"]
	c.ClientID, c.ClientSecret, c.RedirectURIs = "x", []byte("sealed"), []string{"http://localhost/cb"}
	if err := c.Validate(false); err == nil {
		t.Fatal("http redirect_uri must be rejected outside dev")
	}
	if err := c.Validate(true); err != nil {
		t.Fatalf("dev: %v", err)
	}
}

// セッションには使った外部 ID を残す（外部 ID を無効にしたらセッションも使えなくするため。4.6）。
func TestSessionRecordsIdentity(t *testing.T) {
	e := setup(t)
	res, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		s, err := tx.Sessions().Get(ctx, e.k.RealmID, res.Session.Session.ID)
		if err != nil || len(s.AuthCredentialIDs) != 1 || s.AuthMethods[0] != "fed" {
			t.Fatalf("session = %+v, %v", s, err)
		}
		return nil
	})
}

// 注入したクライアントでも、トークンエンドポイントのリダイレクトを追わない（client_secret を別の URL に送り直さない）。
func TestTokenEndpointRedirectNotFollowed(t *testing.T) {
	e := setup(t)
	var leaked bool
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		leaked = r.PostForm.Get("client_secret") != ""
		http.Error(w, "no", 400)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	e.svc.HTTP = srv.Client()
	cfg := oauth.Presets["test"]
	cfg.TokenURL = srv.URL + "/token"
	oauth.Presets["redirecting"] = cfg
	defer delete(oauth.Presets, "redirecting")
	c, err := e.svc.NewConnection(context.Background(), e.k.RealmID, "redirecting", "redirecting", clientID, clientSecret, []string{redirect})
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Connections().Create(ctx, c) })
	st, err := e.svc.Start(context.Background(), e.k.RealmID, "redirecting", redirect)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(st.AuthorizationURL)
	_, err = e.svc.Complete(context.Background(), e.k.RealmID, oauth.Complete{FlowID: st.FlowID, State: u.Query().Get("state"), Code: "x"})
	if err == nil || leaked {
		t.Fatalf("redirect followed: err=%v leaked=%v", err, leaked)
	}
	if srv.Client().CheckRedirect != nil {
		t.Fatal("the injected client must not be modified")
	}
}

// ログイン時にプロバイダがメールを確認済みとしなくなっていれば警告 oauth_email_unverified（既定 warn。10章）。
func TestUnverifiedEmailAtLoginWarns(t *testing.T) {
	e := setup(t)
	ev, err := warning.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Sessions.Warnings = ev
	first, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", true))
	if err != nil || len(first.Session.Warnings) != 0 {
		t.Fatalf("signup = %+v, %v", first.Session.Warnings, err)
	}
	res, err := e.complete(t, e.authorize(t, "sub-1", "alice@example.com", false))
	if err != nil {
		t.Fatal(err)
	}
	if ws := res.Session.Warnings; len(ws) != 1 || ws[0].Code != warning.CodeOAuthEmailUnverified || ws[0].Action != warning.Warn {
		t.Fatalf("warnings = %+v", ws)
	}

	// deny にすれば、本人確認の後なので理由つきで拒否する。
	e.svc.Sessions.Warnings, _ = warning.New(map[string]warning.Action{warning.CodeOAuthEmailUnverified: warning.Deny})
	_, err = e.complete(t, e.authorize(t, "sub-1", "alice@example.com", false))
	if d, ok := errors.AsType[*warning.DeniedError](err); !ok || d.Reasons()[0] != "warning_denied.oauth_email_unverified" {
		t.Fatalf("want DeniedError, got %v", err)
	}
}
