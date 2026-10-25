package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/port"
)

// OAuth のフローを HTTP から通しで試す（偽のプロバイダで）。
func TestOAuthLoginOverHTTP(t *testing.T) {
	l := newLoginEnv(t)
	var claims map[string]any
	var challenge string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, "invalid_grant", 400)
			return
		}
		b, _ := json.Marshal(claims)
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".x"})
	}))
	defer srv.Close()
	l.a.oauth.HTTP = srv.Client()
	oauth.Presets["fake"] = oauth.Config{Issuers: []string{"https://fake.example"}, AuthURL: "https://fake.example/auth",
		TokenURL: srv.URL, Scopes: []string{"openid", "email"}}
	defer delete(oauth.Presets, "fake")
	c, err := l.a.oauth.NewConnection(context.Background(), l.a.realm.ID, "fake", "fake", "cid", "csecret", []string{"https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error { return tx.Connections().Create(ctx, c) }); err != nil {
		t.Fatal(err)
	}

	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth/fake:start", map[string]string{})
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var st struct {
		FlowID string `json:"flow_id"`
		URL    string `json:"authorization_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	u, _ := url.Parse(st.URL)
	q := u.Query()
	challenge = q.Get("code_challenge")
	now := l.a.deps.Clock.Now()
	claims = map[string]any{"iss": "https://fake.example", "aud": "cid", "sub": "s1", "email": "carol@example.com",
		"email_verified": true, "nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}

	// Cookie でフロー ID を渡す（ブラウザの場合）。
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth:complete", map[string]string{"state": q.Get("state"), "code": "the-code"},
		"Cookie", oauthCookie+"="+st.FlowID)
	if w.Code != 200 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	var res map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res["created"] != true {
		t.Fatalf("res = %v", res)
	}
	found := false
	for _, ck := range w.Result().Cookies() {
		found = found || (ck.Name == sessionCookie && ck.Value != "")
	}
	if !found {
		t.Fatal("no session cookie")
	}
	// 同じ state は2度使えない。
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth:complete", map[string]string{"state": q.Get("state"), "code": "the-code", "flow_id": st.FlowID})
	if w.Code != 401 {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/oauth/missing:start", nil); w.Code != 404 {
		t.Fatalf("missing connection: %d", w.Code)
	}
}
