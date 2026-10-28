package app

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/clock"
)

// E2E（roadmap M5）：本物の HTTPS のサーバーに、ふつうの RP（zitadel/oidc の rp と rs。ES256）と、ML-DSA-65 を自分で
// 検証する最小の RP が、Discovery から始めてログインを任せる。

type e2e struct {
	l      *loginEnv
	issuer string
	http   *http.Client
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://" + ln.Addr().String()
	// RP は ID トークンの iat・exp を実際の時刻で確かめるので、偽の時計を今に合わせる。
	l := newLoginEnvDeps(t, func(c *config.Config) {
		c.Server.PublicURL = issuer
		// passkey の RP ID に IP アドレスは使えない（この試験では passkey を使わない）。
		c.Passkey.RPID, c.Passkey.Origins = "localhost", []string{"https://localhost"}
	}, nil, func(d *Deps) {
		d.Clock.(*clock.Fake).Set(time.Now().UTC().Truncate(time.Second))
	})
	srv := httptest.NewUnstartedServer(l.a.PublicHandler())
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &e2e{l: l, issuer: issuer, http: c}
}

// browse はブラウザとして認可要求を開き、ログインして、戻り先への転送から認可コードを取り出す。
func (e *e2e) browse(t *testing.T, authURL, email, redirect string) string {
	t.Helper()
	get := func(u, cookie string) *url.URL {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s: %d", u, resp.StatusCode)
		}
		loc, err := resp.Location()
		if err != nil {
			t.Fatal(err)
		}
		return loc
	}
	loc := get(authURL, "")
	if loc.Path != "/login" {
		t.Fatalf("not sent to login: %s", loc)
	}
	_, cookie := e.l.login(t, email)
	cb := get(e.issuer+loc.Query().Get("return_to"), cookie)
	if !strings.HasPrefix(cb.String(), redirect+"?") || cb.Query().Get("code") == "" {
		t.Fatalf("callback: %s", cb)
	}
	return cb.Query().Get("code")
}

type nonceKey struct{}

func TestOIDCE2EStandardRP(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	web := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	api := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://api.example.com/cb"}})

	relying, err := oidcrp.NewRelyingPartyOIDC(ctx, e.issuer, web.clientID, web.secret, web.redirect, []string{"openid", "email"}, oidcrp.WithHTTPClient(e.http),
		oidcrp.WithVerifierOpts(oidcrp.WithNonce(func(ctx context.Context) string { n, _ := ctx.Value(nonceKey{}).(string); return n })))
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier, challenge := pkce()
	authURL := oidcrp.AuthURL("e2e-state", relying, oidcrp.WithCodeChallenge(challenge), func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", "e2e-nonce")}
	})
	code := e.browse(t, authURL, "alice@example.com", web.redirect)
	tokens, err := oidcrp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(ctx, nonceKey{}, "e2e-nonce"), code, relying, oidcrp.WithCodeVerifier(verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	alice := e.l.userID(t, "alice@example.com")
	if tokens.IDTokenClaims.Subject != alice || tokens.IDTokenClaims.SessionID == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens: %+v", tokens.IDTokenClaims)
	}
	info, err := oidcrp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, oidc.BearerToken, alice, relying)
	if err != nil || info.Email != "alice@example.com" || !bool(info.EmailVerified) {
		t.Fatalf("userinfo: %+v %v", info, err)
	}
	// リフレッシュで出す ID トークンには nonce を入れない（OIDC Core 12.2）。
	refreshed, err := oidcrp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", "")
	if err != nil || refreshed.IDTokenClaims.SessionID != tokens.IDTokenClaims.SessionID || refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatalf("refresh: %+v %v", refreshed, err)
	}

	// リソースサーバーはイントロスペクションで確かめる。
	server, err := rs.NewResourceServerClientCredentials(ctx, e.issuer, api.clientID, api.secret, rs.WithClient(e.http))
	if err != nil {
		t.Fatalf("resource server: %v", err)
	}
	in, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, server, refreshed.AccessToken)
	if err != nil || !in.Active || in.Subject != alice || in.ClientID != web.clientID {
		t.Fatalf("introspect: %+v %v", in, err)
	}
	if err := oidcrp.RevokeToken(ctx, relying, refreshed.RefreshToken, "refresh_token"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if in, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, server, refreshed.AccessToken); err != nil || in.Active {
		t.Fatalf("introspect after revoke: %+v %v", in, err)
	}
}

func TestOIDCE2EMLDSARP(t *testing.T) {
	e := newE2E(t)
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	p := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "id_token_signed_response_alg": "ML-DSA-65",
		"redirect_uris": []string{"https://pq.example.com/cb"}})
	getJSON := func(u string, v any) {
		resp, err := e.http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(v) != nil {
			t.Fatalf("GET %s: %d", u, resp.StatusCode)
		}
	}
	var disc struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	getJSON(e.issuer+"/.well-known/openid-configuration", &disc)
	if disc.Issuer != e.issuer {
		t.Fatalf("issuer = %q", disc.Issuer)
	}

	verifier, challenge := pkce()
	q := url.Values{"client_id": {p.clientID}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {p.redirect},
		"state": {"s"}, "nonce": {"pq-nonce"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	code := e.browse(t, disc.Authorization+"?"+q.Encode(), "bob@example.com", p.redirect)
	resp, err := e.http.PostForm(disc.Token, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect},
		"code_verifier": {verifier}, "client_id": {p.clientID}})
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tok)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("token: %d %v", resp.StatusCode, err)
	}

	// JWKS の AKP 鍵（draft-ietf-cose-dilithium）で、crypto/mldsa で直接検証する。
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id token: %q", tok.IDToken)
	}
	var header struct{ Alg, Kid string }
	h := b64(t, parts[0])
	if json.Unmarshal(h, &header) != nil || header.Alg != "ML-DSA-65" {
		t.Fatalf("header: %s", h)
	}
	var set struct {
		Keys []struct{ Kty, Alg, Kid, Pub string } `json:"keys"`
	}
	getJSON(disc.JWKS, &set)
	var pub *mldsa.PublicKey
	for _, k := range set.Keys {
		if k.Kid == header.Kid && k.Kty == "AKP" && k.Alg == "ML-DSA-65" {
			raw, err := base64.RawURLEncoding.DecodeString(k.Pub)
			if err != nil {
				t.Fatal(err)
			}
			if pub, err = mldsa.NewPublicKey(mldsa.MLDSA65(), raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	if pub == nil {
		t.Fatalf("no AKP key %s in %+v", header.Kid, set)
	}
	sig := b64(t, parts[2])
	if err := mldsa.Verify(pub, []byte(parts[0]+"."+parts[1]), sig, &mldsa.Options{}); err != nil {
		t.Fatalf("ml-dsa verify: %v", err)
	}
	var claims map[string]any
	payload := b64(t, parts[1])
	if json.Unmarshal(payload, &claims) != nil || claims["iss"] != e.issuer || claims["aud"] != p.clientID || claims["nonce"] != "pq-nonce" ||
		claims["sub"] != e.l.userID(t, "bob@example.com") {
		t.Fatalf("claims: %v", claims)
	}
	if exp, _ := claims["exp"].(float64); time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Fatalf("expired: %v", claims["exp"])
	}
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}
