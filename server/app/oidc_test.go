package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

const testIssuer = "https://id.example.test"

func withIssuer(c *config.Config) { c.Server.PublicURL = testIssuer + "/" }

// rp は試験用の連携先（Relying Party）。
type rp struct {
	l                          *loginEnv
	clientID, secret, redirect string
	verifier, state, nonce     string
}

func (l *loginEnv) registerRP(t *testing.T, owner string, body map[string]any) *rp {
	t.Helper()
	if body["redirect_uris"] == nil {
		body["redirect_uris"] = []string{"https://rp.example.com/cb"}
	}
	if body["name"] == nil {
		body["name"] = "RP"
	}
	code, out := l.admin(t, "/v1/admin/clients", owner, body)
	if code != 201 {
		t.Fatalf("register client: %d %v", code, out)
	}
	secret, _ := out["client_secret"].(string)
	return &rp{l: l, clientID: out["client_id"].(string), secret: secret, redirect: body["redirect_uris"].([]string)[0]}
}

// oidcDo は OIDC のエンドポイントを呼ぶ（フォームの本文。Cookie はセッションの Cookie の値）。
func (l *loginEnv) oidcDo(t *testing.T, method, path string, form url.Values, cookie string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		r.Header.Set("Cookie", sessionCookie+"="+cookie)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	l.out.Write(w.Body.Bytes())
	return w
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// authorizeURL は認可要求の URL を作る（PKCE・state・nonce は毎回新しく作る）。
func (p *rp) authorizeURL(extra url.Values) string {
	var challenge string
	p.verifier, challenge = pkce()
	p.state, p.nonce = "st-"+p.verifier[:8], "nn-"+p.verifier[8:16]
	q := url.Values{"client_id": {p.clientID}, "response_type": {"code"}, "scope": {"openid email"}, "redirect_uri": {p.redirect},
		"state": {p.state}, "nonce": {p.nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	return oidcAuthorize + "?" + q.Encode()
}

// location は 302 の転送先を返す。
func location(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d %s", w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// code は連携先の戻り先への転送から認可コードを取り出す。
func (p *rp) code(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	u := location(t, w)
	if got := u.Scheme + "://" + u.Host + u.Path; got != p.redirect {
		t.Fatalf("redirected to %s", u)
	}
	if u.Query().Get("state") != p.state || u.Query().Get("code") == "" {
		t.Fatalf("callback: %s", u)
	}
	return u.Query().Get("code")
}

// login は未ログインのブラウザで認可要求から始め、ログイン画面を経て認可コードを受け取る。セッションの Cookie も返す。
func (p *rp) login(t *testing.T, email string, extra url.Values) (code, cookie string) {
	t.Helper()
	u := location(t, p.l.oidcDo(t, "GET", p.authorizeURL(extra), nil, ""))
	if u.Path != "/login" {
		t.Fatalf("not sent to login: %s", u)
	}
	back := u.Query().Get("return_to")
	if !strings.HasPrefix(back, oidcResume+"?request=") || safeReturnTo(back) != back {
		t.Fatalf("return_to = %q", back)
	}
	_, cookie = p.l.login(t, email)
	return p.code(t, p.l.oidcDo(t, "GET", back, nil, cookie)), cookie
}

func (p *rp) exchange(t *testing.T, code string, form url.Values, hdr ...string) (int, map[string]any) {
	t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "code_verifier": {p.verifier}}
	for k, v := range form {
		f[k] = v
	}
	if p.secret != "" && len(hdr) == 0 && f.Get("client_assertion") == "" {
		hdr = []string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(p.clientID)+":"+url.QueryEscape(p.secret)))}
	}
	if p.secret == "" && f.Get("client_assertion") == "" {
		f.Set("client_id", p.clientID)
	}
	w := p.l.oidcDo(t, "POST", oidcToken, f, "", hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code == 200 && (w.Header().Get("Cache-Control") != "no-store" || out["token_type"] != "Bearer") {
		t.Fatalf("token response headers/body: %v %v", w.Header(), out)
	}
	return w.Code, out
}

func (l *loginEnv) userinfo(t *testing.T, token string) (int, map[string]any) {
	t.Helper()
	w := l.oidcDo(t, "GET", oidcUserinfo, nil, "", "Authorization", "Bearer "+token)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code == 401 && w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
	}
	return w.Code, out
}

// idClaims は ID トークンを JWKS で検証し、クレームを返す。ES256 は jwx（一般の RP と同じ経路）でも検証する。
func (l *loginEnv) idClaims(t *testing.T, idToken, alg string) map[string]any {
	t.Helper()
	var payload []byte
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		payload, err = l.a.keys.Verify(ctx, tx, l.a.realm.ID, idToken)
		return err
	})
	if err != nil {
		t.Fatalf("verify id token: %v", err)
	}
	if alg == port.AlgES256 {
		w := l.oidcDo(t, "GET", oidcKeys, nil, "")
		set, err := jwk.Parse(w.Body.Bytes())
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		if _, err := jwt.Parse([]byte(idToken), jwt.WithKeySet(set), jwt.WithValidate(false)); err != nil {
			t.Fatalf("jwx verify: %v", err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestOIDCAuthorizationCodeFlow(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	// Discovery と JWKS。
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &disc) != nil || disc["issuer"] != testIssuer ||
		disc["token_endpoint"] != testIssuer+oidcToken || disc["jwks_uri"] != testIssuer+oidcKeys {
		t.Fatalf("discovery: %d %s", w.Code, w.Body)
	}
	if algs, _ := disc["id_token_signing_alg_values_supported"].([]any); !slices.Contains(algs, any("ML-DSA-65")) ||
		!slices.Contains(algs, any("ES256")) || slices.Contains(algs, any("RS256")) {
		t.Fatalf("id token algs: %v", algs)
	}

	code, cookie := p.login(t, "alice@example.com", nil)
	status, tok := p.exchange(t, code, nil)
	if status != 200 || tok["access_token"] == "" || tok["id_token"] == "" || tok["scope"] != "openid email" {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	alice := l.userID(t, "alice@example.com")
	if claims["iss"] != testIssuer || claims["aud"] != p.clientID || claims["azp"] != p.clientID || claims["sub"] != alice ||
		claims["nonce"] != p.nonce || claims["email"] != "alice@example.com" || claims["email_verified"] != true ||
		claims["sid"] == nil || claims["auth_time"] == nil || claims["amr"] == nil {
		t.Fatalf("id token claims: %v", claims)
	}
	// 内部 ID は出さない（ADR 0045）。
	if strings.Contains(l.out.String(), l.internalUserID(t, alice)) {
		t.Fatal("internal user id leaked")
	}
	// 同じコードは2度使えない。
	if status, out := p.exchange(t, code, nil); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", status, out)
	}
	if status, info := l.userinfo(t, tok["access_token"].(string)); status != 200 || info["sub"] != alice || info["email"] != "alice@example.com" {
		t.Fatalf("userinfo: %d %v", status, info)
	}
	// POST の本文の access_token でも受ける（OIDC Core 5.3.1）。
	if w := l.oidcDo(t, "POST", oidcUserinfo, url.Values{"access_token": {tok["access_token"].(string)}}, ""); w.Code != 200 ||
		!strings.Contains(w.Body.String(), alice) {
		t.Fatalf("userinfo POST: %d %s", w.Code, w.Body)
	}
	// client_secret_post（本文の client_id と client_secret）でも認証できる。nonce の無い認可要求も受け、ID トークンに
	// nonce を入れない。
	cp := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"nonce": nil}), nil, cookie))
	status, tp := p.exchange(t, cp, url.Values{"client_id": {p.clientID}, "client_secret": {p.secret}}, "Accept", "application/json")
	if status != 200 {
		t.Fatalf("client_secret_post: %d %v", status, tp)
	}
	if c := l.idClaims(t, tp["id_token"].(string), port.AlgES256); c["nonce"] != nil || c["sub"] != alice {
		t.Fatalf("id token without nonce: %v", c)
	}

	// ログイン済みならそのまま戻る。セッションの ID を入れ替えても sid は変わらない。
	l.advance(l.a.cfg.Security.Session.RotationInterval.D() + time.Second)
	w = l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			cookie = c.Value
		}
	}
	status, tok2 := p.exchange(t, p.code(t, w), nil)
	if status != 200 {
		t.Fatalf("second token: %d %v", status, tok2)
	}
	if c2 := l.idClaims(t, tok2["id_token"].(string), port.AlgES256); c2["sid"] != claims["sid"] {
		t.Fatalf("sid changed: %v -> %v", claims["sid"], c2["sid"])
	}

	// prompt=login はログイン画面へ戻す。prompt=none は未ログインならエラーで戻る。
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"prompt": {"login"}}), nil, cookie)); u.Path != "/login" {
		t.Fatalf("prompt=login: %s", u)
	}
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"prompt": {"none"}}), nil, ""))
	if u.Host != "rp.example.com" || u.Query().Get("error") != "login_required" || u.Query().Get("state") != p.state {
		t.Fatalf("prompt=none: %s", u)
	}
	// PKCE が無い要求は戻り先にエラーを返す。登録に無い戻り先には転送しない。
	q := url.Values{"client_id": {p.clientID}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {p.redirect}, "state": {"s"}}
	if u := location(t, l.oidcDo(t, "GET", oidcAuthorize+"?"+q.Encode(), nil, cookie)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("no pkce: %s", u)
	}
	q.Set("redirect_uri", "https://evil.example.com/cb")
	if w := l.oidcDo(t, "GET", oidcAuthorize+"?"+q.Encode(), nil, cookie); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("bad redirect_uri: %d %v", w.Code, w.Header())
	}
	q.Set("client_id", "cli_unknown")
	if w := l.oidcDo(t, "GET", oidcAuthorize+"?"+q.Encode(), nil, cookie); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("unknown client: %d %v", w.Code, w.Header())
	}

	// 誤った秘密・code_verifier・戻り先は拒む。
	c3 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.clientID+":wrong"))
	if status, out := p.exchange(t, c3, nil, "Authorization", bad); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("bad secret: %d %v", status, out)
	}
	c4 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	if status, out := p.exchange(t, c4, url.Values{"code_verifier": {strings.Repeat("a", 43)}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", status, out)
	}
	c5 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	if status, out := p.exchange(t, c5, url.Values{"redirect_uri": {"https://rp.example.com/other"}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("bad redirect at token: %d %v", status, out)
	}
	// 認可コードの期限。
	c6 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	l.advance(l.a.cfg.OIDC.CodeTTL.D() + time.Second)
	if status, out := p.exchange(t, c6, nil); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("expired code: %d %v", status, out)
	}

	// ログアウトすると、そのログインの系列のトークンは使えない。
	if code, _ := l.meDo(t, "POST", cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if status, out := l.userinfo(t, tok2["access_token"].(string)); status != 401 || out["error"] != "invalid_token" {
		t.Fatalf("userinfo after logout: %d %v", status, out)
	}
	if status, _ := l.userinfo(t, "atk_x.y"); status != 401 {
		t.Fatalf("garbage token: %d", status)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	if types["oidc.authorized"] != 3 {
		t.Fatalf("audit: %v", types)
	}
}

func TestOIDCPublicClientMLDSAAndOrg(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "id_token_signed_response_alg": "ML-DSA-65",
		"redirect_uris": []string{"http://127.0.0.1/cb"}})
	// 公開クライアントの loopback の戻り先はポートを問わない（RFC 8252 7.3）。
	p.redirect = "http://127.0.0.1:53111/cb"
	code, cookie := p.login(t, "bob@example.com", nil)
	status, tok := p.exchange(t, code, nil)
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgMLDSA65)
	if claims["org_id"] == nil || claims["org_id"] != l.activeOrgPublic(t, cookie) {
		t.Fatalf("org_id = %v (active %s)", claims["org_id"], l.activeOrgPublic(t, cookie))
	}
	header, _, _ := strings.Cut(tok["id_token"].(string), ".")
	h, _ := base64.RawURLEncoding.DecodeString(header)
	if !strings.Contains(string(h), `"alg":"ML-DSA-65"`) || !strings.Contains(string(h), `"kid":"sgk_`) {
		t.Fatalf("header: %s", h)
	}
	// 公開クライアントは秘密を送らない。別の連携先の client_id ではコードを使えない。
	other := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []string{"http://127.0.0.1/cb"}})
	other.redirect = p.redirect
	c2 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
	other.verifier = p.verifier
	if status, out := other.exchange(t, c2, nil); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code for another client: %d %v", status, out)
	}
}

func TestOIDCPrivateKeyJWT(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Import[jwk.Key](priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	_ = pub.Set(jwk.KeyIDKey, "rp-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	jwks, _ := json.Marshal(set)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": json.RawMessage(jwks)})
	sk, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = sk.Set(jwk.KeyIDKey, "rp-1")
	assertion := func(jti, aud string, exp time.Duration) string {
		now := l.a.deps.Clock.Now()
		tk, _ := jwt.NewBuilder().Issuer(p.clientID).Subject(p.clientID).Audience([]string{aud}).JwtID(jti).
			IssuedAt(now).Expiration(now.Add(exp)).Build()
		b, err := jwt.Sign(tk, jwt.WithKey(jwa.ES256(), sk))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	form := func(a string) url.Values {
		return url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a}}
	}
	code, cookie := p.login(t, "carol@example.com", nil)
	if status, out := p.exchange(t, code, form(assertion("j1", testIssuer+oidcToken, time.Minute))); status != 200 {
		t.Fatalf("token: %d %v", status, out)
	}
	// 同じ jti、別の aud、長すぎる exp は拒む。
	for name, a := range map[string]string{
		"replay":   assertion("j1", testIssuer+oidcToken, time.Minute),
		"aud":      assertion("j2", "https://other.example.com/token", time.Minute),
		"long exp": assertion("j3", testIssuer, time.Hour),
	} {
		c := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(nil), nil, cookie))
		if status, out := p.exchange(t, c, form(a)); status != 401 || out["error"] != "invalid_client" {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
}

// post は連携先として token・introspect・revoke を呼ぶ（client_secret_basic）。
func (p *rp) post(t *testing.T, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	var hdr []string
	if p.secret != "" {
		hdr = []string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(p.clientID)+":"+url.QueryEscape(p.secret)))}
	} else {
		form.Set("client_id", p.clientID)
	}
	w := p.l.oidcDo(t, "POST", path, form, "", hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (p *rp) refresh(t *testing.T, token string) (int, map[string]any) {
	t.Helper()
	return p.post(t, oidcToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}})
}

func (p *rp) introspect(t *testing.T, token string) map[string]any {
	t.Helper()
	status, out := p.post(t, oidcIntrospect, url.Values{"token": {token}})
	if status != 200 {
		t.Fatalf("introspect: %d %v", status, out)
	}
	return out
}

func TestOIDCRefreshIntrospectRevoke(t *testing.T) {
	l := newLoginEnvWith(t, withIssuer, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	if disc["introspection_endpoint"] != testIssuer+oidcIntrospect || disc["revocation_endpoint"] != testIssuer+oidcRevoke {
		t.Fatalf("discovery: %v", disc)
	}
	if gt, _ := disc["grant_types_supported"].([]any); !slices.Contains(gt, any("refresh_token")) {
		t.Fatalf("grant types: %v", gt)
	}

	code, _ := p.login(t, "alice@example.com", nil)
	_, tok := p.exchange(t, code, nil)
	rt, _ := tok["refresh_token"].(string)
	if !strings.HasPrefix(rt, "rtk_") {
		t.Fatalf("refresh token: %v", tok)
	}
	alice := l.userID(t, "alice@example.com")
	if in := p.introspect(t, tok["access_token"].(string)); in["active"] != true || in["sub"] != alice || in["client_id"] != p.clientID ||
		in["token_type"] != "access_token" || in["scope"] != "openid email" || in["iss"] != testIssuer {
		t.Fatalf("introspect access: %v", in)
	}

	// リフレッシュするたびに新しいリフレッシュトークンに替わる。ID トークンの sid は変わらない。
	l.advance(time.Minute)
	status, tok2 := p.refresh(t, rt)
	if status != 200 || tok2["refresh_token"] == rt || tok2["access_token"] == tok["access_token"] || tok2["id_token"] == nil {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	if c1, c2 := l.idClaims(t, tok["id_token"].(string), port.AlgES256), l.idClaims(t, tok2["id_token"].(string), port.AlgES256); c1["sid"] != c2["sid"] ||
		c2["nonce"] != nil {
		t.Fatalf("refreshed id token: %v", c2)
	}
	if in := p.introspect(t, rt); in["active"] != false || len(in) != 1 {
		t.Fatalf("used refresh token: %v", in)
	}
	// 使用済みのリフレッシュトークンが再び来たら、認可ごと失効させる（新しいトークンも使えない）。
	if status, out := p.refresh(t, rt); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out)
	}
	if status, out := p.refresh(t, tok2["refresh_token"].(string)); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("after reuse: %d %v", status, out)
	}
	if status, _ := l.userinfo(t, tok2["access_token"].(string)); status != 401 {
		t.Fatalf("access token after reuse: %d", status)
	}

	// 失効（RFC 7009）。知らないトークンも 200。失効させた認可のトークンは非アクティブ。
	code, _ = p.login(t, "alice@example.com", nil)
	_, tok3 := p.exchange(t, code, nil)
	if status, _ := p.post(t, oidcRevoke, url.Values{"token": {"rtk_unknown.x"}}); status != 200 {
		t.Fatalf("revoke unknown: %d", status)
	}
	other := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if status, _ := other.post(t, oidcRevoke, url.Values{"token": {tok3["refresh_token"].(string)}}); status != 200 {
		t.Fatalf("revoke by other: %d", status)
	}
	if in := p.introspect(t, tok3["access_token"].(string)); in["active"] != true {
		t.Fatalf("revoked by another client: %v", in)
	}
	// 別の連携先（リソースサーバー）も確認できる。
	if in := other.introspect(t, tok3["access_token"].(string)); in["active"] != true || in["client_id"] != p.clientID {
		t.Fatalf("introspect by resource server: %v", in)
	}
	if status, _ := p.post(t, oidcRevoke, url.Values{"token": {tok3["access_token"].(string)}}); status != 200 {
		t.Fatalf("revoke: %d", status)
	}
	if in := p.introspect(t, tok3["refresh_token"].(string)); in["active"] != false {
		t.Fatalf("after revoke: %v", in)
	}

	// 停止はイントロスペクションにすぐ反映される。
	code, _ = p.login(t, "alice@example.com", nil)
	_, tok4 := p.exchange(t, code, nil)
	if in := p.introspect(t, tok4["access_token"].(string)); in["active"] != true {
		t.Fatalf("before suspension: %v", in)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+alice+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "x"}); status != 201 {
		t.Fatalf("suspend: %d %v", status, out)
	}
	if in := p.introspect(t, tok4["access_token"].(string)); in["active"] != false {
		t.Fatalf("after suspension: %v", in)
	}
	if status, out := p.refresh(t, tok4["refresh_token"].(string)); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after suspension: %d %v", status, out)
	}

	// イントロスペクションは機密の連携先だけ。公開クライアントは invalid_client、誤った秘密は 401。
	pub := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	if status, out := pub.post(t, oidcIntrospect, url.Values{"token": {tok4["access_token"].(string)}}); status != 400 || out["error"] != "invalid_client" {
		t.Fatalf("public introspect: %d %v", status, out)
	}
	bad := &rp{l: l, clientID: p.clientID, secret: "wrong"}
	if status, out := bad.post(t, oidcIntrospect, url.Values{"token": {tok4["access_token"].(string)}}); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("bad secret introspect: %d %v", status, out)
	}

	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	// 失効は連携先によるものと、停止で系列が終わったもの。
	if types["oidc.refresh_reused"] != 1 || types["oidc.grant_revoked"] != 2 {
		t.Fatalf("audit: %v", types)
	}
	if strings.Contains(l.out.String(), l.internalUserID(t, alice)) {
		t.Fatal("internal user id leaked")
	}
}
