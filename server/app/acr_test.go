package app

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// acr・AAL と step-up（フィーチャー acr、ADR 0093）を HTTP で確かめる。

func newACREnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.Password, feature.OrgLoginPolicy)
		if on {
			names = append(names, feature.ACR)
		}
		c.Features = &names
		c.Security.Password.Argon2 = config.Argon2{MemoryKiB: 8, Iterations: 1, Parallelism: 1}
	}, feature.Registered())
}

const acrPassword = "a long and memorable passphrase"

// strongUser はパスワードと TOTP を登録したユーザーを作り、TOTP の秘密を返す。
func (l *loginEnv) strongUser(t *testing.T, email string) []byte {
	t.Helper()
	_, cookie := l.login(t, email)
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": acrPassword}); status != 204 {
		t.Fatalf("set password: %d %v", status, res)
	}
	secret, status, res, _ := l.enrollTOTP(t, cookie)
	if status != 200 {
		t.Fatalf("totp: %d %v", status, res)
	}
	return secret
}

// strongLogin はパスワードと TOTP でログインし（amr は pwd・otp・mfa で AAL2）、セッションの Cookie を返す。
func (l *loginEnv) strongLogin(t *testing.T, email string, secret []byte) string {
	t.Helper()
	l.advance(30 * time.Second) // TOTP の同じ窓のコードは2度使えない
	status, res, restricted := l.passwordLogin(t, email, acrPassword)
	if status != 200 || res["next"] != "second_factor" {
		t.Fatalf("password login: %d %v", status, res)
	}
	status, res, full := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if status != 200 || full == "" {
		t.Fatalf("second factor: %d %v", status, res)
	}
	if got := amr(t, l, full); !slices.Equal(got, []any{"pwd", "otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	return full
}

func fetchDiscovery(t *testing.T, l *loginEnv) map[string]any {
	t.Helper()
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &disc) != nil {
		t.Fatalf("discovery: %d %s", w.Code, w.Body)
	}
	return disc
}

// オフなら今の動作と同じ：acr を出さず、acr_values と claims を見ず、step-up の WWW-Authenticate も付けない。
func TestACRFeatureOff(t *testing.T) {
	l := newACREnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	disc := fetchDiscovery(t, l)
	if disc["acr_values_supported"] != nil || slices.Contains(disc["claims_supported"].([]any), any("acr")) {
		t.Fatalf("discovery: %v", disc)
	}
	code, cookie := p.login(t, "alice@example.com", url.Values{"acr_values": {acr.AAL2}, "claims": {"not json"}})
	status, tok := p.exchange(t, code, nil)
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	if c := l.idClaims(t, tok["id_token"].(string), port.AlgES256); c["acr"] != nil {
		t.Fatalf("id token acr: %v", c)
	}
	if _, info := l.userinfo(t, tok["access_token"].(string)); info["acr"] != nil {
		t.Fatalf("userinfo acr: %v", info)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["acr"] != nil {
		t.Fatalf("introspection acr: %v", in)
	}

	// aal_at_least と min_aal は保存できない。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/action-namespaces/app.payment", map[string]any{"requirements": map[string]any{
		"app.payment:send": map[string]any{"aal_at_least": 2}}}); code != 400 || out["error"] != "invalid_condition" {
		t.Fatalf("aal requirement without acr: %d %v", code, out)
	}
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	if code, out := l.putSettings(t, boss, acme, map[string]any{"login_policy": map[string]any{"min_aal": 2}}); code != 400 || out["error"] != "setting_invalid" {
		t.Fatalf("min_aal without acr: %d %v", code, out)
	}

	l.advance(l.a.cfg.Security.Session.MaxAuthAge.Default.D() + time.Minute)
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp:start", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("reauth without acr: %d %v", w.Code, w.Header())
	}
}

func TestACRIDTokenAndStepUp(t *testing.T) {
	l := newACREnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	disc := fetchDiscovery(t, l)
	if got := disc["acr_values_supported"]; !slices.Equal(anys(got), []any{acr.AAL1, acr.AAL2, acr.PHR}) ||
		!slices.Contains(disc["claims_supported"].([]any), any("acr")) {
		t.Fatalf("discovery: %v", disc)
	}

	// 要求が無ければ AAL の値。メールのコードだけのログインは AAL1。ID トークン・UserInfo・イントロスペクションで同じ値。
	code, weak := p.login(t, "alice@example.com", nil)
	status, tok := p.exchange(t, code, nil)
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	if c := l.idClaims(t, tok["id_token"].(string), port.AlgES256); c["acr"] != acr.AAL1 {
		t.Fatalf("id token acr: %v", c)
	}
	if _, info := l.userinfo(t, tok["access_token"].(string)); info["acr"] != acr.AAL1 {
		t.Fatalf("userinfo acr: %v", info)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["acr"] != acr.AAL1 {
		t.Fatalf("introspection acr: %v", in)
	}
	// リフレッシュしても同じ。
	if status, rt := p.refresh(t, tok["refresh_token"].(string)); status != 200 || l.idClaims(t, rt["id_token"].(string), port.AlgES256)["acr"] != acr.AAL1 {
		t.Fatalf("refresh: %d %v", status, rt)
	}
	// 満たす値を要求すれば、そのまま認可コードを返す（知らない値は捨てる）。
	c2 := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"acr_values": {"urn:example:gold " + acr.AAL1}}), nil, weak))
	if _, tok := p.exchange(t, c2, nil); l.idClaims(t, tok["id_token"].(string), port.AlgES256)["acr"] != acr.AAL1 {
		t.Fatalf("acr_values aal1: %v", tok)
	}

	// AAL2 を求めると、AAL1 のセッションはログイン画面へ回す（step-up）。prompt=none なら login_required。
	l.advance(time.Second)
	step := url.Values{"acr_values": {acr.AAL2}}
	u := location(t, l.oidcDo(t, "GET", p.authorizeURL(step), nil, weak))
	if u.Path != "/login" {
		t.Fatalf("step-up: %s", u)
	}
	back, state := u.Query().Get("return_to"), p.state
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"acr_values": {acr.AAL2}, "prompt": {"none"}}), nil, weak)); u.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none: %s", u)
	}
	// 戻ってもログインし直していなければ、もう一度ログイン画面へ。
	if u := location(t, l.oidcDo(t, "GET", back, nil, weak)); u.Path != "/login" {
		t.Fatalf("resume without login: %s", u)
	}
	// ログインし直しても AAL1 なら、連携先に unmet_authentication_requirements を返す。
	l.advance(time.Second)
	_, again := l.login(t, "alice@example.com")
	u = location(t, l.oidcDo(t, "GET", back, nil, again))
	if u.Host != "rp.example.com" || u.Query().Get("error") != "unmet_authentication_requirements" || u.Query().Get("state") != state {
		t.Fatalf("unmet: %s", u)
	}

	// パスワードと TOTP で入り直せば AAL2 で戻る。要求の順で最初に満たす値を返す（phr は passkey が要る）。
	secret := l.strongUser(t, "bob@example.com")
	u = location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"acr_values": {acr.PHR + " " + acr.AAL2}}), nil, ""))
	back = u.Query().Get("return_to")
	strong := l.strongLogin(t, "bob@example.com", secret)
	status, tok = p.exchange(t, p.code(t, l.oidcDo(t, "GET", back, nil, strong)), nil)
	if status != 200 || l.idClaims(t, tok["id_token"].(string), port.AlgES256)["acr"] != acr.AAL2 {
		t.Fatalf("aal2: %d %v", status, tok)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["acr"] != acr.AAL2 {
		t.Fatalf("introspection aal2: %v", in)
	}
	// メールのコードと TOTP は、どちらも otp なので AAL1 にとどまる（ADR 0093）。
	_, restricted := l.login(t, "bob@example.com")
	l.advance(30 * time.Second)
	_, _, emailTOTP := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(step), nil, emailTOTP)); u.Path != "/login" {
		t.Fatalf("email + totp must not satisfy aal2: %s", u)
	}

	// claims パラメーターの id_token.acr（essential の有無を問わない）も受ける。JSON でなければ invalid_request。
	claims := `{"id_token":{"acr":{"essential":true,"values":["` + acr.AAL2 + `"]}}}`
	status, tok = p.exchange(t, p.code(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"claims": {claims}}), nil, strong)), nil)
	if status != 200 || l.idClaims(t, tok["id_token"].(string), port.AlgES256)["acr"] != acr.AAL2 {
		t.Fatalf("claims acr: %d %v", status, tok)
	}
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"claims": {claims}}), nil, weak)); u.Path != "/login" {
		t.Fatalf("claims acr step-up: %s", u)
	}
	if u := location(t, l.oidcDo(t, "GET", p.authorizeURL(url.Values{"claims": {"{"}}), nil, strong)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("bad claims: %s", u)
	}

	// 止めた後は、前に作った認可でも acr を載せない。
	enabled := slices.DeleteFunc(slices.Clone(*l.e.cfg.Features), func(n string) bool { return n == feature.ACR })
	if _, err := l.restart(t, enabled, feature.Registered()); err != nil {
		t.Fatal(err)
	}
	status, rt := p.refresh(t, tok["refresh_token"].(string))
	if status != 200 || l.idClaims(t, rt["id_token"].(string), port.AlgES256)["acr"] != nil {
		t.Fatalf("refresh after disabling: %d %v", status, rt)
	}
	if in := p.introspect(t, rt["access_token"].(string)); in["active"] != true || in["acr"] != nil {
		t.Fatalf("introspection after disabling: %v", in)
	}
}

func anys(v any) []any {
	s, _ := v.([]any)
	return s
}

// iam 自身の公開 API の step-up：直近の認証や AAL が足りない 401 に、RFC 9470 の WWW-Authenticate を足す（本文は変えない）。
func TestACRStepUpChallenge(t *testing.T) {
	l := newACREnv(t, true)
	_, op := l.operator(t, "root@example.com", role.RealmOwner)
	// 名前空間 me の要件（me:delete だけ）。aal_at_least は acr_values で求める。
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/action-namespaces/me", map[string]any{"requirements": map[string]any{
		role.ActionMeDelete: map[string]any{"all": []any{map[string]any{"aal_at_least": 2}, map[string]any{"auth_within": 120}}}}}); code != 200 {
		t.Fatalf("put me: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	maxAge := int(l.a.cfg.Security.Session.MaxAuthAge.Default.D() / time.Second)

	l.advance(time.Duration(maxAge+60) * time.Second)
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp:start", nil, "Cookie", sessionCookie+"="+cookie)
	want := `Bearer error="insufficient_user_authentication", error_description="a stronger or more recent authentication is required", max_age="` +
		itoa(maxAge) + `"`
	if w.Code != 401 || !strings.Contains(w.Body.String(), "reauthentication_required") || w.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("stale: %d %s %q", w.Code, w.Body, w.Header().Get("WWW-Authenticate"))
	}
	// 未ログインの 401 には付けない。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp:start", nil); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("anonymous: %d %v", w.Code, w.Header())
	}

	_, cookie = l.login(t, "alice@example.com")
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/me/account:delete", nil, "Cookie", sessionCookie+"="+cookie)
	want = `Bearer error="insufficient_user_authentication", error_description="a stronger or more recent authentication is required", acr_values="` + acr.AAL2 + `"`
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("aal: %d %s %q", w.Code, w.Body, w.Header().Get("WWW-Authenticate"))
	}
	// 判定の API も、同じ手がかりを step_up で返す（Org の要件。Org のオーナーは org:invite を持つ）。
	acme := l.sharedOrg(t, cookie, "Acme")
	if code, out := l.putSettings(t, cookie, acme, map[string]any{"requirements": map[string]any{
		"org:invite": map[string]any{"any": []any{map[string]any{"aal_at_least": 2}, map[string]any{"auth_within": 120}}}}}); code != 200 {
		t.Fatalf("org requirements: %d %v", code, out)
	}
	l.advance(5 * time.Minute)
	code, out := l.meDo(t, "POST", cookie, "/v1/me:check", map[string]any{"action": "org:invite", "org_id": acme})
	if su, _ := out["step_up"].(map[string]any); code != 200 || out["allowed"] != false || su["acr_values"] != acr.AAL2 || su["max_age"] != float64(120) {
		t.Fatalf("me:check: %d %v", code, out)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Org のログインポリシーの min_aal：AAL の足りないセッションはその Org に入れない（理由は policy.min_aal）。
func TestACROrgLoginPolicyMinAAL(t *testing.T) {
	l := newACREnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	secret := l.strongUser(t, "pat@acme.example")
	l.advance(time.Second)

	for _, v := range []int{4, -1} {
		if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"min_aal": v}}); code != 400 || out["error"] != "setting_invalid" {
			t.Fatalf("min_aal %d: %d %v", v, code, out)
		}
	}
	code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"min_aal": 2}})
	if code != 200 || out["settings"].(map[string]any)["login_policy"].(map[string]any)["min_aal"] != float64(2) {
		t.Fatalf("put min_aal: %d %v", code, out)
	}
	// メールのコードと TOTP（AAL1）では入れない。切り替えは 403。
	res, restricted := l.login(t, "pat@acme.example")
	if res["next"] != "second_factor" {
		t.Fatalf("login: %v", res)
	}
	l.advance(30 * time.Second)
	_, res, weak := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if res["org_id"] == acme {
		t.Fatalf("entered acme with aal1: %v", res)
	}
	if code, body, _ := l.post(t, weak, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.min_aal" {
		t.Fatalf("switch with aal1: %d %v", code, body)
	}
	// パスワードと TOTP（AAL2）なら入れる。
	strong := l.strongLogin(t, "pat@acme.example", secret)
	if code, body, _ := l.post(t, strong, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch with aal2: %d %v", code, body)
	}
}
