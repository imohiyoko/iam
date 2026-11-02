package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Device Authorization Grant（RFC 8628、ADR 0095）を HTTP で確かめる。

func deviceEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.DeviceFlow)
		}
		c.Features = &names
	}, feature.Registered())
}

// deviceRP は Device Authorization Grant を許した連携先を登録する（戻り先なし）。
func (l *loginEnv) deviceRP(t *testing.T, owner string, body map[string]any) *rp {
	t.Helper()
	body["name"], body["device_authorization_grant"] = "Living Room TV", true
	if body["redirect_uris"] == nil {
		body["redirect_uris"] = []string{}
	}
	code, out := l.admin(t, "/v1/admin/clients", owner, body)
	if code != 201 || out["device_authorization_grant"] != true {
		t.Fatalf("register device client: %d %v", code, out)
	}
	secret, _ := out["client_secret"].(string)
	return &rp{l: l, clientID: out["client_id"].(string), secret: secret}
}

// startDevice は device_authorization エンドポイントを呼ぶ。
func (p *rp) startDevice(t *testing.T, scope string) (int, map[string]any) {
	t.Helper()
	return p.post(t, oidcDeviceAuth, url.Values{"scope": {scope}})
}

func (p *rp) pollDevice(t *testing.T, deviceCode string) (int, map[string]any) {
	t.Helper()
	return p.post(t, oidcToken, url.Values{"grant_type": {provider.GrantTypeDeviceCode}, "device_code": {deviceCode}})
}

func TestDeviceFlowOff(t *testing.T) {
	l := deviceEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	gt, _ := disc["grant_types_supported"].([]any)
	if disc["device_authorization_endpoint"] != nil || slices.Contains(gt, any(provider.GrantTypeDeviceCode)) {
		t.Fatalf("discovery shows the device grant: %v", disc)
	}
	// 連携先に許可を付けられず、許可の有無も返さない。
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "TV", "redirect_uris": []string{},
		"token_endpoint_auth_method": "none", "device_authorization_grant": true}); code != 400 {
		t.Fatalf("device grant while off: %d %v", code, out)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+p.clientID, nil); code != 200 || out["device_authorization_grant"] != nil {
		t.Fatalf("client: %d %v", code, out)
	}
	// 戻り先の無い連携先は今までどおり登録できない。
	if code, _ := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "TV", "redirect_uris": []string{},
		"token_endpoint_auth_method": "none"}); code != 400 {
		t.Fatalf("no redirect uris: %d", code)
	}
	for _, path := range []string{oidcDeviceAuth, oidcDevice} {
		if w := l.oidcDo(t, "POST", path, url.Values{"client_id": {p.clientID}}, ""); w.Code != 404 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if status, out := p.pollDevice(t, "x"); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("device grant at token: %d %v", status, out)
	}
}

func TestDeviceFlow(t *testing.T) {
	l := deviceEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})

	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	if gt, _ := disc["grant_types_supported"].([]any); disc["device_authorization_endpoint"] != testIssuer+oidcDeviceAuth ||
		!slices.Contains(gt, any(provider.GrantTypeDeviceCode)) || !slices.Contains(gt, any("authorization_code")) {
		t.Fatalf("discovery: %v", disc)
	}

	// openid のスコープが要る。
	if status, out := p.startDevice(t, "email"); status != 400 || out["error"] != "invalid_scope" {
		t.Fatalf("without openid: %d %v", status, out)
	}
	status, dev := p.startDevice(t, "openid email profile")
	userCode, _ := dev["user_code"].(string)
	deviceCode, _ := dev["device_code"].(string)
	if status != 200 || deviceCode == "" || dev["verification_uri"] != testIssuer+oidcDevice || dev["expires_in"] != float64(600) ||
		dev["interval"] != float64(5) || dev["verification_uri_complete"] != testIssuer+oidcDevice+"?user_code="+userCode {
		t.Fatalf("device authorization: %d %v", status, dev)
	}
	if _, ok := provider.NormalizeUserCode(userCode); !ok {
		t.Fatalf("user code %q", userCode)
	}

	// 承認の前は authorization_pending、間隔より速ければ slow_down。
	if status, out := p.pollDevice(t, deviceCode); status != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", status, out)
	}
	if status, out := p.pollDevice(t, deviceCode); status != 400 || out["error"] != "slow_down" {
		t.Fatalf("slow down: %d %v", status, out)
	}

	// 未ログインなら、user_code を持ったままログイン画面へ。
	complete := strings.TrimPrefix(dev["verification_uri_complete"].(string), testIssuer)
	u := location303(t, l.oidcDo(t, "GET", complete, nil, ""))
	back := u.Query().Get("return_to")
	if u.Path != "/login" || back != complete || safeReturnTo(back) != back {
		t.Fatalf("login redirect: %s", u)
	}
	_, cookie := l.login(t, "alice@example.com")
	// 入力の画面と、確認の画面（連携先の名前・コード・スコープ）。user_code だけでは承認しない。
	if w := l.oidcDo(t, "GET", oidcDevice, nil, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `name="user_code"`) {
		t.Fatalf("enter page: %d %s", w.Code, w.Body)
	}
	w = l.oidcDo(t, "GET", oidcDevice+"?user_code="+url.QueryEscape(strings.ToLower(strings.ReplaceAll(userCode, "-", ""))), nil, cookie)
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, "Living Room TV") || !strings.Contains(body, userCode) ||
		!strings.Contains(body, "<li>email</li>") || strings.Contains(body, "profile") || !strings.Contains(body, `value="approve"`) ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatalf("confirm page: %d %s", w.Code, body)
	}
	if status, out := p.pollDevice(t, deviceCode); status != 400 || out["error"] == nil {
		t.Fatalf("not yet approved: %d %v", status, out)
	}
	// 別オリジンからの承認（CSRF）は受けない。
	if w := l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {userCode}, "action": {"approve"}}, cookie,
		"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"); w.Code != 403 {
		t.Fatalf("cross-origin approve: %d", w.Code)
	}
	// 許可か拒否かを選ばない送信は、何も記録しない。
	if w := l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {userCode}}, cookie); w.Code != 400 ||
		!strings.Contains(w.Body.String(), `value="approve"`) {
		t.Fatalf("no action: %d", w.Code)
	}
	w = l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {userCode}, "action": {"approve"}}, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `data-step="approved"`) {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	// user_code は1回だけ。
	if w := l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {userCode}, "action": {"deny"}}, cookie); w.Code != 400 {
		t.Fatalf("decide twice: %d", w.Code)
	}

	l.advance(time.Minute)
	status, tok := p.pollDevice(t, deviceCode)
	if status != 200 || tok["access_token"] == nil || tok["id_token"] == nil || tok["refresh_token"] == nil || tok["scope"] != "openid email" {
		t.Fatalf("token: %d %v", status, tok)
	}
	alice := l.userID(t, "alice@example.com")
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	if claims["sub"] != alice || claims["aud"] != p.clientID || claims["sid"] == nil || claims["nonce"] != nil || claims["email"] != "alice@example.com" {
		t.Fatalf("id token: %v", claims)
	}
	if status, info := l.userinfo(t, tok["access_token"].(string)); status != 200 || info["sub"] != alice {
		t.Fatalf("userinfo: %d %v", status, info)
	}
	// トークンは1回だけ出す。
	l.advance(time.Minute)
	if status, out := p.pollDevice(t, deviceCode); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("poll after tokens: %d %v", status, out)
	}
	// リフレッシュもでき、ログインの系列に結び付く（ログアウトで使えなくなる）。
	status, tok2 := p.refresh(t, tok["refresh_token"].(string))
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	if code, _ := l.meDo(t, "POST", cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if status, _ := l.userinfo(t, tok2["access_token"].(string)); status != 401 {
		t.Fatalf("token after logout: %d", status)
	}

	// 拒否すれば access_denied。
	_, cookie = l.login(t, "alice@example.com")
	_, dev = p.startDevice(t, "openid")
	l.oidcDo(t, "POST", oidcDevice, url.Values{"user_code": {dev["user_code"].(string)}, "action": {"deny"}}, cookie)
	if status, out := p.pollDevice(t, dev["device_code"].(string)); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("denied: %d %v", status, out)
	}
	// 期限を過ぎれば expired_token。
	_, dev = p.startDevice(t, "openid")
	l.advance(l.a.cfg.OIDC.DeviceCodeTTL.D())
	if status, out := p.pollDevice(t, dev["device_code"].(string)); status != 400 || out["error"] != "expired_token" {
		t.Fatalf("expired: %d %v", status, out)
	}
	if w := l.oidcDo(t, "GET", oidcDevice+"?user_code="+url.QueryEscape(dev["user_code"].(string)), nil, cookie); w.Code != 400 {
		t.Fatalf("expired user code: %d", w.Code)
	}

	types := map[string]map[string]any{}
	for _, e := range l.auditTypes(t) {
		types[e.Type] = e.Details
	}
	if types["oidc.device_approved"]["client_id"] != p.clientID || types["oidc.device_denied"] == nil ||
		types["oidc.authorized"]["grant_type"] != provider.GrantTypeDeviceCode {
		t.Fatalf("audit: %v", types)
	}
	// 秘密（device_code）は監査ログに残さない。
	for _, e := range l.auditTypes(t) {
		if b, _ := json.Marshal(e); strings.Contains(string(b), deviceCode) {
			t.Fatalf("device code in audit log: %s", b)
		}
	}
}

func TestDeviceFlowClients(t *testing.T) {
	l := deviceEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	// 許可していない連携先は使えない。
	web := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if status, out := web.startDevice(t, "openid"); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("not allowed: %d %v", status, out)
	}
	if status, out := web.pollDevice(t, "x"); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("not allowed at token: %d %v", status, out)
	}
	// 機密の連携先は認証が要る。別の連携先の device_code は使えない。
	tv := l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if w := l.oidcDo(t, "POST", oidcDeviceAuth, url.Values{"client_id": {tv.clientID}, "scope": {"openid"}}, ""); w.Code != 401 {
		t.Fatalf("no client auth: %d %s", w.Code, w.Body)
	}
	_, dev := tv.startDevice(t, "openid")
	other := l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	if status, out := other.pollDevice(t, dev["device_code"].(string)); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("other client: %d %v", status, out)
	}

	// 承認の前に許可を外せば、その要求は承認できない。
	_, cookie := l.login(t, "bob@example.com")
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+tv.clientID, map[string]any{"name": "TV", "redirect_uris": []string{"https://tv.example.com/cb"},
		"token_endpoint_auth_method": "client_secret"}); code != 200 || out["device_authorization_grant"] != false {
		t.Fatalf("update: %d %v", code, out)
	}
	if w := l.oidcDo(t, "GET", oidcDevice+"?user_code="+url.QueryEscape(dev["user_code"].(string)), nil, cookie); w.Code != 400 {
		t.Fatalf("user code of a disallowed client: %d", w.Code)
	}

	// user_code の照合は本人ごとに数える（総当たりを防ぐ。上の1回も数える）。
	limit := l.a.cfg.Security.Login.RateLimit.PerAccount
	for i := 1; i <= limit; i++ {
		w := l.oidcDo(t, "GET", oidcDevice+"?user_code=BCDF-GHJK", nil, cookie)
		if want := map[bool]int{true: 400, false: 429}[i < limit]; w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
}

func TestDisableDeviceFlowWithData(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		names := []string{}
		for _, f := range feature.Registered() {
			names = append(names, f.Name)
		}
		c.Features = &names
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "none"})
	disableWithData(t, l, feature.DeviceFlow, 1)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Clients().List(ctx, l.a.realm.ID)
		if err == nil && (len(cs) != 1 || cs[0].DeviceGrant) {
			t.Fatalf("clients after disable: %+v", cs)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// location303 は 303 の転送先を返す。
func location303(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d %s", w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestDeviceFlowE2EStandardRP は、ふつうの RP（zitadel/oidc の rp）が Discovery から Device Authorization Grant を使い、
// 本人が別のブラウザで承認したトークンを受け取ることを、本物の HTTPS のサーバーで確かめる。
func TestDeviceFlowE2EStandardRP(t *testing.T) {
	e := newE2E(t, feature.DeviceFlow)
	ctx := context.Background()
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	tv := e.l.deviceRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	relying, err := oidcrp.NewRelyingPartyOIDC(ctx, e.issuer, tv.clientID, tv.secret, "", []string{"openid", "email"}, oidcrp.WithHTTPClient(e.http))
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	dev, err := oidcrp.DeviceAuthorization(ctx, []string{"openid", "email"}, relying, nil)
	if err != nil || dev.VerificationURI != e.issuer+oidcDevice || dev.Interval != 5 {
		t.Fatalf("device authorization: %+v, %v", dev, err)
	}
	// 本人はブラウザで verification_uri_complete を開き、ログインして承認する。
	_, cookie := e.l.login(t, "alice@example.com")
	do := func(method, u string, form url.Values) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, u, strings.NewReader(form.Encode()))
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := do(http.MethodGet, dev.VerificationURIComplete, nil); resp.StatusCode != 200 {
		t.Fatalf("confirm page: %d", resp.StatusCode)
	}
	if resp := do(http.MethodPost, e.issuer+oidcDevice, url.Values{"user_code": {dev.UserCode}, "action": {"approve"}}); resp.StatusCode != 200 {
		t.Fatalf("approve: %d", resp.StatusCode)
	}
	tok, err := oidcrp.DeviceAccessToken(ctx, dev.DeviceCode, 10*time.Millisecond, relying)
	if err != nil || tok.AccessToken == "" || tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("device access token: %+v, %v", tok, err)
	}
	claims, err := oidcrp.VerifyIDToken[*oidc.IDTokenClaims](ctx, tok.IDToken, relying.IDTokenVerifier())
	if err != nil || claims.Subject != e.l.userID(t, "alice@example.com") || claims.SessionID == "" {
		t.Fatalf("id token: %+v, %v", claims, err)
	}
}
