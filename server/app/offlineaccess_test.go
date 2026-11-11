package app

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"

	"github.com/imohiyoko/iam/authn/dpop/dpoptest"
	"github.com/imohiyoko/iam/authn/method/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// フィーチャー offline_access（OIDC Core 11。ADR 0126）を HTTP で確かめる。

func newOfflineEnv(t *testing.T, on bool, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		c.Passkey.Origins = []string{passkeyOrigin}
		names := slices.Clone(extra)
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.OfflineAccess)
		}
		c.Features = &names
	}, feature.Registered())
}

var offlineScope = url.Values{"scope": {"openid email offline_access"}}

func (l *loginEnv) discoveryScopes(t *testing.T) []any {
	t.Helper()
	var disc map[string]any
	_ = json.Unmarshal(l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "").Body.Bytes(), &disc)
	s, _ := disc["scopes_supported"].([]any)
	return s
}

func TestOfflineAccessOff(t *testing.T) {
	l := newOfflineEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "App", "redirect_uris": []string{"https://rp.example.com/cb"},
		"token_endpoint_auth_method": "client_secret", "offline_access": true}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("offline_access while off: %d %v", code, out)
	}
	if slices.Contains(l.discoveryScopes(t), any("offline_access")) {
		t.Fatal("offline_access advertised while off")
	}
	// スコープを求めても、ふつうの認可（ログアウトで失効し、offline_access は付かない）。
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	code, cookie := p.login(t, "alice@example.com", offlineScope)
	_, tok := p.exchange(t, code, nil)
	if tok["scope"] != "openid email" {
		t.Fatalf("scope: %v", tok)
	}
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after logout: %d", status)
	}
	if status, _ := l.meGet(t, cookie, "/v1/me/offline-access"); status != 401 {
		t.Fatalf("me after logout: %d", status)
	}
	_, cookie = l.login(t, "alice@example.com")
	if status, _ := l.meGet(t, cookie, "/v1/me/offline-access"); status != 404 {
		t.Fatalf("me while off: %d", status)
	}
}

func TestOfflineAccess(t *testing.T) {
	l := newOfflineEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if !slices.Contains(l.discoveryScopes(t), any("offline_access")) {
		t.Fatal("offline_access not advertised")
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true, "name": "Mail"})
	plain := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	// 許していない連携先では offline_access を外したふつうの認可。
	code, cookie := plain.login(t, "alice@example.com", offlineScope)
	_, ptok := plain.exchange(t, code, nil)
	if ptok["scope"] != "openid email" {
		t.Fatalf("plain scope: %v", ptok)
	}
	// 許した連携先では Offline の認可。ログアウトしても残る。
	c := p.code(t, l.oidcDo(t, "GET", p.authorizeURL(offlineScope), nil, cookie))
	_, tok := p.exchange(t, c, nil)
	if tok["scope"] != "openid email offline_access" {
		t.Fatalf("offline scope: %v", tok)
	}
	status, apps := l.meGet(t, cookie, "/v1/me/offline-access")
	list, _ := apps["applications"].([]any)
	if status != 200 || len(list) != 1 || list[0].(map[string]any)["client_id"] != p.clientID || list[0].(map[string]any)["name"] != "Mail" {
		t.Fatalf("me list: %d %v", status, apps)
	}
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := plain.refresh(t, ptok["refresh_token"].(string)); status != 400 {
		t.Fatalf("plain refresh after logout: %d", status)
	}
	l.advance(48 * time.Hour) // セッションの期限を過ぎても使える
	status, tok2 := p.refresh(t, tok["refresh_token"].(string))
	if status != 200 || tok2["scope"] != "openid email offline_access" {
		t.Fatalf("offline refresh after logout: %d %v", status, tok2)
	}
	if in := p.introspect(t, tok2["access_token"].(string)); in["active"] != true {
		t.Fatalf("introspect: %v", in)
	}
	if status, info := l.userinfo(t, tok2["access_token"].(string)); status != 200 || info["email"] != "alice@example.com" {
		t.Fatalf("userinfo: %d %v", status, info)
	}

	// 本人の取り消し。
	code, cookie = p.login(t, "alice@example.com", offlineScope)
	_, tok = p.exchange(t, code, nil)
	if status, _ := l.mePost(t, cookie, "/v1/me/offline-access/"+plain.clientID+":revoke", nil); status != 404 {
		t.Fatalf("revoke plain: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/offline-access/"+p.clientID+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/offline-access/"+p.clientID+":revoke", nil); status != 404 {
		t.Fatalf("revoke again: %d", status)
	}
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after user revoke: %d", status)
	}
	if e := l.lastAudit(t, "oidc.grant_revoked"); e.Details["reason"] != "revoked_by_user" {
		t.Fatalf("audit: %+v", e)
	}

	// 運営者がセッションを失効させれば、Offline の認可も一緒に失効する（時計を進めたので運営者は入り直す）。
	_, owner = l.operator(t, "root2@example.com", role.RealmOwner)
	alice := l.userID(t, "alice@example.com")
	code, _ = p.login(t, "alice@example.com", offlineScope)
	_, tok = p.exchange(t, code, nil)
	if code, out := l.admin(t, "/v1/admin/users/"+alice+"/sessions:revoke-all", owner, nil); code != 200 {
		t.Fatalf("revoke-all: %d %v", code, out)
	}
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after operator revoke: %d", status)
	}

	// 停止（ログアウトの後でも）。
	code, cookie = p.login(t, "alice@example.com", offlineScope)
	_, tok = p.exchange(t, code, nil)
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+alice+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "x"}); status != 201 {
		t.Fatalf("suspend: %d %v", status, out)
	}
	if in := p.introspect(t, tok["access_token"].(string)); in["active"] != false {
		t.Fatalf("introspect after suspension: %v", in)
	}
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after suspension: %d", status)
	}
}

func TestOfflineAccessClientAndDisable(t *testing.T) {
	l := newOfflineEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true})
	code, cookie := p.login(t, "alice@example.com", offlineScope)
	_, tok := p.exchange(t, code, nil)
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	// 連携先の許可を外せば使えない。
	put := func(on bool) {
		t.Helper()
		body := map[string]any{"name": "RP", "redirect_uris": []string{p.redirect}, "token_endpoint_auth_method": "client_secret", "offline_access": on}
		if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/clients/"+p.clientID, body); code != 200 || (out["offline_access"] == true) != on {
			t.Fatalf("update client: %d %v", code, out)
		}
	}
	put(false)
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after client opt-out: %d", status)
	}
	put(true)

	// 無効化の片付け：連携先の許可 1 つと Offline の認可 2 つ（許可を外していた間に使えなくなったものも消す）。
	code, _ = p.login(t, "alice@example.com", offlineScope)
	p.exchange(t, code, nil)
	ctx := context.Background()
	res, err := l.a.DisableFeature(ctx, feature.OfflineAccess, true)
	if err != nil || !res.Done || res.Purged != 3 {
		t.Fatalf("disable: %+v %v", res, err)
	}
	if strings.Contains(l.out.String(), l.internalUserID(t, l.userID(t, "alice@example.com"))) {
		t.Fatal("internal user id leaked")
	}
}

// TestOfflineAccessLifetime は、無操作の期限（既定 30 日。使うたびに延びる）と認可の寿命（既定 365 日。延びない）を確かめる。
func TestOfflineAccessLifetime(t *testing.T) {
	l := newOfflineEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true})
	code, cookie := p.login(t, "alice@example.com", offlineScope)
	_, tok := p.exchange(t, code, nil)
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	rt := tok["refresh_token"].(string)
	for day := 29; day < 365; day += 29 {
		l.advance(29 * 24 * time.Hour)
		status, next := p.refresh(t, rt)
		if status != 200 {
			t.Fatalf("refresh on day %d: %d %v", day, status, next)
		}
		rt = next["refresh_token"].(string)
	}
	l.advance(29 * 24 * time.Hour) // 377 日目：無操作の期限の内でも、認可の寿命を過ぎた
	if status, _ := p.refresh(t, rt); status != 400 {
		t.Fatalf("refresh after max lifetime: %d", status)
	}

	code, cookie = p.login(t, "alice@example.com", offlineScope)
	_, tok = p.exchange(t, code, nil)
	l.advance(31 * 24 * time.Hour)
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after idle: %d", status)
	}
	if status, apps := l.meGet(t, cookie, "/v1/me/offline-access"); status == 200 {
		t.Fatalf("session should have expired: %v", apps)
	}
}

// TestOfflineAccessCredentialChange は、ログアウトで残した Offline の認可が、その後の別のログインでの認証情報の変更
// （パスワードの設定）で失効し、変更したログインの系列の認可は残ることを確かめる。
func TestOfflineAccessCredentialChange(t *testing.T) {
	l := newOfflineEnv(t, true, feature.Password)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true})
	code, cookie := p.login(t, "alice@example.com", offlineScope)
	_, old := p.exchange(t, code, nil)
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	code, cookie = p.login(t, "alice@example.com", offlineScope)
	_, kept := p.exchange(t, code, nil)
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": "a long and memorable passphrase"}); status != 204 {
		t.Fatalf("password: %d %v", status, res)
	}
	if status, _ := p.refresh(t, old["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh of a logged-out grant after password change: %d", status)
	}
	if status, _ := p.refresh(t, kept["refresh_token"].(string)); status != 200 {
		t.Fatalf("refresh of the kept lineage: %d", status)
	}
}

// TestOfflineAccessRemovedEmail は、ログインに使ったメールを本人から外すと、そのログインの Offline の認可が使えなくなることを確かめる。
func TestOfflineAccessRemovedEmail(t *testing.T) {
	l := newOfflineEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true})
	_, cookie := l.login(t, "alice@example.com")
	l.advance(time.Second)
	if status, res := l.addEmail(t, cookie, "alice@work.example"); status != 200 {
		t.Fatalf("add email: %d %v", status, res)
	}
	work := l.methods(t, cookie).Emails[1].ID
	code, wcookie := p.login(t, "alice@work.example", offlineScope)
	_, tok := p.exchange(t, code, nil)
	if status, _, _ := l.post(t, wcookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	status, next := p.refresh(t, tok["refresh_token"].(string))
	if status != 200 {
		t.Fatalf("refresh before removal: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/emails/"+work+":remove", nil); status != 204 {
		t.Fatalf("remove email: %d", status)
	}
	if status, _ := p.refresh(t, next["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after removing the login email: %d", status)
	}
}

// TestOfflineAccessRecovery は、アカウントの復旧が、ログアウト済みの系列の Offline の認可も失効させることを確かめる。
func TestOfflineAccessRecovery(t *testing.T) {
	l := newOfflineEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "offline_access": true})
	code, cookie := p.login(t, "pat@example.com", offlineScope)
	_, tok := p.exchange(t, code, nil)
	if _, status, _, _ := l.enrollTOTP(t, cookie); status != 200 {
		t.Fatal("totp")
	}
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	_, st := l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"})
	code = l.claimLast(t)
	status, out, rec := l.post(t, "", "/v1/recovery/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("verify: %d %v", status, out)
	}
	l.advance(time.Second)
	if status, res := l.registerPasskey(t, rec, passkeytest.New(passkeyOrigin), "Key"); status != 200 {
		t.Fatalf("register in recovery: %d %v", status, res)
	}
	if status, out := l.mePost(t, rec, "/v1/recovery:complete", nil); status != 200 {
		t.Fatalf("complete: %d %v", status, out)
	}
	if status, _ := p.refresh(t, tok["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh after recovery: %d", status)
	}
}

// TestOfflineAccessNoRotation は、リフレッシュトークンをローテーションしない FAPI 2.0 の連携先でも、使うたびに無操作の期限が延び、
// 使わなければ切れることを確かめる。
func TestOfflineAccessNoRotation(t *testing.T) {
	l := fapi2Env(t, nil, feature.OfflineAccess)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := registerFAPI2(t, l, owner, map[string]any{"offline_access": true})
	h := l.a.PublicHandler()
	k := dpoptest.NewKey(t)
	par, token := testIssuer+oidcPAR, testIssuer+oidcToken
	w, out := l.form(t, h, "POST", oidcPAR, withForm(p.pushForm(offlineScope), p.assertion(t, jwa.PS256())), nil, "DPoP", l.proof(t, k, "POST", par, "", ""))
	if w.Code != 201 {
		t.Fatalf("push: %d %v", w.Code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	code := p.code(t, l.oidcDo(t, "GET", oidcAuthorize+"?"+url.Values{"client_id": {p.clientID}, "request_uri": {out["request_uri"].(string)}}.Encode(), nil, cookie))
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "code_verifier": {p.verifier}}
	w, tok := l.form(t, h, "POST", oidcToken, withForm(f, p.assertion(t, jwa.PS256())), nil, "DPoP", l.proof(t, k, "POST", token, "", ""))
	if w.Code != 200 || tok["scope"] != "openid email offline_access" {
		t.Fatalf("token: %d %v", w.Code, tok)
	}
	if status, _, _ := l.post(t, cookie, "/v1/logout", nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	refresh := func() int {
		f := withForm(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}, p.assertion(t, jwa.PS256()))
		w, out := l.form(t, h, "POST", oidcToken, f, nil, "DPoP", l.proof(t, k, "POST", token, "", ""))
		if w.Code == 200 && out["refresh_token"] != nil {
			t.Fatalf("rotated: %v", out)
		}
		return w.Code
	}
	for i := range 3 { // 87 日目まで、同じトークンを 29 日ごとに使う
		l.advance(29 * 24 * time.Hour)
		if st := refresh(); st != 200 {
			t.Fatalf("refresh %d: %d", i, st)
		}
	}
	l.advance(31 * 24 * time.Hour)
	if st := refresh(); st != 400 {
		t.Fatalf("refresh after idle: %d", st)
	}
}
