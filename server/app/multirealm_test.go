package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 複数 realm（design.md 11.1、ADR 0083）を HTTP で確かめる。

const multiRealmURL = "https://id.example.com"

func multiRealmEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = multiRealmURL
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.MultiRealm)
		}
		c.Features = &names
	}, feature.Registered())
}

// realmClient は1つの realm に向けた要求を作る。base は /realms/{slug}、host はホスト名で指すときの Host。
type realmClient struct {
	l           *loginEnv
	base, host  string
	cookieName  string
	deliveryKey string
}

func (c realmClient) do(t *testing.T, admin bool, method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	h := c.l.a.PublicHandler()
	if admin {
		h = c.l.a.AdminHandler()
	}
	if c.host != "" {
		hdr = append(hdr, "Host", c.host)
	}
	r := httptest.NewRequest(method, c.base+path, jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			r.Host = hdr[i+1]
			continue
		}
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func jsonBody(body any) *strings.Reader {
	if body == nil {
		return strings.NewReader("")
	}
	b, _ := json.Marshal(body)
	return strings.NewReader(string(b))
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// login はこの realm でメールのコードでログインし、応答とセッションの Cookie を返す。
func (c realmClient) login(t *testing.T, email string) (map[string]any, string) {
	t.Helper()
	w := c.do(t, false, "POST", "/v1/login/email:start", map[string]string{"email": email})
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	flow := decode(t, w)["flow_id"].(string)
	if _, err := c.l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := c.l.notes.last(t)
	w = c.do(t, true, "POST", "/v1/admin/notifications/"+n.ID+":claim", nil, "Authorization", "Bearer "+c.deliveryKey)
	if w.Code != 200 {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	code := decode(t, w)["code"].(string)
	w = c.do(t, false, "POST", "/v1/login/email:verify", map[string]string{"flow_id": flow, "code": code})
	if w.Code != 200 {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.cookieName {
			return decode(t, w), ck.Value
		}
	}
	t.Fatalf("no session cookie %q in %v", c.cookieName, w.Result().Cookies())
	return nil, ""
}

// newRealm は既定の realm の運営者で realm を作り、配信用のサービスアカウントを用意する。
func (l *loginEnv) newRealm(t *testing.T, owner string, body map[string]any) (realmClient, map[string]any) {
	t.Helper()
	code, out := l.adminDo(t, "POST", owner, "/v1/admin/realms", body)
	if code != 201 {
		t.Fatalf("create realm: %d %v", code, out)
	}
	slug := body["slug"].(string)
	ra, err := l.a.RealmApp(slug)
	if err != nil {
		t.Fatal(err)
	}
	c := realmClient{l: l, cookieName: sessionCookie}
	if hosts, _ := body["hosts"].([]string); len(hosts) > 0 {
		c.host = hosts[0]
	} else {
		c.base, c.cookieName = realmPathPrefix+slug, sessionCookie+"."+slug
	}
	err = l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		sa, err := serviceaccount.Create(ctx, tx, ra.realm.ID, "notification-delivery", l.a.deps.Clock.Now())
		if err != nil {
			return err
		}
		c.deliveryKey = sa.APIKey
		return role.Grant(ctx, tx, ra.realm.ID, role.NotificationDelivery, port.PrincipalServiceAccount, sa.Account.ID, l.a.deps.Clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, out
}

func TestMultiRealm(t *testing.T) {
	l := multiRealmEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	acme, created := l.newRealm(t, owner, map[string]any{"slug": "acme", "settings": map[string]any{"org_creation": "operators_only"}})
	if created["issuer"] != multiRealmURL+"/realms/acme" || created["default"] != false {
		t.Fatalf("created realm = %v", created)
	}
	beta, created := l.newRealm(t, owner, map[string]any{"slug": "beta", "hosts": []string{"Beta.Example.com"}})
	if created["issuer"] != "https://beta.example.com" {
		t.Fatalf("host realm = %v", created)
	}
	beta.host = "beta.example.com:443"

	// 同じメールでも realm ごとに別のユーザー。
	def, defCookie := l.login(t, "alice@example.com")
	inAcme, acmeCookie := acme.login(t, "alice@example.com")
	inBeta, _ := beta.login(t, "alice@example.com")
	if inAcme["created"] != true || inBeta["created"] != true || inAcme["user_id"] == def["user_id"] || inAcme["user_id"] == inBeta["user_id"] {
		t.Fatalf("users: default %v, acme %v, beta %v", def, inAcme, inBeta)
	}
	// セッションは realm の外で効かない。
	if w := acme.do(t, false, "GET", "/v1/me/sessions", nil, "Cookie", acme.cookieName+"="+acmeCookie); w.Code != 200 {
		t.Fatalf("acme session in acme: %d %s", w.Code, w.Body)
	}
	if w := acme.do(t, false, "GET", "/v1/me/sessions", nil, "Cookie", acme.cookieName+"="+defCookie); w.Code != 401 {
		t.Fatalf("default session in acme: %d", w.Code)
	}
	if w := acme.do(t, false, "GET", "/v1/me/sessions", nil, "Authorization", "Bearer "+defCookie); w.Code != 401 {
		t.Fatalf("default token in acme: %d", w.Code)
	}

	// realm ごとの設定：acme では利用者が Org を作れない。
	if code, out := l.mePost(t, defCookie, "/v1/me/orgs", map[string]string{"name": "Default Co"}); code != 201 {
		t.Fatalf("org in default: %d %v", code, out)
	}
	if w := acme.do(t, false, "POST", "/v1/me/orgs", map[string]string{"name": "Acme Co"}, "Cookie", acme.cookieName+"="+acmeCookie); w.Code != 403 {
		t.Fatalf("org in acme: %d %s", w.Code, w.Body)
	}

	// OIDC は realm ごとの issuer と署名鍵。
	for _, c := range []struct {
		rc   realmClient
		want string
	}{{realmClient{l: l}, multiRealmURL}, {acme, multiRealmURL + "/realms/acme"}, {beta, "https://beta.example.com"}} {
		w := c.rc.do(t, false, "GET", "/.well-known/openid-configuration", nil)
		if d := decode(t, w); w.Code != 200 || d["issuer"] != c.want || d["jwks_uri"] != c.want+"/oauth2/keys" {
			t.Fatalf("discovery of %s: %d %v", c.want, w.Code, d)
		}
	}
	keysOf := func(rc realmClient) string {
		w := rc.do(t, false, "GET", "/oauth2/keys", nil)
		return w.Body.String()
	}
	if keysOf(realmClient{l: l}) == keysOf(acme) {
		t.Fatal("realms share signing keys")
	}

	// ログイン画面は realm の接頭辞で API と資源を指す。
	if w := acme.do(t, false, "GET", "/login", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `data-base="/realms/acme"`) ||
		!strings.Contains(w.Body.String(), `/realms/acme/login/assets/login.js`) {
		t.Fatalf("hosted login in acme: %d %s", w.Code, w.Body)
	}
	// パスで指す realm のフローの Cookie は realm ごとの名前にする（同じホストの realm で混ざらない）。
	if w := acme.do(t, false, "POST", "/v1/login/passkey:start", nil); w.Code != 200 ||
		!strings.Contains(w.Header().Get("Set-Cookie"), passkeyCookie+".acme=") {
		t.Fatalf("passkey flow cookie in acme: %d %v", w.Code, w.Header()["Set-Cookie"])
	}

	// 知らない realm、ホスト名を持つ realm のパスは 404。
	for _, path := range []string{"/realms/nope/v1/me/sessions", "/realms/beta/v1/me/sessions"} {
		if w := (realmClient{l: l}).do(t, false, "GET", path, nil); w.Code != 404 || decode(t, w)["error"] != "realm_not_found" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}

	// realm の管理は既定の realm だけ。
	ra, _ := l.a.RealmApp("acme")
	op, err := ra.CreateOperator(context.Background(), "ops@acme.example", role.RealmOwner, 0)
	if err == nil {
		t.Fatalf("ttl 0 accepted: %+v", op)
	}
	for _, ttl := range []int64{1, 86401, 1 << 62} {
		if code, out := l.adminDo(t, "POST", owner, "/v1/admin/realms/"+ra.realm.ID+"/operators", map[string]any{"email": "ops@acme.example", "ttl_seconds": ttl}); code != 400 || out["error"] != "invalid_ttl" {
			t.Fatalf("operator ttl %d: %d %v", ttl, code, out)
		}
	}
	code, opOut := l.adminDo(t, "POST", owner, "/v1/admin/realms/"+ra.realm.ID+"/operators", map[string]any{"email": "ops@acme.example"})
	if code != 201 || opOut["created"] != true || !strings.HasPrefix(opOut["login_url"].(string), multiRealmURL+"/realms/acme/login/link#token=") {
		t.Fatalf("realm operator: %d %v", code, opOut)
	}
	w := acme.do(t, false, "POST", "/v1/login/link:redeem", map[string]any{"token": opOut["login_token"], "return_token": true})
	if w.Code != 200 {
		t.Fatalf("redeem in acme: %d %s", w.Code, w.Body)
	}
	acmeOwner := decode(t, w)["token"].(string)
	if w := acme.do(t, true, "GET", "/v1/admin/realms", nil, "Authorization", "Bearer "+acmeOwner); w.Code != 404 ||
		decode(t, w)["error"] != "realm_management_unavailable" {
		t.Fatalf("realms from acme: %d %s", w.Code, w.Body)
	}
	if w := (realmClient{l: l}).do(t, false, "POST", "/v1/login/link:redeem", map[string]any{"token": opOut["login_token"]}); w.Code == 200 {
		t.Fatal("acme login link redeemed in the default realm")
	}

	// 一覧・変更・重複。
	code, list := l.adminDo(t, "GET", owner, "/v1/admin/realms", nil)
	if code != 200 || len(list["realms"].([]any)) != 3 {
		t.Fatalf("list: %d %v", code, list)
	}
	code, out := l.adminDo(t, "PATCH", owner, "/v1/admin/realms/"+ra.realm.ID, map[string]any{"hosts": []string{"acme.example.com"},
		"settings": map[string]any{"org_creation": "anyone"}})
	if code != 200 || out["issuer"] != "https://acme.example.com" {
		t.Fatalf("update: %d %v", code, out)
	}
	host := realmClient{l: l, host: "acme.example.com", cookieName: sessionCookie}
	if w := host.do(t, false, "POST", "/v1/me/orgs", map[string]string{"name": "Acme Co"}, "Authorization", "Bearer "+acmeCookie); w.Code != 201 {
		t.Fatalf("org in acme after update: %d %s", w.Code, w.Body)
	}
	if w := acme.do(t, false, "GET", "/v1/me/sessions", nil, "Authorization", "Bearer "+acmeCookie); w.Code != 404 {
		t.Fatalf("path of a realm with hosts: %d", w.Code)
	}
	for _, c := range []struct {
		method, path string
		body         map[string]any
		status       int
		code         string
	}{
		{"POST", "/v1/admin/realms", map[string]any{"slug": "acme"}, 409, "realm_taken"},
		{"POST", "/v1/admin/realms", map[string]any{"slug": "gamma", "hosts": []string{"beta.example.com"}}, 409, "realm_taken"},
		{"PATCH", "/v1/admin/realms/" + ra.realm.ID, map[string]any{"hosts": []string{"beta.example.com"}}, 409, "realm_taken"},
		{"POST", "/v1/admin/realms", map[string]any{"slug": "Bad Slug"}, 400, "invalid_slug"},
		{"POST", "/v1/admin/realms", map[string]any{"slug": "gamma", "hosts": []string{"10.0.0.1"}}, 400, "invalid_hosts"},
		{"POST", "/v1/admin/realms", map[string]any{"slug": "gamma", "settings": map[string]any{"timezone": "Mars/Base"}}, 400, "invalid_realm_settings"},
		{"PATCH", "/v1/admin/realms/" + l.a.realm.ID, map[string]any{"hosts": []string{}}, 409, "default_realm"},
		{"GET", "/v1/admin/realms/nope", nil, 404, "not_found"},
	} {
		if code, out := l.adminDo(t, c.method, owner, c.path, c.body); code != c.status || out["error"] != c.code {
			t.Fatalf("%s %s %v: %d %v", c.method, c.path, c.body, code, out)
		}
	}

	// 予約の処理と監査ログは出来事の realm で動く。
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	if types["realm.created"] < 3 || types["realm.updated"] != 1 {
		t.Fatalf("audit: %v", types)
	}

	// realm があるうちは無効にできない。
	if _, err := l.a.DisableFeature(context.Background(), feature.MultiRealm, true); err == nil {
		t.Fatal("disabled multi_realm with realms")
	}
}

func TestMultiRealmOff(t *testing.T) {
	l := multiRealmEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/realms", nil); code != 404 || out["error"] != "multi_realm_disabled" {
		t.Fatalf("realms off: %d %v", code, out)
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/realms/acme/v1/me/sessions", nil); w.Code == http.StatusOK || decode(t, w)["error"] == "realm_not_found" {
		t.Fatalf("path routing while off: %d %s", w.Code, w.Body)
	}
}

// 予約の処理（アカウントの削除）は、共有の Scheduler が出来事の realm の設定とサービスで行う。
func TestMultiRealmScheduledPurge(t *testing.T) {
	l := multiRealmEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	gamma, _ := l.newRealm(t, owner, map[string]any{"slug": "gamma", "settings": map[string]any{"user_deletion_grace_seconds": 60}})
	res, cookie := gamma.login(t, "carol@example.com")
	w := gamma.do(t, false, "POST", "/v1/me/account:delete", nil, "Cookie", gamma.cookieName+"="+cookie)
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	ra, _ := l.a.RealmApp("gamma")
	status := func() port.UserStatus {
		var u port.User
		err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			var err error
			u, err = tx.Users().GetByPublicID(ctx, ra.realm.ID, res["user_id"].(string))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return u.Status
	}
	l.advance(2 * time.Minute)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := status(); s != port.UserDeleted {
		t.Fatalf("status after the grace of gamma = %s", s)
	}
}
