package app

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
)

// Org の段のセキュリティ設定（design.md 2.8、5.4、10章、ADR 0062）を HTTP で確かめる。

func (l *loginEnv) putSettings(t *testing.T, cookie, orgID string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "PUT", "/v1/me/orgs/"+orgID+"/settings", body, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func effectiveOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	e, ok := body["effective"].(map[string]any)
	if !ok {
		t.Fatalf("no effective: %v", body)
	}
	return e
}

func TestOrgSettingsWarnings(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	l.advance(time.Second)
	_, pat := l.login(t, "pat@acme.example")
	if l.activeOrgPublic(t, pat) != acme {
		t.Fatal("pat should enter acme")
	}

	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs/"+acme+"/settings", nil, "Cookie", sessionCookie+"="+owner)
	var got map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	e := effectiveOf(t, got)
	if e["absolute_lifetime_seconds"] != float64(30*24*3600) || e["warnings"].(map[string]any)["single_factor"] != "ignore" {
		t.Fatalf("effective = %v", e)
	}
	// 緩める向き・未知のコード・範囲の外は拒む。メンバーは変えられない。
	for _, body := range []map[string]any{
		{"absolute_lifetime_seconds": 60 * 24 * 3600},
		{"idle_timeout_seconds": 60},
		{"warnings": map[string]string{"oauth_email_unverified": "ignore"}},
		{"warnings": map[string]string{"no_such_code": "deny"}},
	} {
		if code, out := l.putSettings(t, owner, acme, body); code != 400 || out["error"] != "setting_invalid" {
			t.Fatalf("put %v: %d %v", body, code, out)
		}
	}
	if code, _ := l.putSettings(t, pat, acme, map[string]any{}); code != 403 {
		t.Fatalf("member put: %d", code)
	}
	_, solo := l.login(t, "solo@example.com")
	personal := l.activeOrgPublic(t, solo)
	if code, out := l.putSettings(t, owner, personal, map[string]any{}); code != 404 && code != 403 {
		t.Fatalf("put on another's personal org: %d %v", code, out)
	}

	// 1要素の認証（メールのコード）を deny にすると、その認証では Acme に入れない。ログインは成功する。
	code, out := l.putSettings(t, owner, acme, map[string]any{"warnings": map[string]string{"single_factor": "deny"}})
	if code != 200 || effectiveOf(t, out)["warnings"].(map[string]any)["single_factor"] != "deny" {
		t.Fatalf("put: %d %v", code, out)
	}
	res, again := l.login(t, "pat@acme.example")
	if res["org_id"] == acme {
		t.Fatalf("login entered acme: %v", res)
	}
	if code, body, _ := l.post(t, again, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "warning_denied.single_factor" {
		t.Fatalf("switch: %d %v", code, body)
	}
	// 既存のセッションは validity_max_delay の内に Org を使えないと示す。
	l.advance(l.a.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if v, err := l.a.sessions.Validate(t.Context(), l.a.realm.ID, pat); err != nil || !slices.Equal(v.OrgUnavailable, []string{"warning_denied.single_factor"}) {
		t.Fatalf("validated = %+v, %v", v.OrgUnavailable, err)
	}
	// 戻せば入れる。
	if code, out := l.putSettings(t, owner, acme, map[string]any{}); code != 200 || out["settings"].(map[string]any)["warnings"] != nil {
		t.Fatalf("clear: %d %v", code, out)
	}
	if code, body, _ := l.post(t, again, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch after clear: %d %v", code, body)
	}
	n := 0
	for _, e := range l.auditTypes(t) {
		if e.Type == "org.settings_changed" {
			n++
			if e.OrgID != acme {
				t.Fatalf("audit org = %q", e.OrgID)
			}
		}
	}
	if n != 2 {
		t.Fatalf("settings_changed = %d", n)
	}
}

func TestOrgSettingsLifetimes(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.putSettings(t, owner, acme, map[string]any{
		"absolute_lifetime_seconds": 2 * 3600, "idle_timeout_seconds": 10 * 60, "max_auth_age_seconds": 60,
	}); code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	// Acme に入ったセッションは Acme の値に従う。
	_, s := l.login(t, "boss@acme.example")
	code, _, s := l.post(t, s, "/v1/me/orgs/"+acme+":switch", nil)
	if code != 200 || l.activeOrgPublic(t, s) != acme {
		t.Fatalf("switch to acme: %d", code)
	}
	l.advance(2 * time.Minute)
	if code, body, _ := l.post(t, s, "/v1/me/recovery-codes:regenerate", nil); code != 401 || body["error"] != "reauthentication_required" {
		t.Fatalf("regenerate after max_auth_age: %d %v", code, body)
	}
	// 認証手段の追加・削除も直近の認証を求める。
	for path, body := range map[string]any{
		"/v1/me/totp:start": nil, "/v1/me/passkeys:start": nil, "/v1/me/emails:start": map[string]string{"email": "new@acme.example"},
		"/v1/me/identities/google:start": nil, "/v1/me/totp/x:revoke": nil, "/v1/me/passkeys/x:revoke": nil,
		"/v1/me/emails/x:remove": nil, "/v1/me/emails/x:make-primary": nil, "/v1/me/identities/x:unlink": nil,
		"/v1/me/emails:verify": map[string]string{"flow_id": "x", "code": "000000"}, "/v1/me/identities:complete": map[string]string{"flow_id": "x", "state": "x", "code": "x"},
		"/v1/me/totp:confirm": map[string]string{"code": "000000"}, "/v1/me/passkeys:finish": map[string]any{"credential": map[string]any{}},
	} {
		if code, out, _ := l.post(t, s, path, body); code != 401 || out["error"] != "reauthentication_required" {
			t.Fatalf("%s after max_auth_age: %d %v", path, code, out)
		}
	}
	l.advance(11 * time.Minute)
	if code, _ := l.me(t, s); code != 401 {
		t.Fatalf("after org idle timeout: %d", code)
	}

	// 個人 Org では realm の値。切り替え先の Acme の寿命（認証から2時間）を超えていれば再認証を求める。
	_, s = l.login(t, "boss@acme.example")
	var s2 string
	personal := ""
	{
		_, got := l.myOrgs(t, s)
		for _, o := range got.Orgs {
			if o.ID != acme {
				personal = o.ID
			}
		}
	}
	code, _, s2 = l.post(t, s, "/v1/me/orgs/"+personal+":switch", nil)
	if code != 200 || s2 == "" {
		t.Fatalf("switch to personal: %d", code)
	}
	// 無操作の期限を越えないように使い続ける（Cookie の ID の入れ替えを避けて、検証だけをする）。
	for range 14 {
		l.advance(9 * time.Minute)
		if _, err := l.a.sessions.Validate(t.Context(), l.a.realm.ID, s2); err != nil {
			t.Fatalf("personal session: %v", err)
		}
	}
	if code, body, _ := l.post(t, s2, "/v1/me/orgs/"+acme+":switch", nil); code != 401 || body["error"] != "reauthentication_required" {
		t.Fatalf("switch beyond acme lifetime: %d %v", code, body)
	}

	// 運営者も設定できる（orgs:update）。
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	w := l.do(t, l.a.AdminHandler(), "PUT", "/v1/admin/orgs/"+acme+"/settings", map[string]any{"max_auth_age_seconds": 300}, "Authorization", "Bearer "+admin)
	var out map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || effectiveOf(t, out)["max_auth_age_seconds"] != float64(300) ||
		effectiveOf(t, out)["idle_timeout_seconds"] != float64(7*24*3600) {
		t.Fatalf("admin put: %d %s", w.Code, w.Body)
	}
	if status := l.adminGet(t, "/v1/admin/orgs/"+acme+"/settings", admin, &out); status != 200 {
		t.Fatalf("admin get: %d", status)
	}
}
