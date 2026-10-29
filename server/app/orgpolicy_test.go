package app

import (
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Org のログインポリシー（design.md 4.4、フィーチャー org_login_policy、ADR 0069）を HTTP で確かめる。

func newPolicyEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.OrgLoginPolicy)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestOrgLoginPolicyFeatureOff(t *testing.T) {
	l := newPolicyEnv(t, false)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"require_passkey": true}}); code != 400 || out["error"] != "setting_invalid" {
		t.Fatalf("put without feature: %d %v", code, out)
	}
	// 空のポリシーは設定しないのと同じ。
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{}}); code != 200 {
		t.Fatalf("put empty: %d %v", code, out)
	}
}

func TestOrgLoginPolicy(t *testing.T) {
	l := newPolicyEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	l.join(t, owner, acme, "eve@other.example", "member")
	l.advance(time.Second)

	for _, p := range []map[string]any{
		{"membership_email_domains": []string{"user@acme.example"}},
		{"membership_email_domains": []string{"localhost"}},
		{"ip_allowlist": []string{"10.0.0.1"}},
	} {
		if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": p}); code != 400 || out["error"] != "setting_invalid" {
			t.Fatalf("put %v: %d %v", p, code, out)
		}
	}

	// メールのドメイン：大文字・重複は正規化して保存する。acme.example の人だけが入れる。
	code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"membership_email_domains": []string{"ACME.example", "acme.example"}}})
	if code != 200 {
		t.Fatalf("put domains: %d %v", code, out)
	}
	pol := out["settings"].(map[string]any)["login_policy"].(map[string]any)
	if ds := pol["membership_email_domains"].([]any); len(ds) != 1 || ds[0] != "acme.example" {
		t.Fatalf("stored policy = %v", pol)
	}
	if res, _ := l.login(t, "pat@acme.example"); res["org_id"] != acme {
		t.Fatalf("pat should enter acme: %v", res)
	}
	res, eve := l.login(t, "eve@other.example")
	if res["org_id"] == acme {
		t.Fatalf("eve entered acme: %v", res)
	}
	if code, body, _ := l.post(t, eve, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.membership_email_domain" {
		t.Fatalf("eve switch: %d %v", code, body)
	}

	// passkey 必須：メールのコードのログインでは入れない（ログインは成功する）。
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"require_passkey": true}}); code != 200 {
		t.Fatalf("put passkey: %d %v", code, out)
	}
	res, pat := l.login(t, "pat@acme.example")
	if res["org_id"] == acme {
		t.Fatalf("pat entered acme without passkey: %v", res)
	}
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.require_passkey" {
		t.Fatalf("pat switch: %d %v", code, body)
	}

	// IP の許可リスト（httptest の接続元は 192.0.2.1）。
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"ip_allowlist": []string{"10.0.0.0/8", "2001:db8::/32"}}}); code != 200 {
		t.Fatalf("put ip: %d %v", code, out)
	}
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.ip_allowlist" {
		t.Fatalf("switch from outside: %d %v", code, body)
	}
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"ip_allowlist": []string{"192.0.2.0/24"}}}); code != 200 {
		t.Fatalf("put ip: %d %v", code, out)
	}
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch from inside: %d %v", code, body)
	}

	// 変更は監査ログに残る。
	var changed []map[string]any
	for _, e := range l.auditTypes(t) {
		if e.Type == "org.settings_changed" {
			changed = append(changed, e.Details)
		}
	}
	if !slices.ContainsFunc(changed, func(d map[string]any) bool {
		after, _ := d["after"].(map[string]any)
		return after["login_policy"] != nil
	}) {
		t.Fatalf("settings_changed = %v", changed)
	}
}

// 2要素目の前の段では判定しないので、完了のときにポリシーを満たさなければ、ログインは失敗させずに他の Org に入る。
func TestOrgLoginPolicyAfterSecondFactor(t *testing.T) {
	l := newPolicyEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	pat := l.join(t, owner, acme, "pat@acme.example", "member")
	secret, code, out, _ := l.enrollTOTP(t, pat)
	if code != 200 {
		t.Fatalf("totp: %d %v", code, out)
	}
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"ip_allowlist": []string{"10.0.0.0/8"}}}); code != 200 {
		t.Fatalf("put ip: %d %v", code, out)
	}
	l.advance(30 * time.Second)
	login, restricted := l.login(t, "pat@acme.example")
	if login["next"] != "second_factor" {
		t.Fatalf("login: %v", login)
	}
	code, res, upgraded := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if code != 200 || upgraded == "" {
		t.Fatalf("verify: %d %v", code, res)
	}
	if got := l.activeOrgPublic(t, upgraded); got == acme || got == "" {
		t.Fatalf("entered %q after second factor", got)
	}
}
