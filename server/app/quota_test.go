package app

import (
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Quota（design.md 11.14、ADR 0070）を HTTP で確かめる。

func newQuotaEnv(t *testing.T, on bool) *loginEnv {
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
			names = append(names, feature.Quota)
		}
		c.Features = &names
	}, feature.Registered())
}

func TestQuotaFeatureOff(t *testing.T) {
	l := newQuotaEnv(t, false)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, op := l.operator(t, "ops@example.com", role.RealmAdmin)
	if code, out := l.adminDo(t, "GET", op, "/v1/admin/orgs/"+acme+"/quota", nil); code != 404 || out["error"] != "quota_disabled" {
		t.Fatalf("quota without feature: %d %v", code, out)
	}
}

func TestQuotaAPI(t *testing.T) {
	l := newQuotaEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, op := l.operator(t, "ops@example.com", role.RealmAdmin)
	base := "/v1/admin/orgs/" + acme + "/quota"

	code, out := l.adminDo(t, "POST", op, base+"/grants", map[string]any{"kind": "base", "quantity": 2})
	if code != 201 || out["source"] != "manual" {
		t.Fatalf("create grant: %d %v", code, out)
	}
	manual := out["id"].(string)
	if code, out := l.adminDo(t, "GET", op, base, nil); code != 200 || out["limit"] != float64(2) || out["count"] != float64(1) {
		t.Fatalf("quota: %d %v", code, out)
	}

	// 招待中も数える。2人目の招待で枠が尽きる。
	_, pat := l.login(t, "pat@acme.example")
	if code, body := l.invite(t, owner, acme, "pat@acme.example", "member"); code != 201 {
		t.Fatalf("invite pat: %d %v", code, body)
	}
	_, token := l.claimToken(t)
	code, body := l.invite(t, owner, acme, "sam@acme.example", "member")
	q, _ := body["quota"].(map[string]any)
	if code != 409 || body["error"] != "quota_exceeded" || q["shortage"] != float64(1) || q["limit"] != float64(2) || q["until"] != nil {
		t.Fatalf("invite over quota: %d %v", code, body)
	}
	// 受け入れはその招待の枠を引き継ぐ。
	if code, body := l.accept(t, pat, token); code != 200 {
		t.Fatalf("accept: %d %v", code, body)
	}

	// 外部の付与は external_ref で上書きする。下回っても拒否せず、org.quota.exceeded を残す。
	code, out = l.adminDo(t, "POST", op, base+"/grants", map[string]any{"kind": "base", "quantity": 1, "external_ref": "sub_1"})
	if code != 201 || out["source"] != "external" {
		t.Fatalf("external grant: %d %v", code, out)
	}
	ext := out["id"].(string)
	code, out = l.adminDo(t, "POST", op, base+"/grants", map[string]any{"kind": "base", "quantity": 3, "external_ref": "sub_1"})
	if code != 200 || out["id"] != ext || out["quantity"] != float64(3) {
		t.Fatalf("external upsert: %d %v", code, out)
	}
	exceeded := 0
	for _, e := range l.auditTypes(t) {
		if e.Type == "org.quota.exceeded" && e.OrgID == acme {
			exceeded++
		}
	}
	if exceeded != 1 {
		t.Fatalf("org.quota.exceeded = %d", exceeded)
	}
	if code, out := l.adminDo(t, "PUT", op, base+"/grants/"+ext, map[string]any{"kind": "base", "quantity": 9}); code != 409 || out["error"] != "quota_grant_external" {
		t.Fatalf("manual update of external: %d %v", code, out)
	}
	if code, body := l.invite(t, owner, acme, "sam@acme.example", "member"); code != 201 {
		t.Fatalf("invite after upsert: %d %v", code, body)
	}

	// 手動の付与の変更：override 3 を今から10日。
	until := l.a.deps.Clock.Now().Add(10 * 24 * time.Hour)
	if code, out := l.adminDo(t, "PUT", op, base+"/grants/"+manual, map[string]any{"kind": "override", "quantity": 3, "ends_at": until}); code != 200 {
		t.Fatalf("update manual: %d %v", code, out)
	}
	// 手動で上限を下げて既存の3人（招待中を含む）が超えるのは拒む。外部の付与は消せる（拒否しない）。
	if code, out := l.adminDo(t, "PUT", op, base+"/grants/"+manual, map[string]any{"kind": "override", "quantity": 2}); code != 409 || out["error"] != "quota_exceeded" || out["quota"] == nil {
		t.Fatalf("reduce manual: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "DELETE", op, base+"/grants/"+ext, nil); code != 204 {
		t.Fatalf("delete external: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "DELETE", op, base+"/grants/"+manual, nil); code != 204 {
		t.Fatalf("delete manual: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "DELETE", op, base+"/grants/"+manual, nil); code != 404 {
		t.Fatalf("delete again: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", op, base+"/grants", map[string]any{"kind": "nope", "quantity": 1}); code != 400 {
		t.Fatalf("invalid kind: %d %v", code, out)
	}
}
