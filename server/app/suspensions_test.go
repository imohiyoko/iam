package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
)

// ユーザーの停止と有効期間（design.md 4.7、4.8）を HTTP で確かめる。

func (l *loginEnv) loginDenied(t *testing.T, email string) []string {
	t.Helper()
	w := l.loginVerify(t, email)
	var body struct {
		Error   string   `json:"error"`
		Reasons []string `json:"reasons"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return body.Reasons
}

func (l *loginEnv) adminPatch(t *testing.T, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.AdminHandler(), "PATCH", path, body, "Authorization", "Bearer "+bearer)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestAdminSuspensions(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Security.SuspensionCategories = []string{"fraud_review"} }, nil)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	path := "/v1/admin/users/" + uid + "/suspensions"

	// 種別ごとの権限（4.11）。realm で足した種別は owner だけ。
	for _, c := range []struct {
		bearer, category string
	}{{support, "tos_violation"}, {admin, "security_risk"}, {sec, "tos_violation"}, {admin, "fraud_review"}} {
		if status, out := l.admin(t, path, c.bearer, map[string]string{"category": c.category, "reason": "x"}); status != 403 {
			t.Fatalf("%s: %d %v", c.category, status, out)
		}
	}
	if status, out := l.admin(t, path, admin, map[string]string{"category": "tos_violation", "reason": " "}); status != 400 || out["error"] != "invalid_reason" {
		t.Fatalf("empty reason: %d %v", status, out)
	}
	if status, out := l.admin(t, path, admin, map[string]string{"category": "nope", "reason": "x"}); status != 403 {
		t.Fatalf("unknown category by admin: %d %v", status, out)
	}
	if status, out := l.admin(t, path, owner, map[string]string{"category": "nope", "reason": "x"}); status != 400 || out["error"] != "unknown_category" {
		t.Fatalf("unknown category by owner: %d %v", status, out)
	}

	l.advance(time.Second)
	// 停止はすぐに効く。既存のセッションも使えず、本人にはコードだけを返す（reason は見せない）。
	status, sp := l.admin(t, path, admin, map[string]string{"category": "tos_violation", "reason": "spam campaign"})
	if status != 201 || sp["active"] != true {
		t.Fatalf("suspend: %d %v", status, sp)
	}
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("session while suspended: %d", status)
	}
	w := l.loginVerify(t, "pat@example.com")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "suspended.tos_violation") || strings.Contains(w.Body.String(), "spam") {
		t.Fatalf("login while suspended: %d %s", w.Code, w.Body)
	}
	if status, owned := l.admin(t, path, owner, map[string]string{"category": "fraud_review", "reason": "x"}); status != 201 {
		t.Fatalf("extra category by owner: %d %v", status, owned)
	} else if reasons := l.loginDenied(t, "pat@example.com"); strings.Join(reasons, ",") != "suspended.fraud_review,suspended.tos_violation" {
		t.Fatalf("stacked reasons: %v", reasons)
	} else if status, _ := l.admin(t, "/v1/admin/suspensions/"+owned["id"].(string)+":lift", owner, map[string]string{"reason": "ok"}); status != 200 {
		t.Fatalf("lift extra: %d", status)
	}
	var list struct {
		Suspensions []map[string]any `json:"suspensions"`
	}
	if status := l.adminGet(t, path, support, &list); status != 200 || len(list.Suspensions) != 2 {
		t.Fatalf("list: %d %v", status, list)
	}

	l.advance(time.Second)
	lift := "/v1/admin/suspensions/" + sp["id"].(string) + ":lift"
	if status, _ := l.admin(t, lift, sec, map[string]string{"reason": "ok"}); status != 403 {
		t.Fatalf("lift by security: %d", status)
	}
	if status, out := l.admin(t, lift, admin, map[string]string{"reason": "appeal accepted"}); status != 200 || out["active"] != false || out["lifted_at"] == nil {
		t.Fatalf("lift: %d %v", status, out)
	}
	// 停止をまたいだセッションは戻らない。新しくログインすれば入れる。
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("session spanning suspension: %d", status)
	}
	_, cookie = l.login(t, "pat@example.com")

	// 予約した停止は開始の時刻ちょうどに効き、終わりの時刻に解ける（キャッシュの期限も境界に合わせる）。
	start := l.e.deps.Clock.Now().Add(time.Hour)
	body := map[string]any{"category": "customer_request", "reason": "leave", "starts_at": start, "ends_at": start.Add(time.Hour), "external_ref": "hr-42"}
	status, rsv := l.admin(t, path, admin, body)
	if status != 201 || rsv["active"] != false {
		t.Fatalf("reserve: %d %v", status, rsv)
	}
	if status, again := l.admin(t, path, admin, body); status != 200 || again["id"] != rsv["id"] {
		t.Fatalf("idempotent: %d %v", status, again)
	}
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("before reservation: %d", status)
	}
	l.advance(time.Hour - time.Nanosecond)
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("just before start: %d", status)
	}
	l.advance(time.Nanosecond)
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("at start: %d", status)
	}
	l.advance(time.Hour)
	_, cookie = l.login(t, "pat@example.com")
	if n, err := l.a.scheduler.Fire(t.Context()); err != nil || n != 2 {
		t.Fatalf("boundary events: %d %v", n, err)
	}

	// 本人は自分の停止（予約も）を解除できない。運営者のセッションは直近の認証を求めるので、入り直す。
	_, owner = l.operator(t, "owner2@example.com", role.RealmOwner)
	adminID, admin := l.operator(t, "admin2@example.com", role.RealmAdmin)
	status, self := l.admin(t, "/v1/admin/users/"+adminID+"/suspensions", owner,
		map[string]any{"category": "customer_request", "reason": "x", "starts_at": l.e.deps.Clock.Now().Add(time.Hour)})
	if status != 201 {
		t.Fatalf("suspend admin: %d %v", status, self)
	}
	if status, _ := l.admin(t, "/v1/admin/suspensions/"+self["id"].(string)+":lift", admin, map[string]string{"reason": "x"}); status != 403 {
		t.Fatalf("self lift: %d", status)
	}
	if status, _ := l.admin(t, "/v1/admin/suspensions/sus_missing:lift", admin, map[string]string{"reason": "x"}); status != 404 {
		t.Fatalf("missing: %d", status)
	}
	_ = cookie
}

func TestAdminValidity(t *testing.T) {
	l := newLoginEnv(t)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	path := "/v1/admin/users/" + uid
	until := l.e.deps.Clock.Now().Add(time.Hour)
	if status, _ := l.adminPatch(t, path, support, map[string]any{"valid_until": until}); status != 403 {
		t.Fatalf("support: %d", status)
	}
	if status, out := l.adminPatch(t, path, admin, map[string]any{"valid_from": until, "valid_until": until}); status != 400 || out["error"] != "invalid_period" {
		t.Fatalf("empty period: %d %v", status, out)
	}
	if status, out := l.adminPatch(t, path, admin, map[string]any{"valid_until": until}); status != 200 || out["valid_until"] == nil {
		t.Fatalf("set: %d %v", status, out)
	}
	l.advance(time.Hour - time.Nanosecond)
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("just before until: %d", status)
	}
	l.advance(time.Nanosecond)
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("at until: %d", status)
	}
	if reasons := l.loginDenied(t, "pat@example.com"); strings.Join(reasons, ",") != "outside_validity" {
		t.Fatalf("login after until: %v", reasons)
	}
	_, admin = l.operator(t, "admin2@example.com", role.RealmAdmin) // 直近の認証を求める
	if status, out := l.adminPatch(t, path, admin, map[string]any{}); status != 200 || out["valid_until"] != nil {
		t.Fatalf("clear: %d %v", status, out)
	}
	l.login(t, "pat@example.com")
	if status, _ := l.adminPatch(t, "/v1/admin/users/usr_missing", admin, map[string]any{}); status != 404 {
		t.Fatalf("missing: %d", status)
	}
}
