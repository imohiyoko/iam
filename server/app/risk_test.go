package app

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// リスク（ADR 0084）：realm の種類の一覧、ログインのフックの点数、評価器の管理 API。

func riskEnv(t *testing.T, post *fakeHook) *loginEnv {
	t.Helper()
	return newLoginEnvDeps(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.FlowHooks, feature.ServiceAccounts)
		c.Features = &names
		c.Hooks = map[string]config.Hook{port.HookPostAuthentication: {Timeout: config.Duration(100 * time.Millisecond)}}
	}, feature.Registered(), func(d *Deps) {
		d.Hooks = map[string]port.FlowHook{port.HookPostAuthentication: post}
	})
}

// sessionRisks はユーザーのセッションの保存した点数（新しい順）。
func (l *loginEnv) sessionRisks(t *testing.T, userPublicID string) []map[string]int {
	t.Helper()
	var out []map[string]int
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, userPublicID)
		if err != nil {
			return err
		}
		ss, err := tx.Sessions().ListByPrincipal(ctx, l.a.realm.ID, port.PrincipalUser, u.ID)
		for _, s := range ss {
			var m map[string]int
			if len(s.Risk) > 0 {
				if err := json.Unmarshal(s.Risk, &m); err != nil {
					return err
				}
			}
			out = append(out, m)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRisk(t *testing.T) {
	var mu sync.Mutex
	scores := map[string]int{}
	post := &fakeHook{decide: func(port.HookInput) (port.HookResult, error) {
		mu.Lock()
		defer mu.Unlock()
		return port.HookResult{Allow: true, Risk: maps.Clone(scores)}, nil
	}}
	l := riskEnv(t, post)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)

	// 一覧：組み込みの種類は変えなくても載る。
	code, out := l.adminDo(t, "GET", owner, "/v1/admin/risk-types", nil)
	if code != 200 || len(out["risk_types"].([]any)) != 3 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", support, "/v1/admin/risk-types", nil); code != 403 {
		t.Fatalf("support lists: %d", code)
	}
	put := func(bearer, name string, body map[string]any) (int, map[string]any) {
		return l.adminDo(t, "PUT", bearer, "/v1/admin/risk-types/"+name, body)
	}
	if code, out := put(owner, "payment.fraud", map[string]any{"enabled": true, "band": map[string]any{"medium": 20, "high": 50}}); code != 200 ||
		out["enabled"] != true || out["builtin"] != false || out["band"].(map[string]any)["high"] != float64(50) || out["updated_at"] == nil {
		t.Fatalf("add type: %d %v", code, out)
	}
	if code, out := put(owner, "device", map[string]any{"enabled": false}); code != 200 || out["builtin"] != true || out["band"].(map[string]any)["medium"] != float64(30) {
		t.Fatalf("disable builtin: %d %v", code, out)
	}
	for _, c := range []struct {
		name string
		body map[string]any
		err  string
	}{
		{"fraud", map[string]any{"enabled": true}, "invalid_risk_type"},
		{"Payment.fraud", map[string]any{"enabled": true}, "invalid_risk_type"},
		{"payment.x", map[string]any{"enabled": true, "band": map[string]any{"medium": 50, "high": 50}}, "invalid_band"},
		{"payment.x", map[string]any{"enabled": true, "band": map[string]any{"medium": 0, "high": 50}}, "invalid_band"},
	} {
		if code, out := put(owner, c.name, c.body); code != 400 || out["error"] != c.err {
			t.Fatalf("put %s %v: %d %v", c.name, c.body, code, out)
		}
	}
	if code, _ := put(support, "payment.y", map[string]any{"enabled": true}); code != 403 {
		t.Fatalf("support puts: %d", code)
	}
	// 変わらない置き直しは監査ログに残さない。
	n := countAudit(l.auditTypes(t), "realm.risk_types_changed")
	if code, _ := put(owner, "payment.fraud", map[string]any{"enabled": true}); code != 200 || countAudit(l.auditTypes(t), "realm.risk_types_changed") != n {
		t.Fatalf("unchanged put: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/risk-types", nil); code != 200 || len(out["risk_types"].([]any)) != 4 {
		t.Fatalf("list after put: %d %v", code, out)
	}

	// ログイン：フックの点数のうち、一覧で有効で範囲内のものだけをセッションに入れる。捨てたものは監査ログに残す。
	mu.Lock()
	scores = map[string]int{"account": 40, "ip": 150, "device": 10, "nope.x": 1, "payment.fraud": 5}
	mu.Unlock()
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	if got := l.sessionRisks(t, aliceID); len(got) != 1 || !reflect.DeepEqual(got[0], map[string]int{"account": 40, "payment.fraud": 5}) {
		t.Fatalf("session risk after login: %v", got)
	}
	ev := lastAudit(l.auditTypes(t), "session.risk_updated")
	if ev == nil || ev.Details["source"] != "post_authentication" || !reflect.DeepEqual(ev.Details["dropped"], []any{"device", "ip", "nope.x"}) {
		t.Fatalf("hook risk audit: %+v", ev)
	}
	v, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, alice)
	if err != nil || !reflect.DeepEqual(v.Risk, map[string]int{"account": 40, "payment.fraud": 5}) {
		t.Fatalf("validated risk: %v, %v", v.Risk, err)
	}

	// 評価器：risk:write を持つサービスアカウント。
	code, out = l.admin(t, "/v1/admin/roles", owner, map[string]any{"name": "risk-evaluator", "permissions": []string{role.PermRiskWrite}})
	if code != 201 {
		t.Fatalf("create role: %d %v", code, out)
	}
	roleID := out["id"].(string)
	code, out = l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "evaluator"})
	if code != 201 {
		t.Fatalf("create sa: %d %v", code, out)
	}
	sa := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": roleID, "principal_type": "service_account", "principal_id": sa}); code != 201 {
		t.Fatalf("bind: %d %v", code, out)
	}
	_, out = l.admin(t, "/v1/admin/service-accounts/"+sa+"/credentials", owner, map[string]any{"type": "api_key"})
	key := out["secret"].(string)

	sessionID := v.SessionID
	setSession := func(bearer string, risk map[string]any) (int, map[string]any) {
		return l.admin(t, "/v1/admin/sessions/"+sessionID+":risk", bearer, map[string]any{"risk": risk})
	}
	// 人の運営者は risk:write を持っていても使えない。
	if code, out := setSession(owner, map[string]any{"account": 90}); code != 403 {
		t.Fatalf("operator sets risk: %d %v", code, out)
	}
	for _, risk := range []map[string]any{{}, {"account": 101}, {"account": -1}, {"nope.x": 1}, {"device": 10}} {
		if code, out := setSession(key, risk); code != 400 || out["error"] != "invalid_risk" {
			t.Fatalf("set %v: %d %v", risk, code, out)
		}
	}
	if code, out := setSession(key, map[string]any{"payment.fraud": 70, "account": nil}); code != 200 || out["sessions"] != float64(1) {
		t.Fatalf("set session risk: %d %v", code, out)
	}
	if got := l.sessionRisks(t, aliceID); !reflect.DeepEqual(got[0], map[string]int{"payment.fraud": 70}) {
		t.Fatalf("session risk after update: %v", got)
	}
	ev = lastAudit(l.auditTypes(t), "session.risk_updated")
	if ev == nil || ev.Details["source"] != "admin" || ev.Actor.ID != sa || ev.SessionID != sessionID ||
		!reflect.DeepEqual(ev.Details["changes"], map[string]any{"payment.fraud": float64(70), "account": nil}) {
		t.Fatalf("admin risk audit: %+v", ev)
	}
	// 更新はキャッシュを捨てて、すぐ判定に効く。
	if v, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, alice); err != nil || !reflect.DeepEqual(v.Risk, map[string]int{"payment.fraud": 70}) {
		t.Fatalf("validated risk after update: %v, %v", v.Risk, err)
	}
	if code, _ := l.admin(t, "/v1/admin/sessions/ses_nope:risk", key, map[string]any{"risk": map[string]any{"account": 1}}); code != 404 {
		t.Fatalf("unknown session: %d", code)
	}

	// ユーザーのすべてのセッション。終わったセッションは更新しない。
	_, alice2 := l.login(t, "alice@example.com")
	if code, out := l.admin(t, "/v1/admin/users/"+aliceID+":risk", key, map[string]any{"risk": map[string]any{"account": 85}}); code != 200 || out["sessions"] != float64(2) {
		t.Fatalf("set user risk: %d %v", code, out)
	}
	got := l.sessionRisks(t, aliceID)
	// 時計を進めていないので、2つのセッションの順は決まらない。
	if len(got) != 2 || !slices.ContainsFunc(got, func(m map[string]int) bool {
		return reflect.DeepEqual(m, map[string]int{"account": 85, "payment.fraud": 5})
	}) ||
		!slices.ContainsFunc(got, func(m map[string]int) bool {
			return reflect.DeepEqual(m, map[string]int{"account": 85, "payment.fraud": 70})
		}) {
		t.Fatalf("user risk: %v", got)
	}
	if code, _ := l.admin(t, "/v1/admin/users/usr_nope:risk", key, map[string]any{"risk": map[string]any{"account": 1}}); code != 404 {
		t.Fatalf("unknown user: %d", code)
	}

	// 止めた種類の点数は判定に使わない。
	if code, _ := put(owner, "payment.fraud", map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if v, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, alice2); err != nil || !reflect.DeepEqual(v.Risk, map[string]int{"account": 85}) {
		t.Fatalf("validated risk after disabling: %v, %v", v.Risk, err)
	}
	ev = lastAudit(l.auditTypes(t), "realm.risk_types_changed")
	if ev == nil || ev.Details["name"] != "payment.fraud" || ev.Details["enabled"] != false || ev.Details["previous"].(map[string]any)["enabled"] != true {
		t.Fatalf("risk types audit: %+v", ev)
	}
}

func countAudit(evs []audit.Event, typ string) int {
	return len(slices.DeleteFunc(slices.Clone(evs), func(e audit.Event) bool { return e.Type != typ }))
}

func lastAudit(evs []audit.Event, typ string) *audit.Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == typ {
			return &evs[i]
		}
	}
	return nil
}
