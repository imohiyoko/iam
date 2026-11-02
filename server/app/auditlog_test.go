package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの照会と、イベントの Webhook の購読（ADR 0100）を HTTP で確かめる。

// auditEnv は既定のフィーチャーに extra を足した環境。
func auditEnv(t *testing.T, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
	}, feature.Registered())
}

func events(out map[string]any) []map[string]any {
	var es []map[string]any
	for _, e := range out["events"].([]any) {
		es = append(es, e.(map[string]any))
	}
	return es
}

// lastAuditRead は最後の audit.read の詳細を返す。
func (l *loginEnv) lastAudit(t *testing.T, typ string) audit.Event {
	t.Helper()
	var found audit.Event
	for _, e := range l.auditTypes(t) {
		if e.Type == typ {
			found = e
		}
	}
	if found.ID == "" {
		t.Fatalf("no %s in the audit log", typ)
	}
	return found
}

func TestAuditQueryAPI(t *testing.T) {
	l := auditEnv(t)
	l.ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	_ = alice

	// 権限：support は読めない。admin は読めるが全文は読めない。
	if code, _ := l.adminDo(t, "GET", support, "/v1/admin/audit-events", nil); code != 403 {
		t.Fatalf("support reads audit: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", admin, "/v1/admin/audit-events?include_client_data=true", nil); code != 403 {
		t.Fatalf("admin reads client data: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", "", "/v1/admin/audit-events", nil); code != 401 {
		t.Fatalf("anonymous reads audit: %d", code)
	}

	// 対象（details の user_id）とページング。
	code, out := l.adminDo(t, "GET", admin, "/v1/admin/audit-events?limit=1&target_id="+aliceID, nil)
	if code != 200 || len(events(out)) != 1 || out["next_cursor"] == nil {
		t.Fatalf("list by target: %d %v", code, out)
	}
	first := events(out)
	code, out = l.adminDo(t, "GET", admin, "/v1/admin/audit-events?limit=200&target_id="+aliceID+"&after="+out["next_cursor"].(string), nil)
	if code != 200 || len(events(out)) == 0 || out["next_cursor"] != nil {
		t.Fatalf("second page: %d %v", code, out)
	}
	if s1, s2 := first[0]["seq"].(float64), events(out)[0]["seq"].(float64); s2 >= s1 {
		t.Fatalf("pages overlap: %v then %v", s1, s2)
	}
	for _, e := range append(first, events(out)...) {
		if e["client"] != nil {
			t.Fatalf("event leaks client data: %v", e)
		}
	}

	// 種類・結果・主体で絞る。
	code, out = l.adminDo(t, "GET", admin, "/v1/admin/audit-events?type_prefix=login.&actor_id="+aliceID+"&result=success", nil)
	if code != 200 || len(events(out)) == 0 {
		t.Fatalf("filter: %d %v", code, out)
	}
	for _, e := range events(out) {
		if !strings.HasPrefix(e["type"].(string), "login.") || e["actor"].(map[string]any)["id"] != aliceID || e["result"] != "success" {
			t.Fatalf("filtered event: %v", e)
		}
	}
	loginEvent := events(out)[0]

	// 誤った条件。
	for _, q := range []string{"limit=0", "limit=201", "after=abc", "result=maybe", "since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
		"type=" + strings.Repeat("x", 201)} {
		if code, out := l.adminDo(t, "GET", admin, "/v1/admin/audit-events?"+q, nil); code != 400 {
			t.Fatalf("%s: %d %v", q, code, out)
		}
	}

	// 1件と、全文の復号（owner）。読んだことが監査ログに残る。
	code, ev := l.adminDo(t, "GET", owner, "/v1/admin/audit-events/"+loginEvent["id"].(string)+"?include_client_data=true", nil)
	if code != 200 || ev["id"] != loginEvent["id"] || ev["client"] == nil || ev["client"].(map[string]any)["user_agent"] != l.ua {
		t.Fatalf("get with client data: %d %v", code, ev)
	}
	read := l.lastAudit(t, EventAuditRead)
	if read.Details["client_data"] != true || read.Details["event_id"] != loginEvent["id"] || read.Actor.Type != "user" {
		t.Fatalf("audit.read = %+v", read)
	}
	if code, _ := l.adminDo(t, "GET", admin, "/v1/admin/audit-events/evt_missing", nil); code != 404 {
		t.Fatalf("missing event: %d", code)
	}

	// 照会の監査ログは条件を残す。
	if code, _ := l.adminDo(t, "GET", admin, "/v1/admin/audit-events?type=login.succeeded", nil); code != 200 {
		t.Fatal(code)
	}
	read = l.lastAudit(t, EventAuditRead)
	if f, _ := read.Details["filter"].(map[string]any); f["type"] != "login.succeeded" || read.Details["scope"] != "realm" {
		t.Fatalf("audit.read details = %v", read.Details)
	}
	// 読んだことも照会できる（大量の読み取りの検知）。
	code, out = l.adminDo(t, "GET", owner, "/v1/admin/audit-events?type=audit.read", nil)
	if code != 200 || len(events(out)) < 3 {
		t.Fatalf("audit.read events: %d %v", code, out)
	}
}

func TestAuditVerifyAPI(t *testing.T) {
	l := auditEnv(t)
	l.login(t, "alice@example.com")
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	if code, _ := l.adminDo(t, "POST", support, "/v1/admin/audit-events:verify", map[string]any{}); code != 403 {
		t.Fatalf("support verifies: %d", code)
	}
	code, out := l.adminDo(t, "POST", admin, "/v1/admin/audit-events:verify", map[string]any{})
	if code != 200 || out["valid"] != true || out["anchored"] != true || out["from_seq"].(float64) != 1 || out["to_seq"] != out["head_seq"] ||
		out["prev_hash"] != strings.Repeat("0", 64) || out["last_hash"] == nil {
		t.Fatalf("verify all: %d %v", code, out)
	}
	head := out["head_seq"].(float64)
	// 範囲を分けて確かめ、前の last_hash と次の prev_hash を突き合わせる。
	code, a := l.adminDo(t, "POST", admin, "/v1/admin/audit-events:verify", map[string]any{"from_seq": 1, "to_seq": 3})
	code2, b := l.adminDo(t, "POST", admin, "/v1/admin/audit-events:verify", map[string]any{"from_seq": 4, "to_seq": head})
	if code != 200 || code2 != 200 || a["to_seq"].(float64) != 3 || b["anchored"] != false || a["last_hash"] != b["prev_hash"] || b["valid"] != true {
		t.Fatalf("split verify: %v / %v", a, b)
	}
	if code, out := l.adminDo(t, "POST", admin, "/v1/admin/audit-events:verify", map[string]any{"from_seq": 5, "to_seq": 2}); code != 400 {
		t.Fatalf("inverted range: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", admin, "/v1/admin/audit-events:verify", map[string]any{"from_seq": 1, "to_seq": 200001}); code != 200 ||
		out["to_seq"] != out["head_seq"] {
		t.Fatalf("to beyond head is clamped: %d %v", code, out)
	}
	if v := l.lastAudit(t, EventAuditVerified); v.Result != audit.ResultSuccess || v.Details["valid"] != true {
		t.Fatalf("audit.verified = %+v", v)
	}

}

func TestOrgAuditLogAPI(t *testing.T) {
	l := auditEnv(t, feature.OrgAuditLog)
	_, owner := l.login(t, "boss@acme.example")
	bossID := l.userID(t, "boss@acme.example")
	opID, opToken := l.operator(t, "admin@example.com", role.RealmAdmin)
	// 運営者が Org を作る（主体の ID は Org に見せない）。
	code, created := l.adminDo(t, "POST", opToken, "/v1/admin/orgs", map[string]any{"name": "Acme", "owner_id": bossID})
	if code != 201 {
		t.Fatalf("operator creates org: %d %v", code, created)
	}
	acme := created["id"].(string)
	member := l.join(t, owner, acme, "pat@acme.example", "member")
	patID := l.userID(t, "pat@acme.example")
	_, other := l.login(t, "eve@other.example")
	evil := l.sharedOrg(t, other, "Evil")

	path := "/v1/me/orgs/" + acme + "/audit-events"
	if code, _ := l.meDo(t, "GET", member, path, nil); code != 403 {
		t.Fatalf("member reads org audit: %d", code)
	}
	if code, _ := l.meDo(t, "GET", other, path, nil); code != 404 {
		t.Fatalf("outsider reads org audit: %d", code)
	}
	code, out := l.meDo(t, "GET", owner, path, nil)
	if code != 200 || len(events(out)) == 0 {
		t.Fatalf("owner reads org audit: %d %v", code, out)
	}
	sawPat, sawOperator := false, false
	for _, e := range events(out) {
		for _, k := range []string{"ip", "user_agent", "session_id", "seq", "hash", "client", "org_id"} {
			if _, ok := e[k]; ok {
				t.Fatalf("org audit event exposes %s: %v", k, e)
			}
		}
		actor := e["actor"].(map[string]any)
		if actor["id"] == patID {
			sawPat = true
		}
		if e["type"] == "org.created" {
			sawOperator = true
			if actor["id"] != nil || actor["type"] != "user" {
				t.Fatalf("operator id exposed to the org: %v", e)
			}
		}
		if actor["id"] == opID {
			t.Fatalf("operator id exposed to the org: %v", e)
		}
	}
	if !sawPat || !sawOperator {
		t.Fatalf("org events are missing: %v", out)
	}
	// 別の Org の条件を渡しても、範囲は変わらない。
	code, out = l.meDo(t, "GET", owner, path+"?org_id="+evil+"&actor_id="+patID, nil)
	if code != 200 || len(events(out)) == 0 {
		t.Fatalf("filter by member: %d %v", code, out)
	}
	if code, out := l.meDo(t, "GET", owner, path+"?limit=0", nil); code != 400 {
		t.Fatalf("bad limit: %d %v", code, out)
	}
	code, out = l.meDo(t, "GET", other, "/v1/me/orgs/"+evil+"/audit-events", nil)
	if code != 200 {
		t.Fatal(code)
	}
	for _, e := range events(out) {
		if id := e["actor"].(map[string]any)["id"]; id == patID || id == bossID {
			t.Fatalf("acme event leaked to evil: %v", e)
		}
	}
	read := l.lastAudit(t, EventAuditRead)
	if read.OrgID != evil || read.Details["scope"] != "org" {
		t.Fatalf("org audit.read = %+v", read)
	}

	// フィーチャーが無ければ 404。
	off := auditEnv(t)
	_, o2 := off.login(t, "boss@acme.example")
	acme2 := off.sharedOrg(t, o2, "Acme")
	if code, _ := off.meDo(t, "GET", o2, "/v1/me/orgs/"+acme2+"/audit-events", nil); code != 404 {
		t.Fatalf("org_audit_log off: %d", code)
	}
}

type hookRecorder struct {
	mu     sync.Mutex
	status int
	reqs   []*http.Request
	bodies [][]byte
}

func (h *hookRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reqs, h.bodies = append(h.reqs, r), append(h.bodies, b)
	w.WriteHeader(h.status)
}

func TestEventSubscriptionsAPI(t *testing.T) {
	l := auditEnv(t, feature.EventSubscriptions)
	rcv := &hookRecorder{status: http.StatusOK}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	base := "/v1/admin/event-subscriptions"
	if code, _ := l.adminDo(t, "POST", admin, base, map[string]any{"url": srv.URL}); code != 403 {
		t.Fatalf("admin creates: %d", code)
	}
	for _, c := range []struct {
		body map[string]any
		err  string
	}{
		{map[string]any{"url": "ftp://x"}, "invalid_url"},
		{map[string]any{"url": srv.URL, "event_types": []string{"Bad Type"}}, "invalid_event_types"},
		{map[string]any{"url": srv.URL, "pii": "raw"}, "invalid_pii"},
	} {
		if code, out := l.adminDo(t, "POST", owner, base, c.body); code != 400 || out["error"] != c.err {
			t.Fatalf("create %v: %d %v", c.body, code, out)
		}
	}
	code, created := l.adminDo(t, "POST", owner, base, map[string]any{"url": srv.URL + "/hook?token=abc", "event_types": []string{"login."}})
	if code != 201 || !strings.HasPrefix(created["secret"].(string), "whsec_") || created["pii"] != "omit" || created["enabled"] != true {
		t.Fatalf("create: %d %v", code, created)
	}
	subID, secret := created["id"].(string), created["secret"].(string)

	// 秘密は作成のときだけ返す。
	code, got := l.adminDo(t, "GET", owner, base+"/"+subID, nil)
	if code != 200 || got["secret"] != nil || got["url"] != srv.URL+"/hook?token=abc" {
		t.Fatalf("get: %d %v", code, got)
	}
	code, list := l.adminDo(t, "GET", owner, base, nil)
	if code != 200 || len(list["subscriptions"].([]any)) != 1 || list["subscriptions"].([]any)[0].(map[string]any)["secret"] != nil {
		t.Fatalf("list: %d %v", code, list)
	}

	// 送る：login. のイベントだけ、署名つきで。
	l.login(t, "alice@example.com")
	if _, err := l.a.subDelivery.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rcv.bodies) != 1 {
		t.Fatalf("deliveries = %d", len(rcv.bodies))
	}
	var body struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.Unmarshal(rcv.bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	for _, e := range body.Events {
		if !strings.HasPrefix(e.Type, "login.") || e.IP != "" || e.Client != "" || e.Chain == nil {
			t.Fatalf("delivered event: %+v", e)
		}
	}
	r := rcv.reqs[0]
	if r.URL.RawQuery != "token=abc" || r.Header.Get(eventsub.SubscriptionHeader) != subID ||
		r.Header.Get(eventsub.SignatureHeader) != eventsub.Sign([]byte(secret), l.a.deps.Clock.Now(), rcv.bodies[0]) {
		t.Fatalf("request: %s %v", r.URL, r.Header)
	}

	// 変更・テスト送信・鍵の作り直し・削除。
	code, up := l.adminDo(t, "PATCH", owner, base+"/"+subID, map[string]any{"pii": "pseudonymize", "enabled": false})
	if code != 200 || up["pii"] != "pseudonymize" || up["enabled"] != false {
		t.Fatalf("update: %d %v", code, up)
	}
	code, res := l.adminDo(t, "POST", owner, base+"/"+subID+":test", nil)
	if code != 200 || res["delivered"] != true || res["status"].(float64) != 200 {
		t.Fatalf("test: %d %v", code, res)
	}
	var test struct {
		Events []audit.Event `json:"events"`
	}
	_ = json.Unmarshal(rcv.bodies[len(rcv.bodies)-1], &test)
	if len(test.Events) != 1 || test.Events[0].Type != eventsub.TestEventType {
		t.Fatalf("test event: %s", rcv.bodies[len(rcv.bodies)-1])
	}
	for range 4 {
		l.adminDo(t, "POST", owner, base+"/"+subID+":test", nil)
	}
	if code, _ := l.adminDo(t, "POST", owner, base+"/"+subID+":test", nil); code != 429 {
		t.Fatalf("test over the limit: %d", code)
	}
	code, rot := l.adminDo(t, "POST", owner, base+"/"+subID+":rotate-secret", nil)
	if code != 200 || rot["secret"] == secret || !strings.HasPrefix(rot["secret"].(string), "whsec_") {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	if code, _ := l.adminDo(t, "POST", owner, base+"/"+subID+":delete", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, base+"/"+subID, nil); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
	// 操作は監査ログに残り、URL の経路・問い合わせと秘密は残さない。
	for _, e := range l.auditTypes(t) {
		if strings.HasPrefix(e.Type, "event_subscription.") {
			b, _ := json.Marshal(e)
			if strings.Contains(string(b), "token=abc") || strings.Contains(string(b), "whsec_") {
				t.Fatalf("audit leaks: %s", b)
			}
		}
	}
	tested := l.lastAudit(t, "event_subscription.tested")
	if tested.Details["delivered"] != true {
		t.Fatalf("tested = %+v", tested)
	}

	// フィーチャーが無ければ 404 event_subscriptions_disabled。
	off := auditEnv(t)
	_, o2 := off.operator(t, "root@example.com", role.RealmOwner)
	if code, out := off.adminDo(t, "GET", o2, base, nil); code != 404 || out["error"] != "event_subscriptions_disabled" {
		t.Fatalf("feature off: %d %v", code, out)
	}
}

// 開発ビルドでなければ、公開でないアドレスの宛先は登録できない。
func TestEventSubscriptionsRefusePrivateAddresses(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		names := []string{feature.Org, feature.Warnings, feature.EventSubscriptions}
		c.Features = &names
	}, feature.Registered())
	l.a.eventSubs.Dev, l.a.eventSubs.AllowPrivateNetworks = false, false
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, u := range []string{"https://127.0.0.1/", "https://[::1]/x", "https://169.254.169.254/latest", "http://hooks.example.com/"} {
		if code, out := l.adminDo(t, "POST", owner, "/v1/admin/event-subscriptions", map[string]any{"url": u}); code != 400 || out["error"] != "invalid_url" {
			t.Fatalf("%s: %d %v", u, code, out)
		}
	}
}

// フィーチャー event_subscriptions の無効化は購読（と署名の鍵）を片付ける。
func TestDisableEventSubscriptions(t *testing.T) {
	l := auditEnv(t, feature.EventSubscriptions)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	code, created := l.adminDo(t, "POST", owner, "/v1/admin/event-subscriptions", map[string]any{"url": "https://hooks.example.com/"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, created)
	}
	res, err := l.a.DisableFeature(context.Background(), feature.EventSubscriptions, false)
	if err != nil || res.Done || res.Remaining != 1 {
		t.Fatalf("disable without purge = %+v, %v", res, err)
	}
	res, err = l.a.DisableFeature(context.Background(), feature.EventSubscriptions, true)
	if err != nil || !res.Done || res.Purged != 1 {
		t.Fatalf("disable with purge = %+v, %v", res, err)
	}
	if err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if _, err := tx.DataKeys().Get(ctx, created["id"].(string)); err == nil {
			t.Error("signing key's data key survived the purge")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
