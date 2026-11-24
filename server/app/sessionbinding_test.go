package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/geoip/static"
	"github.com/imohiyoko/iam/authn/sessionbinding"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
)

// セッションの端末・接続元の監視（ADR 0128）を HTTP で確かめる。

func newBindingEnv(t *testing.T, extra []string, edit func(*config.Config)) *loginEnv {
	t.Helper()
	geo, err := static.Parse(strings.NewReader(riskGeo))
	if err != nil {
		t.Fatal(err)
	}
	return newProtectEnv(t, append([]string{feature.SessionBinding}, extra...), edit, func(d *Deps) { d.GeoIP = geo })
}

// anomalies は監査ログの session.anomaly_detected の兆候の名前。
func (l *loginEnv) anomalies(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, ev := range l.auditOf(t, sessionbinding.EventAnomaly) {
		out = append(out, ev.Details["signal"].(string))
	}
	return out
}

func bindingRisk(evs []audit.Event) map[string]any {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Details["source"] == "session_binding" {
			r, _ := evs[i].Details["risk"].(map[string]any)
			return r
		}
	}
	return nil
}

// 別の端末の Cookie でセッションが使われたら記録し、系列のリスクを上げる。要件の risk_at_most で step-up を求める。
// 同じ兆候は系列ごとに 1 回だけ記録する。
func TestSessionBindingDevice(t *testing.T) {
	l := newBindingEnv(t, []string{feature.DeviceRecognition}, nil)
	_, op := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/action-namespaces/me", map[string]any{"requirements": map[string]any{
		role.ActionMeDelete: map[string]any{"any": []any{
			map[string]any{"risk_at_most": map[string]any{"type": "device", "level": "medium"}},
			map[string]any{"aal_at_least": 2}}}}}); code != 200 {
		t.Fatalf("put me: %d %v", code, out)
	}
	jar := ""
	l.device = &jar
	l.ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"
	l.hdr = []string{"X-Forwarded-For", "198.51.100.10"}
	_, cookie := l.login(t, "pat@example.com")
	for range 3 {
		if code, out := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
			t.Fatalf("me: %d %v", code, out)
		}
	}
	// ブラウザの更新（版の数字だけ変わる）と、同じ事業者の中の IP の変化は兆候にしない。
	l.ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 Version/18.1 Safari/605.1.15"
	l.hdr = []string{"X-Forwarded-For", "198.51.100.77"}
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
		t.Fatalf("same browser: %d", code)
	}
	if got := l.anomalies(t); len(got) != 0 {
		t.Fatalf("anomalies before the theft: %v", got)
	}

	// 盗んだ Cookie を別のブラウザ（端末の Cookie が違う）で使う。
	other := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	l.device = &other
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
		t.Fatalf("stolen cookie with the risk action: %d", code)
	}
	if got := l.anomalies(t); len(got) != 1 || got[0] != "device_changed" {
		t.Fatalf("anomalies: %v", got)
	}
	ev := l.lastAudit(t, sessionbinding.EventAnomaly)
	if ev.Details["sid"] == nil || ev.Details["user_id"] == nil || ev.Details["device_cookie"] != true {
		t.Fatalf("anomaly event: %+v", ev)
	}
	if r := bindingRisk(l.auditOf(t, "session.risk_updated")); r["device"] != float64(90) {
		t.Fatalf("raised risk: %v", r)
	}
	// 本人の重要な操作は step-up を求める（端末の Cookie を戻しても、系列のリスクは下がらない）。
	l.device = &jar
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/account:delete", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `acr_values="`+acr.AAL2+`"`) {
		t.Fatalf("step-up: %d %s %q", w.Code, w.Body, w.Header().Get("WWW-Authenticate"))
	}
	// 端末の Cookie を外しても同じ兆候なので、もう記録しない。
	none := ""
	l.device = &none
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
		t.Fatalf("again: %d", code)
	}
	if got := l.anomalies(t); len(got) != 1 {
		t.Fatalf("reported twice: %v", got)
	}

	// 新しいログインは新しい系列なので、新しい起点から見る。
	l.device = &jar
	_, fresh := l.login(t, "pat@example.com")
	if code, _ := l.meDo(t, "GET", fresh, "/v1/me", nil); code != 200 {
		t.Fatalf("fresh: %d", code)
	}
	if got := l.anomalies(t); len(got) != 1 {
		t.Fatalf("fresh session: %v", got)
	}
}

// 国が変われば失効させる設定（revoke）：その要求から未ログインになり、本人に知らせる。
func TestSessionBindingCountryRevoke(t *testing.T) {
	l := newBindingEnv(t, nil, func(c *config.Config) {
		c.Security.SessionBinding.CountryChanged.Actions = []string{"revoke", "notify"}
	})
	l.hdr = []string{"X-Forwarded-For", "198.51.100.10"}
	_, cookie := l.login(t, "pat@example.com")
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
		t.Fatalf("me: %d", code)
	}
	before := l.notes.count()
	l.hdr = []string{"X-Forwarded-For", "203.0.113.10"}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != 401 {
		t.Fatalf("after the country change: %d %s", w.Code, w.Body)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == sessionCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("session cookie not cleared")
	}
	ev := l.lastAudit(t, sessionbinding.EventAnomaly)
	if ev.Details["signal"] != "country_changed" || ev.Details["from_country"] != "JP" || ev.Details["to_country"] != "US" {
		t.Fatalf("anomaly: %+v", ev)
	}
	if rv := l.lastAudit(t, "session.revoked"); rv.Details["reason"] != "session_anomaly" {
		t.Fatalf("revoked: %+v", rv)
	}
	// 元の国に戻っても使えない。
	l.hdr = []string{"X-Forwarded-For", "198.51.100.10"}
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 401 {
		t.Fatalf("back home: %d", code)
	}
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.notes.count() <= before || l.notes.last(t).Type != sessionbinding.TypeSuspiciousSession {
		t.Fatalf("notification: %d -> %d", before, l.notes.count())
	}
}

// 短い時間に別々のネットワークを渡り歩けば network_flapping。2 つの回線の行き来と、無視するネットワークは数えない。
// GeoIP で引けない接続元は /24 で数える。
func TestSessionBindingFlapping(t *testing.T) {
	l := newBindingEnv(t, nil, func(c *config.Config) {
		c.Security.SessionBinding.MaxNetworks = 3
		c.Security.SessionBinding.IgnoreNetworks = []string{"10.0.0.0/8"}
	})
	l.hdr = []string{"X-Forwarded-For", "100.64.1.1"}
	_, cookie := l.login(t, "pat@example.com")
	from := func(ip string) {
		t.Helper()
		l.hdr = []string{"X-Forwarded-For", ip}
		if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
			t.Fatalf("%s: %d", ip, code)
		}
	}
	for range 3 {
		from("100.64.1.1")
		from("100.64.2.1")
		from("10.1.2.3")
		from("10.9.9.9")
	}
	if got := l.anomalies(t); len(got) != 0 {
		t.Fatalf("two networks: %v", got)
	}
	from("100.64.3.1")
	if got := l.anomalies(t); len(got) != 1 || got[0] != "network_flapping" {
		t.Fatalf("three networks: %v", got)
	}
	if ev := l.lastAudit(t, sessionbinding.EventAnomaly); ev.Details["networks"] != float64(3) {
		t.Fatalf("anomaly: %+v", ev)
	}
	if r := bindingRisk(l.auditOf(t, "session.risk_updated")); r["ip"] != float64(70) {
		t.Fatalf("raised risk: %v", r)
	}

	// window を過ぎた後に 1 つずつ移るのは数えない（別の系列で確かめる）。
	l.hdr = []string{"X-Forwarded-For", "100.64.1.1"}
	_, cookie = l.login(t, "pat@example.com")
	for _, ip := range []string{"100.64.1.1", "100.64.2.1", "100.64.3.1", "100.64.4.1"} {
		l.advance(6 * time.Minute)
		from(ip)
	}
	if got := l.anomalies(t); len(got) != 1 {
		t.Fatalf("slow moves: %v", got)
	}
}

// フィーチャーが無ければ見ない。
func TestSessionBindingOff(t *testing.T) {
	l := newProtectEnv(t, nil, nil, nil)
	l.hdr = []string{"X-Forwarded-For", "198.51.100.10"}
	_, cookie := l.login(t, "pat@example.com")
	for _, ip := range []string{"203.0.113.1", "100.64.1.1", "100.64.2.1", "100.64.3.1", "100.64.4.1", "100.64.5.1"} {
		l.hdr = []string{"X-Forwarded-For", ip}
		if code, _ := l.meDo(t, "GET", cookie, "/v1/me", nil); code != 200 {
			t.Fatalf("%s: %d", ip, code)
		}
	}
	if got := l.anomalies(t); len(got) != 0 {
		t.Fatalf("anomalies without the feature: %v", got)
	}
}

// 設定の検査。
func TestSessionBindingConfig(t *testing.T) {
	c := config.Default()
	c.Security.SessionBinding.MaxNetworks = 1
	c.Security.SessionBinding.IgnoreNetworks = []string{"nope"}
	c.Security.SessionBinding.DeviceChanged.Actions = []string{"explode"}
	c.Security.SessionBinding.ASNChanged.Score = 101
	err := c.Validate()
	if err == nil {
		t.Fatal("no error")
	}
	got := err.Error()
	for _, want := range []string{"max_networks", "ignore_networks", `actions: unknown value "explode"`, "asn_changed.score"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
