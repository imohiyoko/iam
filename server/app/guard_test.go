package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// auditTypes は監査ログのイベントの種類を古い順に返す。
func (l *loginEnv) auditTypes(t *testing.T) []audit.Event {
	t.Helper()
	var out []audit.Event
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		recs, err := tx.Audit().Scan(ctx, 1, 10000)
		for _, r := range recs {
			var e audit.Event
			if err := json.Unmarshal(r.Payload, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func countType(es []audit.Event, typ string) int {
	n := 0
	for _, e := range es {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// 不変条件：本人確認の前は、アカウントの有無で応答も応答時間も変わらない（4.9、13.5）。
func TestLoginResponseTimeFloor(t *testing.T) {
	const floor = 80 * time.Millisecond
	l := newLoginEnvWith(t, func(c *config.Config) { c.Security.Login.MinResponseTime = config.Duration(floor) }, nil)
	l.login(t, "known@example.com")

	shape := func(b []byte) string {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(m))
		for k, v := range m {
			keys = append(keys, k+":"+strings.Repeat("x", len(v.(string))))
		}
		slices.Sort(keys)
		return strings.Join(keys, ",")
	}
	var shapes []string
	for _, email := range []string{"known@example.com", "unknown@example.com"} {
		start := time.Now()
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": email})
		if took := time.Since(start); took < floor {
			t.Fatalf("%s answered in %s, below the floor %s", email, took, floor)
		}
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", email, w.Code, w.Body)
		}
		shapes = append(shapes, shape(w.Body.Bytes()))
	}
	if shapes[0] != shapes[1] {
		t.Fatalf("responses differ: %s vs %s", shapes[0], shapes[1])
	}
	// 失敗も同じ下限を守る。
	start := time.Now()
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": "nope", "code": "000000"}); w.Code != 401 {
		t.Fatalf("verify: %d", w.Code)
	}
	if took := time.Since(start); took < floor {
		t.Fatalf("failure answered in %s", took)
	}
	// ログイン以外は待たない。
	start = time.Now()
	l.do(t, l.a.PublicHandler(), "GET", "/healthz", nil)
	if took := time.Since(start); took >= floor {
		t.Fatalf("healthz waited %s", took)
	}
}

func TestRateLimitPerAccount(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Security.Login.RateLimit.PerAccount = 2 }, nil)
	start := func(email string) *http.Response {
		return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": email}).Result()
	}
	for range 2 {
		if r := start("a@example.com"); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	// 大文字小文字の違いでは逃れられない。登録の有無も関係しない。
	for range 2 {
		r := start("A@example.com")
		if r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
			t.Fatalf("want 429 with Retry-After, got %d %v", r.StatusCode, r.Header)
		}
	}
	if r := start("b@example.com"); r.StatusCode != 200 {
		t.Fatalf("other address: %d", r.StatusCode)
	}
	es := l.auditTypes(t)
	if n := countType(es, "rate_limit.triggered"); n != 1 {
		t.Fatalf("rate_limit.triggered recorded %d times, want once per window", n)
	}
	if n := countType(es, "login.email.requested"); n != 3 {
		t.Fatalf("flows started = %d", n)
	}
	// 窓が過ぎれば戻る。
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(11 * time.Minute)
	if r := start("a@example.com"); r.StatusCode != 200 {
		t.Fatalf("after window: %d", r.StatusCode)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Security.Login.RateLimit.PerIP = 3 }, nil)
	for i := range 3 {
		if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": "x", "code": "1"}); w.Code != 401 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": "c@example.com"})
	if w.Code != 429 || !bytes.Contains(w.Body.Bytes(), []byte(`"rate_limited"`)) {
		t.Fatalf("want 429 rate_limited, got %d %s", w.Code, w.Body)
	}
	// ログイン以外は数えない。
	if w := l.do(t, l.a.PublicHandler(), "GET", "/healthz", nil); w.Code != 200 {
		t.Fatalf("healthz: %d", w.Code)
	}
	if n := countType(l.auditTypes(t), "rate_limit.triggered"); n != 1 {
		t.Fatalf("rate_limit.triggered = %d", n)
	}
}

func TestIPBucket(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2::9":      "2001:db8:1:2::/64",
		"not-an-ip":            "not-an-ip",
	} {
		if got := ipBucket(in); got != want {
			t.Errorf("ipBucket(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWarningsOverHTTP(t *testing.T) {
	binary := feature.Registered()
	t.Run("warn is returned and stored", func(t *testing.T) {
		l := newLoginEnvWith(t, func(c *config.Config) { c.Security.Warnings = map[string]string{"single_factor": "warn"} }, binary)
		if !l.a.Plan().IsActive(feature.Warnings) {
			t.Fatalf("warnings must be active on a fresh install: %+v", l.a.Plan())
		}
		res, _ := l.login(t, "w@example.com")
		ws, _ := res["warnings"].([]any)
		if len(ws) != 1 || ws[0].(map[string]any)["code"] != warning.CodeSingleFactor {
			t.Fatalf("warnings = %v", res["warnings"])
		}
		err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			s, err := tx.Sessions().Get(ctx, l.a.realm.ID, res["session_id"].(string))
			if err == nil && !bytes.Contains(s.Warnings, []byte(`"single_factor"`)) {
				t.Fatalf("sessions.warnings = %s", s.Warnings)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ignore by default", func(t *testing.T) {
		l := newLoginEnvWith(t, nil, binary)
		res, _ := l.login(t, "i@example.com")
		if ws, ok := res["warnings"].([]any); !ok || len(ws) != 0 {
			t.Fatalf("warnings = %v", res["warnings"])
		}
	})
	t.Run("deny returns the reason after identity", func(t *testing.T) {
		l := newLoginEnvWith(t, func(c *config.Config) { c.Security.Warnings = map[string]string{"single_factor": "deny"} }, binary)
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": "d@example.com"})
		var st struct {
			FlowID string `json:"flow_id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &st)
		if _, err := l.a.notifier.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		n := l.notes.last(t)
		w = l.do(t, l.a.AdminHandler(), "POST", "/v1/admin/notifications/"+n.ID+":claim", nil, "Authorization", "Bearer "+l.apiKey)
		var sec struct{ Code string }
		_ = json.Unmarshal(w.Body.Bytes(), &sec)
		w = l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": st.FlowID, "code": sec.Code})
		var body struct {
			Error   string   `json:"error"`
			Reasons []string `json:"reasons"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 403 || body.Error != "warning_denied.single_factor" || len(body.Reasons) != 1 {
			t.Fatalf("want 403 warning_denied.single_factor, got %d %s", w.Code, w.Body)
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookie && c.Value != "" {
				t.Fatal("a session cookie was issued")
			}
		}
		es := l.auditTypes(t)
		if countType(es, "session.created") != 0 || countType(es, "user.created") != 0 || countType(es, "login.failed") != 1 {
			t.Fatalf("audit = %v", es)
		}
	})
	t.Run("feature off skips evaluation", func(t *testing.T) {
		l := newLoginEnvWith(t, func(c *config.Config) {
			c.Security.Warnings = map[string]string{"single_factor": "deny"}
			c.Features = &[]string{}
		}, binary)
		if res, _ := l.login(t, "off@example.com"); res["created"] != true {
			t.Fatalf("res = %v", res)
		}
	})
}

// 空の DB では有効にするフィーチャーを台帳に active で記録する。既存の DB では記録しない（11.12）。
func TestFreshInstallActivatesFeatures(t *testing.T) {
	binary := []feature.Feature{{Name: feature.Warnings, DataVersion: 1, DefaultEnabled: true}, {Name: feature.Password, DataVersion: 1}}
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, binary)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Plan().IsActive(feature.Warnings) || a.Plan().IsActive(feature.Password) {
		t.Fatalf("plan = %+v", a.Plan())
	}

	// 既存の DB（realm がある）では、新しく含めたフィーチャーを勝手に有効にしない。
	e2 := newEnv(t)
	if _, err := New(context.Background(), e2.cfg, e2.deps, nil); err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), e2.cfg, e2.deps, binary)
	if err != nil {
		t.Fatal(err)
	}
	if b.Plan().IsActive(feature.Warnings) || len(b.Plan().Warnings) == 0 {
		t.Fatalf("existing install: plan = %+v", b.Plan())
	}
}
