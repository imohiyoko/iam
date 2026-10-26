package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// recorder は届いた通知を記録する Notifier。
type recorder struct {
	mu   sync.Mutex
	got  []port.Notification
	sent bytes.Buffer // 外部に渡ったペイロード
}

func (r *recorder) Notify(_ context.Context, n port.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(n)
	r.sent.Write(b)
	r.got = append(r.got, n)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *recorder) last(t *testing.T) port.Notification {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) == 0 {
		t.Fatal("no notification")
	}
	return r.got[len(r.got)-1]
}

// loginEnv はメールのログインを HTTP から通しで試す環境。外部に出たものをすべて out に集める。
type loginEnv struct {
	a      *App
	e      *env
	notes  *recorder
	apiKey string
	out    bytes.Buffer
	codes  []string // claim で受け取ったコード（秘密が漏れないことの確認用）
}

func newLoginEnv(t *testing.T) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, nil, nil)
}

// newLoginEnvWith は設定を変え、binary のフィーチャーを含めて組み立てる。
func newLoginEnvWith(t *testing.T, edit func(*config.Config), binary []feature.Feature) *loginEnv {
	t.Helper()
	return newLoginEnvDeps(t, edit, binary, nil)
}

// newLoginEnvDeps は newLoginEnvWith に加え、アダプタも差し替える。
func newLoginEnvDeps(t *testing.T, edit func(*config.Config), binary []feature.Feature, editDeps func(*Deps)) *loginEnv {
	t.Helper()
	e := newEnv(t)
	if edit != nil {
		edit(&e.cfg)
	}
	notes := &recorder{}
	e.deps.Notifier = notes
	if editDeps != nil {
		editDeps(&e.deps)
	}
	a, err := New(context.Background(), e.cfg, e.deps, binary)
	if err != nil {
		t.Fatal(err)
	}
	l := &loginEnv{a: a, e: e, notes: notes}
	err = a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := serviceaccount.Create(ctx, tx, a.realm.ID, "notification-delivery", a.deps.Clock.Now())
		if err != nil {
			return err
		}
		l.apiKey = c.APIKey
		return role.Grant(ctx, tx, a.realm.ID, role.NotificationDelivery, port.PrincipalServiceAccount, c.Account.ID, a.deps.Clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *loginEnv) do(t *testing.T, h http.Handler, method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for k, v := range w.Header() {
		l.out.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	l.out.Write(w.Body.Bytes())
	return w
}

// login はメールの所有確認でログインし、応答とセッションの Cookie を返す。
func (l *loginEnv) login(t *testing.T, email string) (map[string]any, string) {
	t.Helper()
	w := l.loginVerify(t, email)
	if w.Code != 200 {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return res, c.Value
		}
	}
	t.Fatal("no session cookie")
	return nil, ""
}

// loginVerify はメールのコードで確認まで進め、確認の応答を返す（拒否の応答を確かめるため）。
func (l *loginEnv) loginVerify(t *testing.T, email string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": email})
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var st struct {
		FlowID string `json:"flow_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.notifier.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	n := l.notes.last(t)
	w = l.do(t, l.a.AdminHandler(), "POST", "/v1/admin/notifications/"+n.ID+":claim", nil, "Authorization", "Bearer "+l.apiKey)
	if w.Code != 200 {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	var sec struct{ Code string }
	if err := json.Unmarshal(w.Body.Bytes(), &sec); err != nil || sec.Code == "" {
		t.Fatalf("claim body: %s %v", w.Body, err)
	}
	l.codes = append(l.codes, sec.Code)
	return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": st.FlowID, "code": sec.Code})
}

func TestEmailSignupThenLogin(t *testing.T) {
	l := newLoginEnv(t)
	first, _ := l.login(t, "alice@example.com")
	if first["created"] != true {
		t.Fatalf("first = %v", first)
	}
	if n := l.notes.last(t); n.Type != "email_verification" || n.UserID != "" {
		t.Fatalf("signup notification = %+v", n)
	}
	second, cookie := l.login(t, "Alice@Example.com")
	if second["created"] != false || second["user_id"] != first["user_id"] {
		t.Fatalf("second = %v, first = %v", second, first)
	}
	if n := l.notes.last(t); n.Type != "magic_link" || n.UserID != first["user_id"] {
		t.Fatalf("login notification = %+v", n)
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/sessions", nil, "Cookie", sessionCookie+"="+cookie); w.Code != 200 {
		t.Fatalf("sessions: %d %s", w.Code, w.Body)
	}
}

// 不変条件：内部 ID は Storage の外（API の応答、Cookie、通知、監査ログ）に出ない（design.md 13.5、ADR 0045）。
func TestInternalIDsNeverLeave(t *testing.T) {
	l := newLoginEnv(t)
	res, _ := l.login(t, "alice@example.com")
	_, cookie := l.login(t, "alice@example.com")
	l.do(t, l.a.PublicHandler(), "GET", "/v1/me/sessions", nil, "Cookie", sessionCookie+"="+cookie)
	l.do(t, l.a.PublicHandler(), "POST", "/v1/logout", nil, "Cookie", sessionCookie+"="+cookie)

	ctx := context.Background()
	if _, err := l.a.relay.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	l.out.Write(l.e.out.Bytes())
	l.out.Write(l.notes.sent.Bytes())
	if l.e.out.Len() == 0 || l.notes.sent.Len() == 0 {
		t.Fatal("nothing was emitted; the test would pass vacuously")
	}

	var internal []string
	err := l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, res["user_id"].(string))
		if err != nil {
			return err
		}
		internal = append(internal, u.ID)
		es, err := tx.Emails().ListByUser(ctx, l.a.realm.ID, u.ID)
		for _, e := range es {
			internal = append(internal, e.ID)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(internal) < 2 {
		t.Fatalf("internal ids = %v", internal)
	}
	out := l.out.String()
	for _, v := range internal {
		// 接頭辞を除いた部分も探す（形を変えて出ていないか）。
		_, body, _ := strings.Cut(v, "_")
		if strings.Contains(out, v) || strings.Contains(out, body) {
			t.Errorf("internal id %s leaked", v)
		}
	}
}
