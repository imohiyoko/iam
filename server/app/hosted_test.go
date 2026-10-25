package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/adapters/notifier/dev"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/port"
)

func TestHostedLoginPage(t *testing.T) {
	l := newLoginEnv(t)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := l.a.oauth.NewConnection(ctx, l.a.realm.ID, "google", "google", "cid", "secret", []string{"https://id.example/login/oauth/callback"})
		if err != nil {
			return err
		}
		return tx.Connections().Create(ctx, c)
	})
	if err != nil {
		t.Fatal(err)
	}

	w := l.do(t, l.a.PublicHandler(), "GET", "/login?return_to=/x%22%3E%3Cscript%3Ealert(1)%3C/script%3E", nil, "Accept-Language", "ja-JP,ja;q=0.9,en;q=0.8")
	body := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET /login: %d %s", w.Code, w.Header())
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	for _, want := range []string{`lang="ja"`, "メールアドレス", `data-connection="google"`, `data-page="login"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("return_to is not escaped")
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login", nil); !strings.Contains(w.Body.String(), `lang="en"`) {
		t.Fatal("default language must be en")
	}
	for path, page := range map[string]string{"/login/link": "link", "/login/email": "magic_link", "/login/oauth/callback": "oauth_callback"} {
		if w := l.do(t, l.a.PublicHandler(), "GET", path, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `data-page="`+page+`"`) {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login/assets/login.js", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "/v1/login/email:start") {
		t.Fatalf("login.js: %d", w.Code)
	}
	for _, path := range []string{"/login/assets/login.html", "/login/assets/../app.go", "/login/nope"} {
		if w := l.do(t, l.a.PublicHandler(), "GET", path, nil); w.Code != 404 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/login", nil); w.Code != 405 {
		t.Fatalf("POST /login: %d", w.Code)
	}
	// API は今までどおり。
	if w := l.do(t, l.a.PublicHandler(), "GET", "/healthz", nil); w.Code != 200 {
		t.Fatalf("healthz: %d", w.Code)
	}
}

func TestHostedLoginTemplateOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "login.html"), []byte(`<!doctype html><title>Acme</title><main id="app" data-page="{{.Page}}">{{.T.Title}}</main>`), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newLoginEnvWith(t, func(c *config.Config) { c.Server.LoginTemplates = dir }, nil)
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login", nil); !strings.Contains(w.Body.String(), "<title>Acme</title>") {
		t.Fatalf("override not used: %s", w.Body)
	}

	// 誤ったテンプレートは起動時に拒否する。
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "login.html"), []byte(`{{.NoSuchField}}`), 0o600)
	e := newEnv(t)
	e.cfg.Server.LoginTemplates = bad
	if _, err := New(context.Background(), e.cfg, e.deps, nil); err == nil {
		t.Fatal("broken template accepted")
	}
}

// 開発用の Notifier は秘密を取り出してログに出す（配信用のアプリ無しで試せるように）。
func TestDevNotifierShowsSecret(t *testing.T) {
	e := newEnv(t)
	var buf bytes.Buffer
	e.deps.Notifier = &dev.Notifier{Log: slog.New(slog.NewJSONHandler(&buf, nil))}
	e.cfg.Server.PublicURL = "http://localhost:8080"
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.email.Start(context.Background(), a.realm.ID, "dev@example.com", emailflow.Client{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"code":"`) || !strings.Contains(buf.String(), "http://localhost:8080/login/email#token=") {
		t.Fatalf("log = %s", buf.String())
	}
}

// 戻り先は同じオリジンのパスだけ。ブラウザが外部の URL と解釈しうる形は捨てる。
func TestSafeReturnTo(t *testing.T) {
	for _, ok := range []string{"/", "/app", "/app/x?y=1#z", "/a.b/c..d"} {
		if got := safeReturnTo(ok); got != ok {
			t.Errorf("%q: got %q", ok, got)
		}
	}
	for _, bad := range []string{
		"", "app", "https://evil.example", "//evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil",
		"/a/..//evil.example", "/%2e//evil.example", "/%2E%2E//evil.example", "/./evil", "/%2f/evil.example", "/%5cevil.example",
	} {
		if got := safeReturnTo(bad); got != "" {
			t.Errorf("%q: got %q, want empty", bad, got)
		}
	}
}
