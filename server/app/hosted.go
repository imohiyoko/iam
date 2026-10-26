package app

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/imohiyoko/iam/shared/port"
)

// ホスト型ログイン画面（design.md 2.5）。公開 API の上に作り、作り込まない（テンプレートの差し替えと多言語化のみ）。
//
//	GET /login                 メール・外部プロバイダでのログイン
//	GET /login/email#token=…   メールのマジックリンク（要求したブラウザでだけ通る）
//	GET /login/link#token=…    運営者が発行したログイン用リンク
//	GET /login/oauth/callback  プロバイダからの戻り先（connection の redirect_uris に登録する）
//
// トークンは URL のフラグメントで受け取るため、サーバーのログにも Referer にも残らない。

//go:embed web
var webFS embed.FS

const hostedCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// texts は画面の文言。言語を足すときはここに足す。
type texts struct {
	Title, Email, SendCode, Or, ContinueWith, CodeSent, Code, Verify, UseAnother, Working, TOTP string
	// Messages は API のエラーのコードなどに対応する文言（JS が使う）。
	Messages map[string]string
}

var catalog = map[string]texts{
	"en": {
		Title: "Sign in", Email: "Email address", SendCode: "Send code", Or: "or", ContinueWith: "Continue with",
		CodeSent: "If the address can sign in, we sent a 6-digit code. It expires in a few minutes.", Code: "Code",
		Verify: "Sign in", UseAnother: "Use another address", Working: "Signing in…", TOTP: "Code from your authenticator app",
		Messages: map[string]string{
			"done": "You are signed in.", "warnings": "You are signed in. Please review your account security.",
			"authentication_failed": "Sign-in failed. Please try again.", "invalid_email": "Enter a valid email address.",
			"rate_limited": "Too many attempts. Please wait and try again.", "account_exists": "This email is already registered. Sign in with your email first, then link this provider.",
			"email_unverified": "The provider has not verified your email address.", "error": "Something went wrong. Please try again.",
			"second_factor_unsupported": "Confirm with your passkey in the app to finish signing in.",
			"enroll_required":           "Set up two-step verification in the app to finish signing in.",
		},
	},
	"ja": {
		Title: "ログイン", Email: "メールアドレス", SendCode: "コードを送る", Or: "または", ContinueWith: "次で続ける：",
		CodeSent: "ログインできるアドレスなら、6桁のコードを送りました。数分で期限が切れます。", Code: "コード",
		Verify: "ログイン", UseAnother: "別のアドレスを使う", Working: "ログインしています…", TOTP: "認証アプリのコード",
		Messages: map[string]string{
			"done": "ログインしました。", "warnings": "ログインしました。アカウントの安全性を確認してください。",
			"authentication_failed": "ログインできませんでした。もう一度お試しください。", "invalid_email": "正しいメールアドレスを入力してください。",
			"rate_limited": "試行が多すぎます。しばらく待ってからお試しください。", "account_exists": "このメールは登録済みです。先にメールでログインしてから、このプロバイダを連携してください。",
			"email_unverified": "プロバイダでメールアドレスが確認されていません。", "error": "問題が起きました。もう一度お試しください。",
			"second_factor_unsupported": "ログインを終えるには、アプリで passkey による確認をしてください。",
			"enroll_required":           "ログインを終えるには、アプリで2段階認証を設定してください。",
		},
	},
}

// hosted は画面を返す。
type hosted struct {
	a      *App
	tmpl   *template.Template
	assets http.Handler
}

// newHosted はテンプレートを読む。dir が空なら組み込みのものを使う。dir の login.html で差し替えられる。
func newHosted(a *App, dir string) (*hosted, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	var src []byte
	if dir == "" {
		src, err = fs.ReadFile(sub, "login.html")
	} else {
		src, err = os.ReadFile(filepath.Join(dir, "login.html")) // #nosec G304 -- テンプレートの場所は運用者が設定する
	}
	if err != nil {
		return nil, fmt.Errorf("hosted login: %w", err)
	}
	t, err := template.New("login").Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("hosted login template: %w", err)
	}
	// 起動時に一度描いて、差し替えたテンプレートの誤りを起動時に見つける。
	if err := t.Execute(&bytes.Buffer{}, pageData{Lang: "en", T: catalog["en"], Messages: catalog["en"].Messages}); err != nil {
		return nil, fmt.Errorf("hosted login template: %w", err)
	}
	return &hosted{a: a, tmpl: t, assets: http.StripPrefix("/login/assets/", http.FileServerFS(sub))}, nil
}

type pageData struct {
	Lang, Page, ReturnTo string
	T                    texts
	Messages             map[string]string
	Connections          []string
}

// lang は Accept-Language から対応する言語を選ぶ（品質値は見ず、書かれた順に最初に対応するもの）。
func lang(r *http.Request) string {
	for part := range strings.SplitSeq(r.Header.Get("Accept-Language"), ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if _, ok := catalog[base]; ok {
			return base
		}
	}
	return "en"
}

var pages = map[string]string{
	"/login": "login", "/login/email": "magic_link", "/login/link": "link", "/login/oauth/callback": "oauth_callback",
}

func (h *hosted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", hostedCSP)
	if strings.HasPrefix(r.URL.Path, "/login/assets/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/login/assets/")
		if name != "login.js" && name != "login.css" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		h.assets.ServeHTTP(w, r)
		return
	}
	page, ok := pages[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	l := lang(r)
	d := pageData{Lang: l, Page: page, T: catalog[l], Messages: catalog[l].Messages, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to"))}
	if page == "login" {
		var err error
		if d.Connections, err = h.connections(r.Context()); err != nil {
			h.a.deps.Logger.ErrorContext(r.Context(), "hosted login: list connections", "error", err)
		}
	}
	var buf bytes.Buffer
	if err := h.tmpl.Execute(&buf, d); err != nil {
		h.a.deps.Logger.ErrorContext(r.Context(), "hosted login: render", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (h *hosted) connections(ctx context.Context) ([]string, error) {
	var out []string
	err := h.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Connections().List(ctx, h.a.realm.ID)
		for _, c := range cs {
			out = append(out, c.Slug)
		}
		return err
	})
	return out, err
}

// isHosted は画面のパスかを返す。
func isHosted(path string) bool { return path == "/login" || strings.HasPrefix(path, "/login/") }

// safeReturnTo はログイン後の戻り先を、同じオリジンのパスに限る（オープンリダイレクトを防ぐ）。
// 画面の JS も解決後のオリジンを確かめるが、ここで先に絞る。ブラウザの URL の解析は制御文字を取り除き、
// バックスラッシュを "/" とみなし、ドット区間を畳むため（"/a/..//evil.example" は "//evil.example" になる）、
// それらを含む値と、"//" を含む値は受け付けない。
func safeReturnTo(s string) string {
	if !strings.HasPrefix(s, "/") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '\\' }) {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return ""
	}
	// 復号したパスで見る（"%2e" は "."、"%2f" は "/"、"%5c" は "\\" になる）。
	if strings.Contains(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return ""
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return ""
		}
	}
	return s
}
