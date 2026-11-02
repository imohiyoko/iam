package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// RP-Initiated Logout 1.0 と Front-Channel Logout 1.0（design.md 5.2、ADR 0094。フィーチャー oidc_logout）。
//
//	GET|POST /oauth2/end_session          連携先が送るログアウトの要求
//	POST     /oauth2/end_session/confirm  確認の画面からの答え
//
// id_token_hint がブラウザのセッション（系列と本人）と合えば、確かめずにセッションを失効させる。合わない・無いときは確認の
// 画面を出す（要求は EphemeralStore に預け、フォームにはその ID だけを入れる。CSRF の対策）。セッションの失効は
// POST /v1/logout と同じで、系列が終わり、Back-Channel Logout が outbox に積まれる（ADR 0066）。完了の画面で、系列の
// 連携先の frontchannel_logout_uri を iframe で開き、登録と一致した post_logout_redirect_uri に戻す。

const (
	oidcEndSession        = "/oauth2/end_session"
	oidcEndSessionConfirm = "/oauth2/end_session/confirm"
)

// logoutTexts はログアウトの画面の文言。言語を足すときはここに足す。
type logoutTexts struct {
	Title, Confirm, RequestedBy, SignOut, StaySignedIn, Done, Continue, Cancelled, Invalid, Expired string
}

var logoutCatalog = map[string]logoutTexts{
	"en": {
		Title: "Sign out", Confirm: "Do you want to sign out?", RequestedBy: "Requested by:", SignOut: "Sign out",
		StaySignedIn: "Stay signed in", Done: "You are signed out.", Continue: "Continue", Cancelled: "You are still signed in.",
		Invalid: "The sign-out request is not valid. Please return to the application.",
		Expired: "The sign-out request has expired. Please return to the application and try again.",
	},
	"ja": {
		Title: "ログアウト", Confirm: "ログアウトしますか？", RequestedBy: "要求したアプリ：", SignOut: "ログアウトする",
		StaySignedIn: "ログインしたままにする", Done: "ログアウトしました。", Continue: "続ける", Cancelled: "ログインしたままです。",
		Invalid: "ログアウトの要求が正しくありません。アプリに戻ってください。",
		Expired: "ログアウトの要求の期限が切れました。アプリに戻って、もう一度お試しください。",
	},
}

type logoutData struct {
	Lang, Page, Base, Client, Request, Redirect, Message string
	T                                                    logoutTexts
	Frames                                               []string
}

// newLogoutTemplate はログアウトの画面のテンプレートを読む。dir に logout.html があれば差し替える。
func newLogoutTemplate(dir string) (*template.Template, error) {
	var src []byte
	var err error
	if dir != "" {
		src, err = os.ReadFile(filepath.Join(dir, "logout.html")) // #nosec G304 -- テンプレートの場所は運用者が設定する
		if errors.Is(err, fs.ErrNotExist) {
			src, err = nil, nil
		}
	}
	if err == nil && src == nil {
		src, err = fs.ReadFile(webFS, "web/logout.html")
	}
	if err != nil {
		return nil, fmt.Errorf("hosted logout: %w", err)
	}
	t, err := template.New("logout").Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("hosted logout template: %w", err)
	}
	for _, page := range []string{"confirm", "done", "cancelled", "error"} {
		if err := t.Execute(&bytes.Buffer{}, logoutData{Lang: "en", Page: page, T: logoutCatalog["en"], Redirect: "https://rp.example/",
			Frames: []string{"https://rp.example/fcl"}}); err != nil {
			return nil, fmt.Errorf("hosted logout template: %w", err)
		}
	}
	return t, nil
}

// logoutLang は ui_locales（空白で区切った BCP 47 の並び。先頭が優先）から対応する言語を選ぶ。無ければ Accept-Language。
func logoutLang(r *http.Request, uiLocales string) string {
	for tag := range strings.FieldsSeq(uiLocales) {
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if _, ok := logoutCatalog[base]; ok {
			return base
		}
	}
	return lang(r)
}

// allowLogout は接続元ごとの回数の上限（ログインの per_ip。バケットはログインと分ける）。超えれば 429 を書いて false。
func (s *oidcServer) allowLogout(w http.ResponseWriter, r *http.Request) bool {
	c, _ := r.Context().Value(clientKey{}).(client)
	err := s.a.perIP.Allow(r.Context(), "logout:ip:"+s.a.realm.ID+":"+ratelimit.Bucket(c.IP))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		if ex.First {
			s.a.recordRateLimit(r.Context(), "ip", r.URL.Path)
		}
		writeRateLimited(w, ex)
		return false
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return false
	}
	return true
}

// endSession は end_session_endpoint（OIDC RP-Initiated Logout 2）。GET の問い合わせか POST のフォームで受ける。
func (s *oidcServer) endSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowLogout(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.logoutPage(w, r, http.StatusBadRequest, logoutData{Lang: lang(r), Page: "error"}, "", "invalid")
		return
	}
	form := r.Form
	if r.Method == http.MethodPost {
		form = r.PostForm
	}
	l := logoutLang(r, form.Get("ui_locales"))
	ctx := r.Context()
	in := provider.EndSessionInput{IDTokenHint: form.Get("id_token_hint"), ClientID: form.Get("client_id"),
		PostLogoutRedirectURI: form.Get("post_logout_redirect_uri"), State: form.Get("state")}
	// logout_hint は手がかりにすぎない（ログアウトするのはこのブラウザのセッション）ので使わない。
	var e provider.EndSession
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		e, err = s.a.tokens.EndSession(ctx, tx, s.a.realm.ID, in)
		return err
	})
	if errors.Is(err, provider.ErrInvalidLogoutRequest) {
		// 戻り先が確かめられないので、連携先には戻さない。
		s.logoutPage(w, r, http.StatusBadRequest, logoutData{Lang: l, Page: "error"}, "", "invalid")
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	au, ok := authFrom(ctx)
	if !ok {
		// ログインしていない：終えるセッションが無いので、連携先にも知らせない（漏れた ID トークンで、このブラウザの連携先の
		// ログインを終えさせられないように）。戻り先があれば戻す。
		s.finishLogout(w, r, l, e, "")
		return
	}
	if e.HintSID != "" && e.HintSID == au.SID && e.HintSub == au.PublicID && au.PrincipalType == port.PrincipalUser {
		s.logout(w, r, l, e, au)
		return
	}
	// 連携先が示したセッションと合わない（無い）ので、本人に確かめる。確認はこのセッションでだけ通す。
	e.SID, e.PrincipalID = au.SID, au.PrincipalID
	rid, err := s.a.flow.HoldLogout(ctx, e)
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	s.logoutPage(w, r, http.StatusOK, logoutData{Lang: l, Page: "confirm", Client: e.ClientName, Request: rid}, originOf(e.RedirectURI), "")
}

// confirmEndSession は確認の画面の答え。要求は1回だけ使え、確認を求めたときと同じセッション（系列と本人）でだけ通る。
func (s *oidcServer) confirmEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowLogout(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.logoutPage(w, r, http.StatusBadRequest, logoutData{Lang: lang(r), Page: "error"}, "", "invalid")
		return
	}
	// 言語は確認の画面のもの（ui_locales で選んだもの）を引き継ぐ。
	l := logoutLang(r, r.PostForm.Get("ui_locales"))
	ctx := r.Context()
	e, err := s.a.flow.TakeLogout(ctx, s.a.realm.ID, r.PostForm.Get("request"))
	if errors.Is(err, provider.ErrLogoutRequestExpired) {
		s.logoutPage(w, r, http.StatusBadRequest, logoutData{Lang: l, Page: "error"}, "", "expired")
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	au, ok := authFrom(ctx)
	if ok && (au.SID != e.SID || au.PrincipalID != e.PrincipalID) {
		s.logoutPage(w, r, http.StatusBadRequest, logoutData{Lang: l, Page: "error"}, "", "expired")
		return
	}
	if r.PostForm.Get("action") != "logout" {
		s.logoutPage(w, r, http.StatusOK, logoutData{Lang: l, Page: "cancelled"}, "", "")
		return
	}
	if !ok {
		// 待つ間に（別のタブなどで）ログアウトした。系列の連携先にだけ知らせる。
		s.finishLogout(w, r, l, e, e.SID)
		return
	}
	s.logout(w, r, l, e, au)
}

// logout はブラウザのセッションを失効させ（系列が終わり、Back-Channel Logout が積まれる）、完了の画面に進む。
func (s *oidcServer) logout(w http.ResponseWriter, r *http.Request, l string, e provider.EndSession, au auth) {
	ctx := r.Context()
	if err := s.a.sessions.Revoke(ctx, s.a.realm.ID, au.SessionID, au.PrincipalID, session.ReasonLogout, au.Actor(), requestID(ctx)); err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	if au.viaCookie {
		http.SetCookie(w, s.a.clearSessionCookie())
	}
	s.finishLogout(w, r, l, e, au.SID)
}

// finishLogout は完了の画面。系列 sid の連携先の frontchannel_logout_uri を iframe で開き、戻り先があれば JS で移る。
// 開くものが無ければ、戻り先にすぐ転送する。
func (s *oidcServer) finishLogout(w http.ResponseWriter, r *http.Request, l string, e provider.EndSession, sid string) {
	ctx := r.Context()
	var frames []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		frames, err = s.a.tokens.FrontChannelURLs(ctx, tx, s.a.realm.ID, sid)
		return err
	})
	if err != nil {
		// セッションは失効済みなので、知らせられなくてもログアウトは終える（Back-Channel Logout は積んである）。
		s.a.deps.Logger.WarnContext(ctx, "oidc: front-channel logout targets", "error", err)
		frames = nil
	}
	redirect := e.RedirectURL()
	if len(frames) == 0 && redirect != "" {
		// #nosec G710 -- 戻り先は連携先に登録した post_logout_redirect_uri と完全一致したものだけ（provider.EndSession）
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	s.logoutPage(w, r, http.StatusOK, logoutData{Lang: l, Page: "done", Redirect: redirect, Frames: frames}, "", "")
}

// originOf は URI のオリジン。空・読めなければ空。
func originOf(uri string) string {
	if uri == "" {
		return ""
	}
	o, _ := provider.Origin(uri)
	return o
}

// logoutCSP はログアウトの画面の CSP。iframe で開く連携先のオリジンだけを frame-src に、確認のフォームの後の転送先
// （戻り先のオリジン）を form-action に足す（ブラウザはフォームの送信の後の転送にも form-action を当てる）。
func logoutCSP(frames []string, formTarget string) string {
	frame := "'none'"
	var origins []string
	for _, f := range frames {
		if o, ok := provider.Origin(f); ok && !slices.Contains(origins, o) {
			origins = append(origins, o)
		}
	}
	if len(origins) > 0 {
		frame = strings.Join(origins, " ")
	}
	form := "'self'"
	if formTarget != "" {
		form += " " + formTarget
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; frame-src " + frame + "; form-action " + form +
		"; frame-ancestors 'none'; base-uri 'none'"
}

// logoutPage は画面を描く。message は error の画面の文言の種類（invalid・expired）。
func (s *oidcServer) logoutPage(w http.ResponseWriter, r *http.Request, status int, d logoutData, formTarget, message string) {
	if _, ok := logoutCatalog[d.Lang]; !ok {
		d.Lang = "en"
	}
	d.T, d.Base = logoutCatalog[d.Lang], s.a.base
	switch message {
	case "invalid":
		d.Message = d.T.Invalid
	case "expired":
		d.Message = d.T.Expired
	}
	var buf bytes.Buffer
	if err := s.a.logoutTmpl.Execute(&buf, d); err != nil {
		s.a.deps.Logger.ErrorContext(r.Context(), "hosted logout: render", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", logoutCSP(d.Frames, formTarget))
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
