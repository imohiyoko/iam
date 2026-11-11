package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imohiyoko/iam/authn/provider"
)

// OAuth 2.0 Form Post Response Mode（フィーチャー form_post。ADR 0124）。
//
// 認可応答（code・state・iss、またはエラー）をブラウザの転送ではなく、連携先の redirect_uri へ自動で POST する画面で返す。
// 認可エンドポイントは転送しか返せないので、応答を EphemeralStore に 1 回限り・短い期限で預け、oidcFormPost の画面に転送する。
// ログインした後の応答はそのセッション（sid）に結び付け、別のブラウザでは開けない（開こうとしても使い切らない）。

const (
	oidcFormPost = "/oauth2/authorize/form_post"
	// formPostTTL は預けた応答を開ける期間（転送の直後に開く）。
	formPostTTL = time.Minute
)

// responseModeFormPost は response_mode=form_post（OAuth 2.0 Form Post Response Mode）。
const responseModeFormPost = oidc.ResponseModeFormPost

type formPostResponse struct {
	Action string     `json:"action"`
	Params url.Values `json:"params"`
}

// formPostKey は預けた応答の鍵。ログインした後の応答はセッション（sid）を鍵に含め、そのセッションの Cookie でしか開けない
// （別のブラウザで開こうとしても使い切らない）。
func formPostKey(realmID, sid, rid string) string {
	return "oidc:formpost:v2:" + realmID + ":" + sid + ":" + rid
}

// authResponse は認可応答の転送を返す。form_post なら応答を預けて画面に回し、それ以外はクエリで戻り先へ転送する。
// フィーチャーが止まっていれば form_post の要求でもクエリで返す（complete は先にエラーにする）。
func (s *oidcServer) authResponse(ctx context.Context, req provider.AuthRequest, response any, sid string) (*op.Redirect, error) {
	if req.ResponseMode != string(responseModeFormPost) || !s.a.formPost {
		u, err := op.AuthResponseURL(req.RedirectURI, oidc.ResponseTypeCode, oidc.ResponseModeQuery, response, s.responseEncoder())
		if err != nil {
			return nil, err
		}
		return op.NewRedirect(u), nil
	}
	// 応答の値はエンコーダーの出力そのもの（戻り先の URI が元から持つクエリは action に残り、応答の値とは混ぜない）。
	params, err := httphelper.URLEncodeParams(response, s.responseEncoder())
	if err != nil {
		return nil, err
	}
	u, err := s.storeFormPost(ctx, req.RedirectURI, params, sid)
	if err != nil {
		return nil, err
	}
	return op.NewRedirect(u), nil
}

// storeFormPost は応答を預け、それを開く画面の URL を返す。
func (s *oidcServer) storeFormPost(ctx context.Context, action string, params url.Values, sid string) (string, error) {
	b, err := json.Marshal(formPostResponse{Action: action, Params: params})
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	rid := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.a.deps.Ephemeral.Set(ctx, formPostKey(s.a.realm.ID, sid, rid), b, formPostTTL); err != nil {
		return "", err
	}
	return s.a.base + oidcFormPost + "?" + url.Values{"r": {rid}}.Encode(), nil
}

// formPostAuthKey は、検証した認可要求の戻り先と response_mode を withFormPostErrors に渡す context の鍵。
type formPostAuthKey struct{}

type formPostAuth struct {
	redirectURI string
	formPost    bool
}

// noteFormPost は VerifyAuthRequest が検証した要求（PAR で預けたものも含む）の戻り先と response_mode を控える。
func noteFormPost(ctx context.Context, d *oidc.AuthRequest) {
	if v, ok := ctx.Value(formPostAuthKey{}).(*formPostAuth); ok {
		v.redirectURI = d.RedirectURI
		v.formPost = d.ResponseMode == responseModeFormPost
	}
}

// withFormPostErrors は、op が自分で戻り先へクエリで転送するエラー（prompt・scope・response_type・code_challenge_method の検証）を、
// form_post の要求なら預けて画面に回す（ADR 0124）。op は戻り先を確かめてからしかエラーを転送しないので、ここで扱う転送先は
// 登録済みの戻り先に限られる。
func (s *oidcServer) withFormPostErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := &formPostAuth{}
		r = r.WithContext(context.WithValue(r.Context(), formPostAuthKey{}, v))
		next.ServeHTTP(&formPostErrorWriter{ResponseWriter: w, s: s, r: r, v: v}, r)
	})
}

type formPostErrorWriter struct {
	http.ResponseWriter
	s       *oidcServer
	r       *http.Request
	v       *formPostAuth
	swallow bool
}

func (w *formPostErrorWriter) WriteHeader(code int) {
	if w.swallow {
		return
	}
	if code < 300 || code >= 400 || !w.v.formPost {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	params, ok := formPostErrorParams(w.v.redirectURI, w.Header().Get("Location"))
	if !ok {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	// 転送の本文（元の URL を含む）は書かない。
	w.swallow = true
	sid := ""
	if au, ok := authFrom(w.r.Context()); ok {
		sid = au.SID
	}
	u, err := w.s.storeFormPost(w.r.Context(), w.v.redirectURI, params, sid)
	if err != nil {
		w.Header().Del("Location")
		w.s.a.unavailable(w.ResponseWriter, w.r, err)
		return
	}
	w.Header().Set("Location", u)
	w.ResponseWriter.WriteHeader(code)
}

func (w *formPostErrorWriter) Write(b []byte) (int, error) {
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// formPostErrorParams は、戻り先へのエラーの転送先から応答の値（戻り先が元から持つクエリの値を除く）を取り出す。
// 転送先が戻り先でないか、error を持たなければ偽。
func formPostErrorParams(redirectURI, location string) (url.Values, bool) {
	base, err := url.Parse(redirectURI)
	if err != nil {
		return nil, false
	}
	loc, err := url.Parse(location)
	if err != nil || loc.Scheme != base.Scheme || loc.Host != base.Host || loc.Path != base.Path {
		return nil, false
	}
	q, orig := loc.Query(), base.Query()
	if len(q["error"]) <= len(orig["error"]) {
		return nil, false
	}
	// op は戻り先のクエリの後ろに応答の値を足す（mergeQueryParams）。
	params := url.Values{}
	for k, vs := range q {
		if n := len(orig[k]); len(vs) > n {
			params[k] = vs[n:]
		}
	}
	return params, true
}

// formPost は預けた認可応答を、連携先の redirect_uri へ自動で POST する画面にする（1 回限り）。
func (s *oidcServer) formPost(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	ctx := r.Context()
	rid := r.URL.Query().Get("r")
	if rid == "" || len(rid) > 128 {
		http.Error(w, "The sign-in response has expired. Please return to the application and try again.", http.StatusBadRequest)
		return
	}
	// 今のセッションに結び付けた応答を先に、無ければセッションに結び付けない応答（ログイン前のエラー）を開く。
	var b []byte
	var ok bool
	var err error
	if au, signed := authFrom(ctx); signed && au.SID != "" {
		b, ok, err = s.a.deps.Ephemeral.Take(ctx, formPostKey(s.a.realm.ID, au.SID, rid))
	}
	if err == nil && !ok {
		b, ok, err = s.a.deps.Ephemeral.Take(ctx, formPostKey(s.a.realm.ID, "", rid))
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	var resp formPostResponse
	if !ok || json.Unmarshal(b, &resp) != nil {
		http.Error(w, "The sign-in response has expired. Please return to the application and try again.", http.StatusBadRequest)
		return
	}
	action, err := url.Parse(resp.Action)
	if err != nil || (action.Scheme != "https" && action.Scheme != "http") || action.Host == "" {
		http.Error(w, "The application's redirect URI is invalid.", http.StatusBadRequest)
		return
	}
	var fields []formPostField
	for _, k := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		for _, v := range resp.Params[k] {
			fields = append(fields, formPostField{Name: k, Value: v})
		}
	}
	var buf bytes.Buffer
	if err := formPostTmpl.Execute(&buf, formPostData{Base: s.a.base, Action: resp.Action, Fields: fields}); err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action "+action.Scheme+"://"+action.Host+
		"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(buf.Bytes())
}

type formPostField struct{ Name, Value string }

type formPostData struct {
	Base, Action string
	Fields       []formPostField
}

// formPostTmpl は連携先へ自動で POST する画面（スクリプトが無効なら送信のボタン）。
var formPostTmpl = template.Must(template.New("formpost").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Signing in</title>
<link rel="stylesheet" href="{{.Base}}/login/assets/login.css">
<script src="{{.Base}}/login/assets/formpost.js"></script>
</head>
<body>
<main>
<form id="formpost" method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<noscript><p>Script is disabled. Press the button to continue.</p><button type="submit">Continue</button></noscript>
</form>
</main>
</body>
</html>
`))
