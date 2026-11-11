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

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imohiyoko/iam/authn/provider"
)

// OAuth 2.0 Form Post Response Mode（フィーチャー form_post。ADR 0124）。
//
// 認可応答（code・state・iss、またはエラー）をブラウザの転送ではなく、連携先の redirect_uri へ自動で POST する画面で返す。
// 認可エンドポイントは転送しか返せないので、応答を EphemeralStore に 1 回限り・短い期限で預け、oidcFormPost の画面に転送する。
// ログインした後の応答はそのセッション（sid）に結び付け、別のブラウザでは開けない。

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
	SID    string     `json:"sid,omitempty"`
}

func formPostKey(realmID, rid string) string { return "oidc:formpost:v1:" + realmID + ":" + rid }

// authResponse は認可応答の転送を返す。form_post なら応答を預けて画面に回し、それ以外はクエリで戻り先へ転送する。
func (s *oidcServer) authResponse(ctx context.Context, req provider.AuthRequest, response any, sid string) (*op.Redirect, error) {
	u, err := op.AuthResponseURL(req.RedirectURI, oidc.ResponseTypeCode, oidc.ResponseModeQuery, response, s.responseEncoder())
	if err != nil {
		return nil, err
	}
	if req.ResponseMode != string(responseModeFormPost) {
		return op.NewRedirect(u), nil
	}
	// 応答の値は、戻り先の URI に足したクエリの値（戻り先が元から持つクエリは除く）。
	full, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	orig := base.Query()
	for k, vs := range full.Query() {
		if _, ok := orig[k]; !ok {
			params[k] = vs
		}
	}
	b, err := json.Marshal(formPostResponse{Action: req.RedirectURI, Params: params, SID: sid})
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	rid := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.a.deps.Ephemeral.Set(ctx, formPostKey(s.a.realm.ID, rid), b, formPostTTL); err != nil {
		return nil, err
	}
	return op.NewRedirect(s.a.base + oidcFormPost + "?" + url.Values{"r": {rid}}.Encode()), nil
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
	b, ok, err := s.a.deps.Ephemeral.Take(ctx, formPostKey(s.a.realm.ID, rid))
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	var resp formPostResponse
	if !ok || json.Unmarshal(b, &resp) != nil {
		http.Error(w, "The sign-in response has expired. Please return to the application and try again.", http.StatusBadRequest)
		return
	}
	if resp.SID != "" {
		if au, ok := authFrom(ctx); !ok || au.SID != resp.SID {
			http.Error(w, "The sign-in response belongs to another browser session.", http.StatusBadRequest)
			return
		}
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
