package app

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/wsfed"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// WS-Federation のパッシブ要求者プロファイル（iam が IdP。フィーチャー wsfed。ADR 0110）。
//
//	GET /wsfed                                        wa=wsignin1.0（トークンを渡す）と wa=wsignout1.0（セッションを終える）
//	GET /wsfed/resume                                 ログイン画面から戻ってトークンを渡す
//	GET /FederationMetadata/2007-06/FederationMetadata.xml  メタデータ
//
// 別のオリジンの RP からのトップレベルの遷移で届くので、CrossOriginProtection の外に置く（GET だけを受け、状態を変えるのは
// トークンの発行の記録とサインアウトだけ）。知らない wtrealm・wreply は RP に戻さずに 400 の画面にする（fail closed）。

// isWSFed は WS-Federation のパスかを返す。
func isWSFed(path string) bool {
	return path == wsfed.PassivePath || path == wsfed.ResumePath || path == wsfed.MetadataPath
}

// newWSFedHandler は WS-Federation のハンドラ。フィーチャーが動いていなければ nil。
func newWSFedHandler(a *App) http.Handler {
	if a.wsfed == nil {
		return nil
	}
	// 要求と続きは GET だけ（getOnly）。メタデータは HEAD も受ける。
	mux := http.NewServeMux()
	mux.Handle("GET "+wsfed.PassivePath, a.withSession(http.HandlerFunc(a.wsfedPassive)))
	mux.Handle("GET "+wsfed.ResumePath, a.withSession(http.HandlerFunc(a.wsfedResume)))
	mux.HandleFunc("GET "+wsfed.MetadataPath, a.wsfedMetadata)
	return mux
}

// wsfedFail は要求の誤りを画面で返す（RP には戻さない）。理由はログにだけ出す。
func (a *App) wsfedFail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	a.deps.Logger.InfoContext(r.Context(), "wsfed: request rejected", "path", r.URL.Path, "error", err)
	http.Error(w, msg, status)
}

// wsfedRejected は解析・RP の決定の誤りを 400 にする。依存先の障害は 503。
func (a *App) wsfedRejected(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, wsfed.ErrUnknownRealm):
		a.wsfedFail(w, r, http.StatusBadRequest, "The application is not registered.", err)
	case errors.Is(err, wsfed.ErrUnknownReply):
		a.wsfedFail(w, r, http.StatusBadRequest, "The reply address is not registered for the application.", err)
	case errors.Is(err, errs.Invalid):
		a.wsfedFail(w, r, http.StatusBadRequest, "The sign-in request is not valid. Please return to the application.", err)
	default:
		a.unavailable(w, r, err)
	}
}

// getOnly は GET だけを通す（ServeMux の GET のパターンは HEAD にも合うため。HEAD でトークンを発行しない）。
func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (a *App) wsfedPassive(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	req, err := wsfed.ParseRequest(r.URL.Query())
	if err != nil {
		a.wsfedRejected(w, r, err)
		return
	}
	if req.Action == wsfed.ActionSignOut {
		a.wsfedSignOut(w, r, req)
		return
	}
	ctx := r.Context()
	rp, reply, err := a.wsfed.Lookup(ctx, a.realm.ID, req.Realm, req.Reply)
	if err != nil {
		a.wsfedRejected(w, r, err)
		return
	}
	now := a.deps.Clock.Now()
	p := wsfed.NewPending(a.realm.ID, rp, reply, req, now)
	if au, ok := authFrom(ctx); ok && au.PrincipalType == port.PrincipalUser && p.Fresh(au.AuthenticatedAt, now) {
		a.wsfedComplete(w, r, rp, p, au)
		return
	}
	rid, err := a.wsfed.Hold(ctx, p)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	http.Redirect(w, r, a.wsfedLoginURL(rid), http.StatusFound)
}

// wsfedLoginURL はログイン画面の URL。ログインの後で ResumePath に戻る。
func (a *App) wsfedLoginURL(rid string) string {
	return a.base + "/login?" + url.Values{"return_to": {a.base + wsfed.ResumePath + "?" + url.Values{"request": {rid}}.Encode()}}.Encode()
}

func (a *App) wsfedResume(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	ctx := r.Context()
	rid := r.URL.Query().Get("request")
	p, err := a.wsfed.Resume(ctx, a.realm.ID, rid)
	if errors.Is(err, wsfed.ErrRequestExpired) {
		a.wsfedFail(w, r, http.StatusBadRequest, "The sign-in request has expired. Please return to the application and try again.", err)
		return
	}
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	au, ok := authFrom(ctx)
	if !ok || au.PrincipalType != port.PrincipalUser || !p.Fresh(au.AuthenticatedAt, a.deps.Clock.Now()) {
		http.Redirect(w, r, a.wsfedLoginURL(rid), http.StatusFound)
		return
	}
	// 待つ間に RP の登録（wtrealm と wreply）が変わっていないかを確かめ直す。
	rp, _, err := a.wsfed.Lookup(ctx, a.realm.ID, p.Realm, p.Reply)
	if err == nil && rp.ID != p.RPID {
		err = wsfed.ErrUnknownRealm
	}
	if err != nil {
		a.wsfedRejected(w, r, err)
		return
	}
	if a.wsfedComplete(w, r, rp, p, au) {
		if err := a.wsfed.Drop(ctx, rid); err != nil {
			a.deps.Logger.WarnContext(ctx, "wsfed: drop request", "error", err)
		}
	}
}

// wsfedComplete はトークンを発行し、RP の wreply へ自動で POST する画面を返す。発行したら true。
func (a *App) wsfedComplete(w http.ResponseWriter, r *http.Request, rp port.WSFedRelyingParty, p wsfed.Pending, au auth) bool {
	ctx := r.Context()
	// active な Org が使えない（停止・有効期間の外など）セッションでは連携先に入れない（4.7。OIDC と同じ）。
	if len(au.OrgUnavailable) > 0 {
		a.wsfedFail(w, r, http.StatusForbidden, "You cannot sign in to the application with the current organization.", errors.New("org unavailable"))
		return false
	}
	out, err := a.wsfed.Issue(ctx, a.realm.ID, rp, p.Reply, p.Context, wsfed.Subject{UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID,
		AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods}, requestID(ctx))
	if err != nil {
		a.unavailable(w, r, err)
		return false
	}
	u, err := url.Parse(out.Reply)
	if err != nil {
		a.unavailable(w, r, err)
		return false
	}
	var buf bytes.Buffer
	if err := wsfedFormTmpl.Execute(&buf, wsfedForm{Base: a.base, Action: out.Reply, Result: out.Result, Context: out.Context}); err != nil {
		a.unavailable(w, r, err)
		return false
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action "+u.Scheme+"://"+u.Host+
		"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
	return true
}

type wsfedForm struct{ Base, Action, Result, Context string }

// wsfedFormTmpl は wreply へ自動で POST する画面（スクリプトが無効なら送信のボタン）。
var wsfedFormTmpl = template.Must(template.New("wsfed").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Signing in</title>
<link rel="stylesheet" href="{{.Base}}/login/assets/login.css">
<script src="{{.Base}}/login/assets/wsfed.js"></script>
</head>
<body>
<main>
<form id="wsfed" method="post" action="{{.Action}}">
<input type="hidden" name="wa" value="wsignin1.0">
<input type="hidden" name="wresult" value="{{.Result}}">
{{if .Context}}<input type="hidden" name="wctx" value="{{.Context}}">{{end}}
<noscript><p>Script is disabled. Press the button to continue.</p><button type="submit">Continue</button></noscript>
</form>
</main>
</body>
</html>
`))

// wsfedSignOut は wsignout1.0。wtrealm が登録にあり、wreply が無いか登録と完全一致のときだけ、確かめずにブラウザの
// セッションを失効させて wreply に戻す（POST /v1/logout と同じ。ADR 0110）。
func (a *App) wsfedSignOut(w http.ResponseWriter, r *http.Request, req wsfed.Request) {
	ctx := r.Context()
	rp, _, err := a.wsfed.Lookup(ctx, a.realm.ID, req.Realm, "")
	if err != nil {
		a.wsfedRejected(w, r, err)
		return
	}
	var reply string
	if req.Reply != "" {
		if reply, err = wsfed.ReplyFor(rp, req.Reply); err != nil {
			a.wsfedRejected(w, r, err)
			return
		}
	}
	if au, ok := authFrom(ctx); ok {
		err := a.sessions.Revoke(ctx, a.realm.ID, au.SessionID, au.PrincipalID, session.ReasonLogout, au.Actor(), requestID(ctx))
		if err != nil && !errors.Is(err, errs.NotFound) {
			a.unavailable(w, r, err)
			return
		}
		if err == nil {
			if err := a.wsfed.SignedOut(ctx, a.realm.ID, rp, au.PublicID, au.SID, requestID(ctx)); err != nil {
				a.deps.Logger.WarnContext(ctx, "wsfed: audit sign-out", "error", err)
			}
		}
	}
	http.SetCookie(w, a.clearSessionCookie())
	if reply != "" {
		http.Redirect(w, r, reply, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("You are signed out.\n"))
}

func (a *App) wsfedMetadata(w http.ResponseWriter, r *http.Request) {
	b, err := a.wsfed.Metadata(r.Context(), a.realm.ID)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/samlmetadata+xml")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// 管理 API（/v1/admin/wsfed/relying-parties。権限 clients:manage）。

func wsfedOut(rp port.WSFedRelyingParty) (adminapi.WSFedRelyingParty, error) {
	cs, err := wsfed.Claims(rp)
	if err != nil {
		return adminapi.WSFedRelyingParty{}, err
	}
	out := adminapi.WSFedRelyingParty{Id: rp.ID, Realm: rp.Realm, Name: rp.Name, ReplyUrls: rp.ReplyURLs, TokenType: rp.TokenType,
		TokenLifetime: rp.TokenLifetime, SigningAlg: rp.SigningAlg, Claims: []adminapi.WSFedClaim{}, CreatedAt: rp.CreatedAt, UpdatedAt: rp.UpdatedAt}
	if out.ReplyUrls == nil {
		out.ReplyUrls = []string{}
	}
	for _, c := range cs {
		out.Claims = append(out.Claims, adminapi.WSFedClaim{Source: c.Source, Type: c.Type})
	}
	return out, nil
}

func wsfedIn(b *adminapi.WSFedRelyingPartyInput) wsfed.Input {
	in := wsfed.Input{Realm: b.Realm, Name: b.Name, ReplyURLs: b.ReplyUrls}
	if b.TokenType != nil {
		in.TokenType = string(*b.TokenType)
	}
	if b.SigningAlg != nil {
		in.SigningAlg = string(*b.SigningAlg)
	}
	if b.TokenLifetime != nil {
		in.TokenLifetime = *b.TokenLifetime
		if in.TokenLifetime == 0 {
			// 0 を明示したら既定（0）と区別できないので、範囲の外として拒む。
			in.TokenLifetime = -1
		}
	}
	if b.Claims != nil {
		in.Claims = []wsfed.Claim{}
		for _, c := range *b.Claims {
			in.Claims = append(in.Claims, wsfed.Claim{Source: c.Source, Type: c.Type})
		}
	}
	return in
}

// wsfedOp は clients:manage を確かめ、フィーチャーが動いていれば fn を1つのトランザクションで実行する。成功なら status は 200。
// 入力の誤りは 400 にし、メッセージを返す。
func (s adminServer) wsfedOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermClientsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.wsfed == nil {
		return failed(http.StatusNotFound, "wsfed_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_relying_party"), e.Msg)}, nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListWSFedRelyingParties(ctx context.Context, _ adminapi.ListWSFedRelyingPartiesRequestObject) (adminapi.ListWSFedRelyingPartiesResponseObject, error) {
	out := adminapi.WSFedRelyingParties{RelyingParties: []adminapi.WSFedRelyingParty{}}
	o, err := s.wsfedOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		rps, err := tx.WSFed().ListRelyingParties(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, rp := range rps {
			v, err := wsfedOut(rp)
			if err != nil {
				return err
			}
			out.RelyingParties = append(out.RelyingParties, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListWSFedRelyingParties200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListWSFedRelyingParties401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListWSFedRelyingParties403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListWSFedRelyingParties404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateWSFedRelyingParty(ctx context.Context, req adminapi.CreateWSFedRelyingPartyRequestObject) (adminapi.CreateWSFedRelyingPartyResponseObject, error) {
	var out adminapi.WSFedRelyingParty
	o, err := s.wsfedOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_relying_party", "body is required")
		}
		rp, err := s.a.wsfed.Create(ctx, tx, s.a.realm.ID, wsfedIn(req.Body), p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = wsfedOut(rp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateWSFedRelyingParty201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateWSFedRelyingParty400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateWSFedRelyingParty401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateWSFedRelyingParty403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateWSFedRelyingParty404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateWSFedRelyingParty409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetWSFedRelyingParty(ctx context.Context, req adminapi.GetWSFedRelyingPartyRequestObject) (adminapi.GetWSFedRelyingPartyResponseObject, error) {
	var out adminapi.WSFedRelyingParty
	o, err := s.wsfedOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		rp, err := tx.WSFed().GetRelyingParty(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		out, err = wsfedOut(rp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetWSFedRelyingParty200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetWSFedRelyingParty401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetWSFedRelyingParty403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetWSFedRelyingParty404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateWSFedRelyingParty(ctx context.Context, req adminapi.UpdateWSFedRelyingPartyRequestObject) (adminapi.UpdateWSFedRelyingPartyResponseObject, error) {
	var out adminapi.WSFedRelyingParty
	o, err := s.wsfedOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_relying_party", "body is required")
		}
		rp, err := tx.WSFed().GetRelyingParty(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if rp, err = s.a.wsfed.Update(ctx, tx, rp, wsfedIn(req.Body), p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out, err = wsfedOut(rp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateWSFedRelyingParty200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateWSFedRelyingParty400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateWSFedRelyingParty401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateWSFedRelyingParty403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateWSFedRelyingParty404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateWSFedRelyingParty409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteWSFedRelyingParty(ctx context.Context, req adminapi.DeleteWSFedRelyingPartyRequestObject) (adminapi.DeleteWSFedRelyingPartyResponseObject, error) {
	o, err := s.wsfedOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		rp, err := tx.WSFed().GetRelyingParty(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.wsfed.Delete(ctx, tx, rp, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteWSFedRelyingParty204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteWSFedRelyingParty401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteWSFedRelyingParty403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteWSFedRelyingParty404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
