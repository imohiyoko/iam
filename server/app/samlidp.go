package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// SAML 2.0 の IdP（iam が IdP。フィーチャー saml_idp。ADR 0115）。
//
//	GET  /saml/idp/sso          AuthnRequest（HTTP-Redirect）
//	POST /saml/idp/sso          AuthnRequest（HTTP-POST。確かめて預け、GET の /saml/idp/sso/resume へ 303 で回す）
//	GET  /saml/idp/sso/resume   ログイン画面（か HTTP-POST の要求）から戻って Response を渡す
//	GET  /saml/idp/init         IdP-initiated（?sp=<Entity ID>&RelayState=。SP ごとに許したときだけ）
//	GET  /saml/idp/slo          LogoutRequest（HTTP-Redirect）
//	POST /saml/idp/slo          LogoutRequest（HTTP-POST。確かめて預け、GET の /saml/idp/slo/resume へ 303 で回す）
//	GET  /saml/idp/slo/resume   預けた LogoutRequest をブラウザのセッションで処理する
//	GET  /saml/idp/metadata     メタデータ
//
// 別のオリジンの SP からのトップレベルの遷移（GET と自動の POST）で届くので、CrossOriginProtection の外に置く。セッションの Cookie は
// SameSite=Lax なので別のサイトからの POST には付かない。POST は確かめて預けるだけにし、セッションを見る処理は同じオリジンへの GET で行う。
// 知らない SP・登録に無い ACS・確かめられない署名は SP に戻さずに 400 の画面にする（fail closed）。

// isSAMLIdP は SAML の IdP のパスかを返す。
func isSAMLIdP(path string) bool {
	switch path {
	case samlidp.SSOPath, samlidp.ResumePath, samlidp.InitPath, samlidp.SLOPath, samlidp.SLOResumePath, samlidp.MetadataPath:
		return true
	}
	return false
}

// maxSAMLForm は HTTP-POST のフォームの大きさの上限。
const maxSAMLForm = 256 << 10

// newSAMLIdPHandler は SAML の IdP のハンドラ。フィーチャーが動いていなければ nil。
func newSAMLIdPHandler(a *App) http.Handler {
	if a.samlIdP == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("GET "+samlidp.SSOPath, a.withSession(http.HandlerFunc(a.samlIdPRedirect)))
	mux.HandleFunc("POST "+samlidp.SSOPath, a.samlIdPPost)
	mux.Handle("GET "+samlidp.ResumePath, a.withSession(http.HandlerFunc(a.samlIdPResume)))
	mux.Handle("GET "+samlidp.InitPath, a.withSession(http.HandlerFunc(a.samlIdPInit)))
	mux.Handle("GET "+samlidp.SLOPath, a.withSession(http.HandlerFunc(a.samlIdPLogoutRedirect)))
	mux.HandleFunc("POST "+samlidp.SLOPath, a.samlIdPLogoutPost)
	mux.Handle("GET "+samlidp.SLOResumePath, a.withSession(http.HandlerFunc(a.samlIdPLogoutResume)))
	mux.HandleFunc("GET "+samlidp.MetadataPath, a.samlIdPMetadata)
	return mux
}

// samlIdPFail は要求の誤りを画面で返す（SP には戻さない）。理由はログにだけ出す。
func (a *App) samlIdPFail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	a.deps.Logger.InfoContext(r.Context(), "saml idp: request rejected", "path", r.URL.Path, "error", err)
	http.Error(w, msg, status)
}

// samlIdPRejected は解析・SP の決定・署名の誤りを 400 にする。依存先の障害は 503。
func (a *App) samlIdPRejected(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, samlidp.ErrUnknownSP):
		a.samlIdPFail(w, r, http.StatusBadRequest, "The application is not registered.", err)
	case errors.Is(err, samlidp.ErrUnknownACS):
		a.samlIdPFail(w, r, http.StatusBadRequest, "The reply address is not registered for the application.", err)
	case errors.Is(err, samlidp.ErrRequestExpired):
		a.samlIdPFail(w, r, http.StatusBadRequest, "The sign-in request has expired. Please return to the application and try again.", err)
	case errors.Is(err, errs.Invalid):
		a.samlIdPFail(w, r, http.StatusBadRequest, "The sign-in request is not valid. Please return to the application.", err)
	default:
		a.unavailable(w, r, err)
	}
}

// samlForm はフォームの値を 1 つだけ読む（2 つ以上あれば空）。
func samlForm(w http.ResponseWriter, r *http.Request) (msg, relay string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLForm)
	if err := r.ParseForm(); err != nil {
		return "", "", false
	}
	if len(r.PostForm["SAMLRequest"]) != 1 || len(r.PostForm["RelayState"]) > 1 {
		return "", "", false
	}
	return r.PostForm.Get("SAMLRequest"), r.PostForm.Get("RelayState"), true
}

func (a *App) samlIdPRedirect(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	m, err := samlidp.DecodeRedirect(r.URL.RawQuery, "SAMLRequest")
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPRequest(w, r, m, false)
}

func (a *App) samlIdPPost(w http.ResponseWriter, r *http.Request) {
	enc, relay, ok := samlForm(w, r)
	if !ok {
		a.samlIdPRejected(w, r, samlidp.ErrBadMessage)
		return
	}
	m, err := samlidp.DecodePOST(enc, relay)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPRequest(w, r, m, true)
}

// samlIdPRequest は AuthnRequest を確かめる。post（HTTP-POST）なら、セッションの Cookie が届かないので預けて GET で戻る。
func (a *App) samlIdPRequest(w http.ResponseWriter, r *http.Request, m samlidp.Message, post bool) {
	ctx := r.Context()
	sp, _, req, err := a.samlIdP.ParseAuthnRequest(ctx, a.realm.ID, m)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	p := samlidp.NewPending(a.realm.ID, sp, req, m.RelayState, a.deps.Clock.Now())
	if req.Status != nil {
		// SP と ACS は確かめた。応えられない要求は ACS へ失敗の Response で返す。
		a.samlIdPError(w, r, "", p, req.Status)
		return
	}
	if post {
		rid, err := a.samlIdP.Hold(ctx, p)
		if err != nil {
			a.unavailable(w, r, err)
			return
		}
		http.Redirect(w, r, a.samlIdPResumeURL(rid), http.StatusSeeOther)
		return
	}
	a.samlIdPDecide(w, r, "", p)
}

func (a *App) samlIdPResumeURL(rid string) string {
	return a.base + samlidp.ResumePath + "?" + url.Values{"request": {rid}}.Encode()
}

func (a *App) samlIdPResume(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	ctx := r.Context()
	rid := r.URL.Query().Get("request")
	p, err := a.samlIdP.Resume(ctx, a.realm.ID, rid)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPDecide(w, r, rid, p)
}

func (a *App) samlIdPInit(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	q := r.URL.Query()
	if len(q["sp"]) != 1 || len(q["RelayState"]) > 1 {
		a.samlIdPRejected(w, r, samlidp.ErrBadMessage)
		return
	}
	_, p, err := a.samlIdP.NewIdPInitiated(r.Context(), a.realm.ID, q.Get("sp"), q.Get("RelayState"))
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPDecide(w, r, "", p)
}

// samlIdPDecide は、セッションが要求（ForceAuthn・RequestedAuthnContext）を満たせば Response を渡し、満たさなければログイン画面に回す。
// IsPassive ならログイン画面に回さずに NoPassive を返す。ログイン画面から戻ってもまだ要求の acr に届かなければ NoAuthnContext。
// rid は預けた要求の ID（まだ預けていなければ空）。
func (a *App) samlIdPDecide(w http.ResponseWriter, r *http.Request, rid string, p samlidp.Pending) {
	ctx := r.Context()
	// 待つ間に SP の登録（Entity ID・ACS・IdP-initiated の許可）が変わっていないかを確かめる。
	sp, cfg, err := a.samlIdP.Recheck(ctx, p)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	au, ok := authFrom(ctx)
	loggedIn := ok && au.PrincipalType == port.PrincipalUser
	if loggedIn && p.Fresh(au.AuthenticatedAt) {
		// active な Org が使えない（停止・有効期間の外など）セッションでは連携先に入れない（4.7。OIDC と同じ）。
		if len(au.OrgUnavailable) > 0 {
			a.samlIdPError(w, r, rid, p, &samlidp.StatusError{Code: samlidp.StatusResponder, Sub: samlidp.StatusRequestDenied,
				Msg: "the current organization cannot be used"})
			return
		}
		if ref, ok := a.samlIdP.SelectClassRef(p.ClassRefs, au.AuthMethods); ok {
			a.samlIdPIssue(w, r, rid, sp, cfg, p, au, ref)
			return
		}
		if p.LoginStarted || p.IsPassive {
			a.samlIdPError(w, r, rid, p, &samlidp.StatusError{Code: samlidp.StatusResponder, Sub: samlidp.StatusNoAuthnContext,
				Msg: "the requested authentication context could not be met"})
			return
		}
		// step-up：要求の acr に届くよう、ここから後のログインを求める（ADR 0093 と同じ）。
		now := a.deps.Clock.Now()
		p.LoginAfter = &now
	}
	if p.IsPassive {
		a.samlIdPError(w, r, rid, p, &samlidp.StatusError{Code: samlidp.StatusResponder, Sub: samlidp.StatusNoPassive,
			Msg: "the user must sign in"})
		return
	}
	p.LoginStarted = true
	if rid == "" {
		if rid, err = a.samlIdP.Hold(ctx, p); err != nil {
			a.unavailable(w, r, err)
			return
		}
	} else if err := a.samlIdP.Save(ctx, rid, p); err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	http.Redirect(w, r, a.base+"/login?"+url.Values{"return_to": {a.samlIdPResumeURL(rid)}}.Encode(), http.StatusFound)
}

// samlIdPIssue は Assertion を入れた Response を発行し、ACS へ自動で POST する画面を返す。
func (a *App) samlIdPIssue(w http.ResponseWriter, r *http.Request, rid string, sp port.SAMLServiceProvider, cfg samlidp.Config, p samlidp.Pending, au auth, ref string) {
	ctx := r.Context()
	out, err := a.samlIdP.Issue(ctx, sp, cfg, p, samlidp.Subject{UserID: au.PrincipalID, OrgID: au.ActiveOrgID, SID: au.SID,
		AuthTime: au.AuthenticatedAt, AMR: au.AuthMethods}, ref, requestID(ctx))
	if st, ok := samlidp.ErrorFor(err); ok {
		a.samlIdPError(w, r, rid, p, st)
		return
	}
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	a.samlIdPDrop(ctx, rid)
	a.samlIdPForm(w, r, out.ACS, "SAMLResponse", out.SAMLResponse, out.RelayState)
}

// samlIdPError は失敗の Response を ACS へ返す（SP と ACS を確かめた後だけ）。
func (a *App) samlIdPError(w http.ResponseWriter, r *http.Request, rid string, p samlidp.Pending, st *samlidp.StatusError) {
	ctx := r.Context()
	a.deps.Logger.InfoContext(ctx, "saml idp: error response", "entity_id", p.EntityID, "status", st.Sub, "reason", st.Msg)
	out, err := a.samlIdP.IssueError(ctx, p, st)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	a.samlIdPDrop(ctx, rid)
	a.samlIdPForm(w, r, out.ACS, "SAMLResponse", out.SAMLResponse, out.RelayState)
}

func (a *App) samlIdPDrop(ctx context.Context, rid string) {
	if rid == "" {
		return
	}
	if err := a.samlIdP.Drop(ctx, rid); err != nil {
		a.deps.Logger.WarnContext(ctx, "saml idp: drop request", "error", err)
	}
}

type samlIdPFormData struct{ Base, Action, Name, Value, RelayState string }

// samlIdPFormTmpl は SP へ自動で POST する画面（スクリプトが無効なら送信のボタン）。
var samlIdPFormTmpl = template.Must(template.New("samlidp").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Signing in</title>
<link rel="stylesheet" href="{{.Base}}/login/assets/login.css">
<script src="{{.Base}}/login/assets/samlidp.js"></script>
</head>
<body>
<main>
<form id="samlidp" method="post" action="{{.Action}}">
<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}">{{end}}
<noscript><p>Script is disabled. Press the button to continue.</p><button type="submit">Continue</button></noscript>
</form>
</main>
</body>
</html>
`))

// samlIdPForm は action へ name=value を自動で POST する画面を返す。CSP の form-action は action のオリジンだけ。
func (a *App) samlIdPForm(w http.ResponseWriter, r *http.Request, action, name, value, relay string) {
	u, err := url.Parse(action)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	var buf bytes.Buffer
	if err := samlIdPFormTmpl.Execute(&buf, samlIdPFormData{Base: a.base, Action: action, Name: name, Value: value, RelayState: relay}); err != nil {
		a.unavailable(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action "+u.Scheme+"://"+u.Host+
		"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func (a *App) samlIdPLogoutRedirect(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	m, err := samlidp.DecodeRedirect(r.URL.RawQuery, "SAMLRequest")
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	lp, err := a.samlIdP.ParseLogoutRequest(r.Context(), a.realm.ID, m)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPLogout(w, r, lp)
}

func (a *App) samlIdPLogoutPost(w http.ResponseWriter, r *http.Request) {
	enc, relay, ok := samlForm(w, r)
	if !ok {
		a.samlIdPRejected(w, r, samlidp.ErrBadMessage)
		return
	}
	m, err := samlidp.DecodePOST(enc, relay)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	ctx := r.Context()
	lp, err := a.samlIdP.ParseLogoutRequest(ctx, a.realm.ID, m)
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	rid, err := a.samlIdP.HoldLogout(ctx, lp)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	http.Redirect(w, r, a.base+samlidp.SLOResumePath+"?"+url.Values{"request": {rid}}.Encode(), http.StatusSeeOther)
}

func (a *App) samlIdPLogoutResume(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	lp, err := a.samlIdP.TakeLogout(r.Context(), a.realm.ID, r.URL.Query().Get("request"))
	if err != nil {
		a.samlIdPRejected(w, r, err)
		return
	}
	a.samlIdPLogout(w, r, lp)
}

// samlIdPLogout は、ブラウザのセッションが LogoutRequest の本人（NameID・SessionIndex）ならセッションを失効させ（POST /v1/logout と同じ。
// Back-Channel Logout も送る）、SP の SingleLogoutService へ LogoutResponse を返す。セッションが無ければ Success、別の本人なら
// セッションを残して Requester / UnknownPrincipal。
func (a *App) samlIdPLogout(w http.ResponseWriter, r *http.Request, lp samlidp.LogoutPending) {
	ctx := r.Context()
	var st *samlidp.StatusError
	if au, ok := authFrom(ctx); ok && au.PrincipalType == port.PrincipalUser {
		match, err := a.samlIdP.Matches(ctx, lp, au.PrincipalID, au.ActiveOrgID, au.SID)
		if err != nil {
			a.samlIdPRejected(w, r, err)
			return
		}
		if !match {
			st = &samlidp.StatusError{Code: samlidp.StatusRequester, Sub: samlidp.StatusUnknownPrincipal, Msg: "the session belongs to another principal"}
		} else {
			err := a.sessions.Revoke(ctx, a.realm.ID, au.SessionID, au.PrincipalID, session.ReasonLogout, au.Actor(), requestID(ctx))
			if err != nil && !errors.Is(err, errs.NotFound) {
				a.unavailable(w, r, err)
				return
			}
			if err == nil {
				if err := a.samlIdP.LoggedOut(ctx, lp, au.PublicID, au.SID, requestID(ctx)); err != nil {
					a.deps.Logger.WarnContext(ctx, "saml idp: audit logout", "error", err)
				}
			}
			http.SetCookie(w, a.clearSessionCookie())
		}
	}
	reply, err := a.samlIdP.LogoutResponse(ctx, lp, st)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	if reply.Binding == samlidp.BindingRedirect {
		http.Redirect(w, r, reply.URL, http.StatusFound)
		return
	}
	a.samlIdPForm(w, r, reply.Location, "SAMLResponse", reply.SAMLResponse, reply.RelayState)
}

func (a *App) samlIdPMetadata(w http.ResponseWriter, r *http.Request) {
	b, err := a.samlIdP.Metadata(r.Context(), a.realm.ID)
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/samlmetadata+xml")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// 管理 API（/v1/admin/saml/service-providers。権限 clients:manage）。

func samlEndpointsOut(es []samlidp.Endpoint, acs bool) []adminapi.SAMLEndpoint {
	out := []adminapi.SAMLEndpoint{}
	for _, e := range es {
		v := adminapi.SAMLEndpoint{Url: e.URL, Binding: &e.Binding}
		if acs {
			v.Index, v.Default = &e.Index, &e.Default
		}
		out = append(out, v)
	}
	return out
}

func samlIdPOut(sp port.SAMLServiceProvider) (adminapi.SAMLServiceProvider, error) {
	c, err := samlidp.ConfigOf(sp)
	if err != nil {
		return adminapi.SAMLServiceProvider{}, err
	}
	out := adminapi.SAMLServiceProvider{Id: sp.ID, EntityId: sp.EntityID, Name: sp.Name, Acs: samlEndpointsOut(c.ACS, true), Slo: samlEndpointsOut(c.SLO, false),
		SigningCertificates: []string{}, RequireSignedRequests: c.RequireSignedRequests, NameIdFormat: c.NameIDFormat, Attributes: []adminapi.SAMLAttribute{},
		SignAssertion: c.SignAssertion, SignResponse: c.SignResponse, AllowIdpInitiated: c.AllowIdPInitiated, AssertionLifetime: c.AssertionLifetime,
		CreatedAt: sp.CreatedAt, UpdatedAt: sp.UpdatedAt}
	for _, d := range c.SigningCerts {
		out.SigningCertificates = append(out.SigningCertificates, base64.StdEncoding.EncodeToString(d))
	}
	if len(c.EncryptionCert) > 0 {
		s := base64.StdEncoding.EncodeToString(c.EncryptionCert)
		out.EncryptionCertificate = &s
	}
	if c.NameIDSource != "" {
		out.NameIdSource = &c.NameIDSource
	}
	for _, at := range c.Attributes {
		v := adminapi.SAMLAttribute{Source: at.Source, Name: at.Name, NameFormat: &at.NameFormat}
		if at.FriendlyName != "" {
			v.FriendlyName = &at.FriendlyName
		}
		out.Attributes = append(out.Attributes, v)
	}
	return out, nil
}

// samlIdPIn は管理 API の入力を登録の内容にする。sign_assertion は省けば true。
func samlIdPIn(b *adminapi.SAMLServiceProviderInput) (samlidp.Input, error) {
	in := samlidp.Input{EntityID: b.EntityId, Name: b.Name}
	c := &in.Config
	for _, e := range b.Acs {
		c.ACS = append(c.ACS, samlidp.Endpoint{URL: e.Url, Binding: deref(e.Binding), Index: deref(e.Index), Default: deref(e.Default)})
	}
	for _, e := range deref(b.Slo) {
		c.SLO = append(c.SLO, samlidp.Endpoint{URL: e.Url, Binding: deref(e.Binding)})
	}
	for _, s := range deref(b.SigningCertificates) {
		der, err := samlidp.ParseCertificate(s)
		if err != nil {
			return samlidp.Input{}, err
		}
		c.SigningCerts = append(c.SigningCerts, der)
	}
	if b.EncryptionCertificate != nil {
		der, err := samlidp.ParseCertificate(*b.EncryptionCertificate)
		if err != nil {
			return samlidp.Input{}, err
		}
		c.EncryptionCert = der
	}
	c.RequireSignedRequests = deref(b.RequireSignedRequests)
	c.NameIDFormat, c.NameIDSource = deref(b.NameIdFormat), deref(b.NameIdSource)
	for _, at := range deref(b.Attributes) {
		c.Attributes = append(c.Attributes, samlidp.Attribute{Source: at.Source, Name: at.Name, NameFormat: deref(at.NameFormat), FriendlyName: deref(at.FriendlyName)})
	}
	c.SignAssertion = b.SignAssertion == nil || *b.SignAssertion
	c.SignResponse = deref(b.SignResponse)
	c.AllowIdPInitiated = deref(b.AllowIdpInitiated)
	if b.AssertionLifetime != nil {
		c.AssertionLifetime = *b.AssertionLifetime
		if c.AssertionLifetime == 0 {
			// 0 を明示したら既定（0）と区別できないので、範囲の外として拒む。
			c.AssertionLifetime = -1
		}
	}
	return in, nil
}

// samlIdPOp は clients:manage を確かめ、フィーチャーが動いていれば fn を1つのトランザクションで実行する。成功なら status は 200。
// 入力の誤りは 400 にし、メッセージを返す。
func (s adminServer) samlIdPOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermClientsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.samlIdP == nil {
		return failed(http.StatusNotFound, "saml_idp_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_service_provider"), e.Msg)}, nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListSAMLServiceProviders(ctx context.Context, _ adminapi.ListSAMLServiceProvidersRequestObject) (adminapi.ListSAMLServiceProvidersResponseObject, error) {
	out := adminapi.SAMLServiceProviders{ServiceProviders: []adminapi.SAMLServiceProvider{}}
	o, err := s.samlIdPOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		sps, err := tx.SAMLIdP().ListServiceProviders(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, sp := range sps {
			v, err := samlIdPOut(sp)
			if err != nil {
				return err
			}
			out.ServiceProviders = append(out.ServiceProviders, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListSAMLServiceProviders200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListSAMLServiceProviders401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListSAMLServiceProviders403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListSAMLServiceProviders404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateSAMLServiceProvider(ctx context.Context, req adminapi.CreateSAMLServiceProviderRequestObject) (adminapi.CreateSAMLServiceProviderResponseObject, error) {
	var out adminapi.SAMLServiceProvider
	o, err := s.samlIdPOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_service_provider", "body is required")
		}
		in, err := samlIdPIn(req.Body)
		if err != nil {
			return err
		}
		sp, err := s.a.samlIdP.Create(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = samlIdPOut(sp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateSAMLServiceProvider201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateSAMLServiceProvider400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateSAMLServiceProvider401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateSAMLServiceProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateSAMLServiceProvider404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateSAMLServiceProvider409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetSAMLServiceProvider(ctx context.Context, req adminapi.GetSAMLServiceProviderRequestObject) (adminapi.GetSAMLServiceProviderResponseObject, error) {
	var out adminapi.SAMLServiceProvider
	o, err := s.samlIdPOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		sp, err := tx.SAMLIdP().GetServiceProvider(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		out, err = samlIdPOut(sp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetSAMLServiceProvider200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetSAMLServiceProvider401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetSAMLServiceProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetSAMLServiceProvider404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateSAMLServiceProvider(ctx context.Context, req adminapi.UpdateSAMLServiceProviderRequestObject) (adminapi.UpdateSAMLServiceProviderResponseObject, error) {
	var out adminapi.SAMLServiceProvider
	o, err := s.samlIdPOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_service_provider", "body is required")
		}
		sp, err := tx.SAMLIdP().GetServiceProvider(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		in, err := samlIdPIn(req.Body)
		if err != nil {
			return err
		}
		if sp, err = s.a.samlIdP.Update(ctx, tx, sp, in, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out, err = samlIdPOut(sp)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateSAMLServiceProvider200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateSAMLServiceProvider400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateSAMLServiceProvider401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateSAMLServiceProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateSAMLServiceProvider404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateSAMLServiceProvider409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteSAMLServiceProvider(ctx context.Context, req adminapi.DeleteSAMLServiceProviderRequestObject) (adminapi.DeleteSAMLServiceProviderResponseObject, error) {
	o, err := s.samlIdPOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		sp, err := tx.SAMLIdP().GetServiceProvider(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.samlIdP.Delete(ctx, tx, sp, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteSAMLServiceProvider204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteSAMLServiceProvider401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteSAMLServiceProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteSAMLServiceProvider404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
