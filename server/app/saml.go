package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 外部 IdP としての SAML 2.0（ADR 0098）。フィーチャー saml。Org 専用の connection には org_managed_users も要る。

// samlCookie は SAML のフロー ID を要求したブラウザにだけ渡す Cookie。ACS は IdP からの POST（別サイト）で届くが、
// 完了の API はホスト型の画面（同じオリジン）から呼ぶので Lax で届く。
const samlCookie = "__Host-iam_saml"

func (s publicServer) setSAMLCookie(ctx context.Context, st saml.Started) {
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: s.a.cookie(samlCookie), Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
}

func (s publicServer) clearSAMLCookie(ctx context.Context) {
	setCookie(ctx, &http.Cookie{Name: s.a.cookie(samlCookie), Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (s publicServer) samlComplete(ctx context.Context, flowID *string, relayState, response string) saml.Complete {
	c := s.a.clientOf(ctx)
	in := saml.Complete{FlowID: deref(flowID), RelayState: relayState, SAMLResponse: response,
		Client: oauth.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, s.a.cookie(samlCookie))
	}
	return in
}

func (s publicServer) StartSAMLLogin(ctx context.Context, req publicapi.StartSAMLLoginRequestObject) (publicapi.StartSAMLLoginResponseObject, error) {
	if s.a.saml == nil {
		return publicapi.StartSAMLLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	st, err := s.a.saml.Start(ctx, s.a.realm.ID, req.Connection)
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.StartSAMLLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case err != nil:
		return nil, err
	}
	s.setSAMLCookie(ctx, st)
	return publicapi.StartSAMLLogin200JSONResponse{FlowId: st.FlowID, RedirectUrl: st.RedirectURL, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) CompleteSAMLLogin(ctx context.Context, req publicapi.CompleteSAMLLoginRequestObject) (publicapi.CompleteSAMLLoginResponseObject, error) {
	fail := publicapi.CompleteSAMLLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if s.a.saml == nil {
		return publicapi.CompleteSAMLLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return fail, nil
	}
	in := s.samlComplete(ctx, req.Body.FlowId, req.Body.RelayState, req.Body.SamlResponse)
	if tok, viaCookie := s.a.sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	res, err := s.a.saml.Complete(ctx, s.a.realm.ID, in)
	// 失敗でもフローは使い終わったので Cookie を消す。
	s.clearSAMLCookie(ctx)
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.CompleteSAMLLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	// コードつきのものを先に比べる（OAuth と同じ）。
	case errors.Is(err, oauth.ErrSSODomainNotVerified):
		return publicapi.CompleteSAMLLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, oauth.ErrQuotaExceeded):
		return publicapi.CompleteSAMLLogin409JSONResponse(conflictOf(err, errs.CodeQuotaExceeded)), nil
	case errors.Is(err, oauth.ErrAccountExists):
		return publicapi.CompleteSAMLLogin409JSONResponse{Error: "account_exists"}, nil
	case errors.Is(err, oauth.ErrEmailUnverified):
		return publicapi.CompleteSAMLLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "email_unverified"}}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CompleteSAMLLogin200JSONResponse(s.loginResult(ctx, res.Session, res.UserID, res.Created, req.Body.ReturnToken)), nil
}

func (s publicServer) StartLinkSAMLIdentity(ctx context.Context, req publicapi.StartLinkSAMLIdentityRequestObject) (publicapi.StartLinkSAMLIdentityResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartLinkSAMLIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.stale(ctx, au) {
		return publicapi.StartLinkSAMLIdentity401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.saml == nil {
		return publicapi.StartLinkSAMLIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	st, err := s.a.saml.StartLink(ctx, s.a.realm.ID, req.Connection, au.PrincipalID)
	switch {
	case errors.Is(err, oauth.ErrNotManagedByOwner):
		return publicapi.StartLinkSAMLIdentity409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.NotFound):
		return publicapi.StartLinkSAMLIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case err != nil:
		return nil, err
	}
	s.setSAMLCookie(ctx, st)
	return publicapi.StartLinkSAMLIdentity200JSONResponse{FlowId: st.FlowID, RedirectUrl: st.RedirectURL, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) CompleteLinkSAMLIdentity(ctx context.Context, req publicapi.CompleteLinkSAMLIdentityRequestObject) (publicapi.CompleteLinkSAMLIdentityResponseObject, error) {
	fail := publicapi.CompleteLinkSAMLIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if s.stale(ctx, au) {
		return publicapi.CompleteLinkSAMLIdentity401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.saml == nil {
		return publicapi.CompleteLinkSAMLIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	in := s.samlComplete(ctx, req.Body.FlowId, req.Body.RelayState, req.Body.SamlResponse)
	ident, err := s.a.saml.CompleteLink(ctx, s.a.realm.ID, au.PrincipalID, in)
	s.clearSAMLCookie(ctx)
	switch {
	case errors.Is(err, oauth.ErrIdentityExists), errors.Is(err, oauth.ErrNotManagedByOwner):
		return publicapi.CompleteLinkSAMLIdentity409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	var slug string
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		conn, err := tx.Connections().Get(ctx, s.a.realm.ID, ident.ConnectionID)
		slug = conn.Slug
		return err
	})
	if err != nil {
		return nil, err
	}
	return publicapi.CompleteLinkSAMLIdentity200JSONResponse{Id: ident.PublicID, Connection: slug, CreatedAt: ident.CreatedAt}, nil
}

func samlInput(b publicapi.SAMLConnectionInput) saml.ConnectionInput {
	return saml.ConnectionInput{MetadataXML: []byte(deref(b.MetadataXml)), MetadataURL: deref(b.MetadataUrl), EntityID: deref(b.EntityId),
		SignRequests: b.SignRequests != nil && *b.SignRequests, NameIDFormat: deref(b.NameIdFormat), EmailAttribute: deref(b.EmailAttribute)}
}

// AddOrgSAMLConnection は Org の SAML の connection を登録する。メタデータの取得（外部への問い合わせ）はトランザクションの外で行う。
func (s publicServer) AddOrgSAMLConnection(ctx context.Context, req publicapi.AddOrgSAMLConnectionRequestObject) (publicapi.AddOrgSAMLConnectionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.AddOrgSAMLConnection401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() || s.a.saml == nil {
		return publicapi.AddOrgSAMLConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.AddOrgSAMLConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	// 権限と個人 Org を先に確かめ、メタデータの取得はトランザクションの外で行い、置くときにもう一度確かめる。
	member := func(ctx context.Context, tx port.Tx) (port.Org, error) {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err == nil && o.Kind == port.OrgPersonal {
			err = org.ErrPersonalOrg
		}
		return o, err
	}
	var o port.Org
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		o, err = member(ctx, tx)
		return err
	})
	var c port.Connection
	if err == nil {
		c, err = s.a.saml.NewConnection(ctx, s.a.realm.ID, "", o.ID, samlInput(*req.Body))
	}
	var out publicapi.OrgConnection
	if err == nil {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			o, err := member(ctx, tx)
			if err != nil {
				return err
			}
			if err := s.a.orgs.AddConnection(ctx, tx, o, c, oauth.MaxOrgConnections, au.Actor(), requestID(ctx)); err != nil {
				return err
			}
			out, err = orgConnectionOut(c)
			return err
		})
	}
	if c, ok := stateCode(err); ok {
		return publicapi.AddOrgSAMLConnection409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.AddOrgSAMLConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.AddOrgSAMLConnection403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.AddOrgSAMLConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCodeOr(err, "invalid_connection")}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.AddOrgSAMLConnection201JSONResponse(out), nil
}

func (s adminServer) CreateSAMLConnection(ctx context.Context, req adminapi.CreateSAMLConnectionRequestObject) (adminapi.CreateSAMLConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateSAMLConnection401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateSAMLConnection403JSONResponse(d.Body), nil
	}
	if s.a.saml == nil {
		return adminapi.CreateSAMLConnection404JSONResponse(adminError("saml_disabled", "")), nil
	}
	bad := func(code, msg string) adminapi.CreateSAMLConnectionResponseObject {
		return adminapi.CreateSAMLConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(code, msg))}
	}
	if req.Body == nil {
		return bad("invalid_connection", "body is required"), nil
	}
	b := req.Body
	if !slugPattern.MatchString(b.Slug) {
		return bad("invalid_connection", "slug must match "+slugPattern.String()), nil
	}
	c, err := s.a.saml.NewConnection(ctx, s.a.realm.ID, b.Slug, "", saml.ConnectionInput{
		MetadataXML: []byte(deref(b.MetadataXml)), MetadataURL: deref(b.MetadataUrl), EntityID: deref(b.EntityId),
		SignRequests: b.SignRequests != nil && *b.SignRequests, NameIDFormat: deref(b.NameIdFormat), EmailAttribute: deref(b.EmailAttribute),
		TrustEmail: b.TrustEmail != nil && *b.TrustEmail,
	})
	if errors.Is(err, errs.Invalid) {
		var e *errs.Error
		errors.As(err, &e)
		return bad(errCodeOr(err, "invalid_connection"), e.Msg), nil
	}
	if err != nil {
		return nil, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Connections().Create(ctx, c); err != nil {
			return err
		}
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "connection.created", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "type": saml.Type},
		})
		return err
	})
	if errors.Is(err, errs.Conflict) {
		return adminapi.CreateSAMLConnection409JSONResponse(adminError("slug_exists", "")), nil
	}
	if err != nil {
		return nil, err
	}
	info, err := saml.InfoOf(c)
	if err != nil {
		return nil, err
	}
	return adminapi.CreateSAMLConnection201JSONResponse{Id: c.ID, Slug: c.Slug, IdpEntityId: info.IdPEntityID, SpEntityId: info.SPEntityID,
		AcsUrl: info.ACSURL}, nil
}

// connectionUsable は、connection を今のフィーチャーの構成で使えるかを返す（ホスト型の画面とホームレルム発見に出すもの）。
func (a *App) connectionUsable(c port.Connection) bool {
	return c.Type != saml.Type || a.saml != nil
}

// serveSAMLMetadata は SP のメタデータを返す（ホスト型の画面のパス。IdP に登録する）。
func (h *hosted) serveSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.TrimPrefix(r.URL.Path, saml.MetadataPath)
	if h.a.saml == nil || slug == "" || strings.Contains(slug, "/") {
		http.NotFound(w, r)
		return
	}
	b, err := h.a.saml.Metadata(r.Context(), h.a.realm.ID, slug)
	if errors.Is(err, errs.NotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.a.deps.Logger.ErrorContext(r.Context(), "saml metadata", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b) // #nosec G705 -- サーバーが組み立てた XML（etree で値を書き出す）を XML の型で返す
}

// maxACSBody は ACS に POST される本文の上限（SAMLResponse は base64 で 256 KiB の XML まで）。
const maxACSBody = 512 << 10

// samlACS は IdP からの POST（HTTP-POST バインディング）を受け、応答を完了の API に渡す画面を返す。ここでは何も確かめず、
// 状態も変えない（別サイトからの POST なので、CSRF の対策の外に置く。確かめるのは完了の API で、フローの Cookie と RelayState に結び付ける）。
func (h *hosted) samlACS(w http.ResponseWriter, r *http.Request) (pageData, bool) {
	if h.a.saml == nil {
		http.NotFound(w, r)
		return pageData{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxACSBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return pageData{}, false
	}
	return pageData{SAMLResponse: r.PostForm.Get("SAMLResponse"), RelayState: r.PostForm.Get("RelayState")}, true
}
