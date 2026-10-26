package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// 本人による認証手段の追加・削除（design.md 4.2、4.3）。

// stateCode は、本人に理由を返してよい拒否（状態が合わない・既に使われている）のコードを返す。
func stateCode(err error) (string, bool) {
	var e *errs.Error
	if errors.As(err, &e) && e.Code != "" && (e.Kind == errs.KindConflict || e.Kind == errs.KindFailedPrecondition) {
		return e.Code, true
	}
	return "", false
}

func notFound() publicapi.NotFoundJSONResponse {
	return publicapi.NotFoundJSONResponse{Error: "not_found"}
}

func (s publicServer) myEmail(ctx context.Context, tx port.Tx, e port.UserEmail) (publicapi.MyEmail, error) {
	out := publicapi.MyEmail{Id: e.PublicID, Primary: e.IsPrimary, Verified: e.VerifiedAt != nil, CreatedAt: e.CreatedAt}
	if via := string(e.VerifiedVia); via != "" {
		out.VerifiedVia = &via
	}
	if len(e.Ciphertext) > 0 {
		addr, err := s.a.accounts.EmailAddress(ctx, tx, e)
		if err != nil {
			return publicapi.MyEmail{}, err
		}
		out.Email = addr
	}
	return out, nil
}

func (s publicServer) ListMyMethods(ctx context.Context, _ publicapi.ListMyMethodsRequestObject) (publicapi.ListMyMethodsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyMethods401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	out := publicapi.ListMyMethods200JSONResponse{Emails: []publicapi.MyEmail{}, Identities: []publicapi.MyIdentity{}}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		m, err := s.a.accounts.ListMethods(ctx, tx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		for _, e := range m.Emails {
			me, err := s.myEmail(ctx, tx, e)
			if err != nil {
				return err
			}
			out.Emails = append(out.Emails, me)
		}
		slugs, err := connectionSlugs(ctx, tx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, i := range m.Identities {
			out.Identities = append(out.Identities, publicapi.MyIdentity{Id: i.PublicID, Connection: slugs[i.ConnectionID], CreatedAt: i.CreatedAt})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func connectionSlugs(ctx context.Context, tx port.Tx, realmID string) (map[string]string, error) {
	cs, err := tx.Connections().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(cs))
	for _, c := range cs {
		m[c.ID] = c.Slug
	}
	return m, nil
}

func (s publicServer) StartAddEmail(ctx context.Context, req publicapi.StartAddEmailRequestObject) (publicapi.StartAddEmailResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartAddEmail401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if req.Body == nil {
		return publicapi.StartAddEmail400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	st, err := s.a.email.StartAdd(ctx, s.a.realm.ID, au.PrincipalID, req.Body.Email, s.a.clientOf(ctx))
	switch {
	case errors.Is(err, account.ErrEmailInvalid):
		return publicapi.StartAddEmail400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_email"}}, nil
	case errors.Is(err, account.ErrViaNotAllowed):
		return publicapi.StartAddEmail400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "verification_method_disabled"}}, nil
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.StartAddEmail429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.StartAddEmail409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: flowCookie, Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
	return publicapi.StartAddEmail200JSONResponse{FlowId: st.FlowID, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) VerifyAddEmail(ctx context.Context, req publicapi.VerifyAddEmailRequestObject) (publicapi.VerifyAddEmailResponseObject, error) {
	fail := publicapi.VerifyAddEmail401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	in := emailflow.Verify{FlowID: deref(req.Body.FlowId), Code: deref(req.Body.Code), LinkToken: deref(req.Body.Token), Client: s.a.clientOf(ctx)}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, flowCookie)
	}
	e, err := s.a.email.VerifyAdd(ctx, s.a.realm.ID, au.PrincipalID, in)
	if errors.Is(err, errs.AuthenticationFailed) {
		return fail, nil
	}
	setCookie(ctx, &http.Cookie{Name: flowCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if code, ok := stateCode(err); ok {
		return publicapi.VerifyAddEmail409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	var out publicapi.MyEmail
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.myEmail(ctx, tx, e)
		return err
	})
	if err != nil {
		return nil, err
	}
	return publicapi.VerifyAddEmail200JSONResponse(out), nil
}

// change は本人の認証手段を1つのトランザクションで変える。理由を返せる拒否は (code, true)。
func (s publicServer) change(ctx context.Context, fn func(ctx context.Context, tx port.Tx, au auth) error) (notFound bool, code string, err error) {
	au, _ := authFrom(ctx)
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, au) })
	if errors.Is(err, errs.NotFound) {
		return true, "", nil
	}
	if c, ok := stateCode(err); ok {
		return false, c, nil
	}
	return false, "", err
}

func (s publicServer) MakeMyEmailPrimary(ctx context.Context, req publicapi.MakeMyEmailPrimaryRequestObject) (publicapi.MakeMyEmailPrimaryResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.MakeMyEmailPrimary401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		return s.a.accounts.SetPrimaryEmail(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.MakeMyEmailPrimary404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.MakeMyEmailPrimary409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.MakeMyEmailPrimary204Response{}, nil
}

func (s publicServer) RemoveMyEmail(ctx context.Context, req publicapi.RemoveMyEmailRequestObject) (publicapi.RemoveMyEmailResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.RemoveMyEmail401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		return s.a.accounts.RemoveEmail(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.RemoveMyEmail404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.RemoveMyEmail409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.RemoveMyEmail204Response{}, nil
}

func (s publicServer) StartLinkIdentity(ctx context.Context, req publicapi.StartLinkIdentityRequestObject) (publicapi.StartLinkIdentityResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartLinkIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	var redirectURI string
	if req.Body != nil {
		redirectURI = deref(req.Body.RedirectUri)
	}
	st, err := s.a.oauth.StartLink(ctx, s.a.realm.ID, req.Connection, redirectURI, au.PrincipalID)
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.StartLinkIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.StartLinkIdentity400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_redirect_uri"}}, nil
	case err != nil:
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: oauthCookie, Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
	return publicapi.StartLinkIdentity200JSONResponse{FlowId: st.FlowID, AuthorizationUrl: st.AuthorizationURL, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) CompleteLinkIdentity(ctx context.Context, req publicapi.CompleteLinkIdentityRequestObject) (publicapi.CompleteLinkIdentityResponseObject, error) {
	fail := publicapi.CompleteLinkIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	in := oauth.Complete{FlowID: deref(req.Body.FlowId), State: req.Body.State, Code: req.Body.Code,
		Client: oauth.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, oauthCookie)
	}
	ident, err := s.a.oauth.CompleteLink(ctx, s.a.realm.ID, au.PrincipalID, in)
	setCookie(ctx, &http.Cookie{Name: oauthCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	switch {
	case errors.Is(err, oauth.ErrIdentityExists):
		return publicapi.CompleteLinkIdentity409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: "identity_exists"}}, nil
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
	return publicapi.CompleteLinkIdentity200JSONResponse{Id: ident.PublicID, Connection: slug, CreatedAt: ident.CreatedAt}, nil
}

func (s publicServer) UnlinkMyIdentity(ctx context.Context, req publicapi.UnlinkMyIdentityRequestObject) (publicapi.UnlinkMyIdentityResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.UnlinkMyIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		_, err := s.a.accounts.UnlinkIdentity(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.UnlinkMyIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.UnlinkMyIdentity409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.UnlinkMyIdentity204Response{}, nil
}
