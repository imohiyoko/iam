package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
)

// oauthCookie は OAuth のフロー ID を要求したブラウザにだけ渡す Cookie。
const oauthCookie = "__Host-iam_oauth"

func (s publicServer) StartOAuthLogin(ctx context.Context, req publicapi.StartOAuthLoginRequestObject) (publicapi.StartOAuthLoginResponseObject, error) {
	var redirectURI string
	if req.Body != nil {
		redirectURI = deref(req.Body.RedirectUri)
	}
	st, err := s.a.oauth.Start(ctx, s.a.realm.ID, req.Connection, redirectURI)
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.StartOAuthLogin404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.StartOAuthLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_redirect_uri"}}, nil
	case err != nil:
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: oauthCookie, Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
	return publicapi.StartOAuthLogin200JSONResponse{FlowId: st.FlowID, AuthorizationUrl: st.AuthorizationURL, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) CompleteOAuthLogin(ctx context.Context, req publicapi.CompleteOAuthLoginRequestObject) (publicapi.CompleteOAuthLoginResponseObject, error) {
	fail := publicapi.CompleteOAuthLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	in := oauth.Complete{FlowID: deref(req.Body.FlowId), State: req.Body.State, Code: req.Body.Code,
		Client: oauth.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, oauthCookie)
	}
	if tok, viaCookie := sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	res, err := s.a.oauth.Complete(ctx, s.a.realm.ID, in)
	// 失敗でもフローは使い終わったので Cookie を消す。
	setCookie(ctx, &http.Cookie{Name: oauthCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	switch {
	case errors.Is(err, oauth.ErrAccountExists):
		return publicapi.CompleteOAuthLogin409JSONResponse{Error: "account_exists"}, nil
	case errors.Is(err, oauth.ErrEmailUnverified):
		return publicapi.CompleteOAuthLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "email_unverified"}}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	out := publicapi.CompleteOAuthLogin200JSONResponse{SessionId: res.Session.Session.ID, ExpiresAt: res.Session.Session.ExpiresAt,
		UserId: res.UserID, Created: res.Created}
	if req.Body.ReturnToken != nil && *req.Body.ReturnToken {
		out.Token = &res.Session.Token
	} else {
		setCookie(ctx, sessionCookieFor(res.Session.Token, res.Session.Session.ExpiresAt, s.a.deps.Clock.Now()))
	}
	return out, nil
}
