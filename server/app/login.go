package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
)

// flowCookie はメールのフロー ID を要求したブラウザにだけ渡す Cookie（design.md 4.1）。
const flowCookie = "__Host-iam_flow"

func (a *App) clientOf(ctx context.Context) emailflow.Client {
	c, _ := ctx.Value(clientKey{}).(client)
	return emailflow.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: requestID(ctx)}
}

func (s publicServer) StartEmailLogin(ctx context.Context, req publicapi.StartEmailLoginRequestObject) (publicapi.StartEmailLoginResponseObject, error) {
	if req.Body == nil {
		return publicapi.StartEmailLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	st, err := s.a.email.Start(ctx, s.a.realm.ID, req.Body.Email, s.a.clientOf(ctx))
	if errors.Is(err, account.ErrEmailInvalid) {
		return publicapi.StartEmailLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_email"}}, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: flowCookie, Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
	return publicapi.StartEmailLogin200JSONResponse{FlowId: st.FlowID, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) VerifyEmailLogin(ctx context.Context, req publicapi.VerifyEmailLoginRequestObject) (publicapi.VerifyEmailLoginResponseObject, error) {
	fail := publicapi.VerifyEmailLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	in := emailflow.Verify{FlowID: deref(req.Body.FlowId), Code: deref(req.Body.Code), LinkToken: deref(req.Body.Token), Client: s.a.clientOf(ctx)}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, flowCookie)
	}
	if tok, viaCookie := sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	v, err := s.a.email.Verify(ctx, s.a.realm.ID, in)
	if errors.Is(err, errs.AuthenticationFailed) {
		return fail, nil
	}
	if err != nil {
		return nil, err
	}
	setCookie(ctx, &http.Cookie{Name: flowCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	out := publicapi.VerifyEmailLogin200JSONResponse{SessionId: v.Session.Session.ID, ExpiresAt: v.Session.Session.ExpiresAt,
		UserId: v.UserID, Created: v.Created}
	if req.Body.ReturnToken != nil && *req.Body.ReturnToken {
		out.Token = &v.Session.Token
	} else {
		setCookie(ctx, sessionCookieFor(v.Session.Token, v.Session.Session.ExpiresAt, s.a.deps.Clock.Now()))
	}
	return out, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
