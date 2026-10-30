package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// メール + パスワード（フィーチャー password。design.md 4.1、ADR 0051）。フィーチャーが動いていなければ 404。

func (s publicServer) PasswordLogin(ctx context.Context, req publicapi.PasswordLoginRequestObject) (publicapi.PasswordLoginResponseObject, error) {
	if s.a.password == nil {
		return publicapi.PasswordLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.PasswordLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	c := s.a.clientOf(ctx)
	in := password.Login{Email: req.Body.Email, Password: req.Body.Password, Client: password.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}}
	if tok, viaCookie := s.a.sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	res, err := s.a.password.Login(ctx, s.a.realm.ID, in)
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.PasswordLogin429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.PasswordLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed):
		return publicapi.PasswordLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.PasswordLogin200JSONResponse(s.loginResult(ctx, res.Session, res.UserID, false, req.Body.ReturnToken)), nil
}

// errCode はエラーのコード（本人に返してよいもの）。
func errCode(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// errMessage は errs.Error の説明（運営者向け。秘密や個人情報を含めないエラーにだけ使う）。
func errMessage(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Msg
	}
	return ""
}

func (s publicServer) SetMyPassword(ctx context.Context, req publicapi.SetMyPasswordRequestObject) (publicapi.SetMyPasswordResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.SetMyPassword401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.password == nil {
		return publicapi.SetMyPassword404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.SetMyPassword400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	recent := s.recent(ctx, au, role.ActionMePassword)
	// 今のパスワードは max_auth_age の代わりになるが、操作の要件の代わりにはならない。
	if au.Restriction != port.RestrictionRecovery && !recent && !s.meets(ctx, au, role.ActionMePassword) {
		return publicapi.SetMyPassword401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	var err error
	if au.Restriction == port.RestrictionRecovery {
		// 復旧では今のパスワードを求めない（忘れたときの再設定。4.12）。
		_, err = s.a.password.Reset(ctx, s.a.realm.ID, au.PrincipalID, req.Body.Password, au.Actor(), requestID(ctx))
	} else {
		_, err = s.a.password.Set(ctx, s.a.realm.ID, au.PrincipalID, req.Body.Password, deref(req.Body.CurrentPassword), recent, au.SessionID, au.Actor(), requestID(ctx))
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.SetMyPassword429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	switch {
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrBreached):
		return publicapi.SetMyPassword400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, password.ErrReauthRequired):
		return publicapi.SetMyPassword401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, password.ErrCurrentPassword):
		return publicapi.SetMyPassword409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: errCode(err)}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.SetMyPassword204Response{}, nil
}

func (s publicServer) RemoveMyPassword(ctx context.Context, req publicapi.RemoveMyPasswordRequestObject) (publicapi.RemoveMyPasswordResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RemoveMyPassword401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.password == nil || req.Body == nil {
		return publicapi.RemoveMyPassword404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	// 今のパスワードは max_auth_age の代わりになるが、認証の手段の操作の要件（me:methods）の代わりにはならない。
	if au.Restriction == port.RestrictionNone && !s.meets(ctx, au, role.ActionMeMethods) {
		return publicapi.RemoveMyPassword401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	err := s.a.password.Remove(ctx, s.a.realm.ID, au.PrincipalID, req.Body.CurrentPassword, au.SessionID, au.Actor(), requestID(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.RemoveMyPassword429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.RemoveMyPassword409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, password.ErrNoPassword):
		return publicapi.RemoveMyPassword404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.RemoveMyPassword204Response{}, nil
}

// myPassword は認証手段の一覧のパスワードの欄。
func myPassword(createdAt time.Time) *struct {
	CreatedAt time.Time `json:"created_at"`
} {
	return &struct {
		CreatedAt time.Time `json:"created_at"`
	}{CreatedAt: createdAt}
}
