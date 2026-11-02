package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// 認証方式のプラグインの汎用の HTTP（ADR 0090、0092）。ペイロードは方式ごとの JSON（OpenAPI では object）。

// methodRestricted は制限つきのセッションで使える汎用のパス（restrictedAllowed の {method} 版）。方式の名前の形だけを見る。
// 登録だけのセッションで2要素目に使えない方式を登録させないことは、ハンドラが確かめる。
func methodRestricted(r port.SessionRestriction, httpMethod, path string) bool {
	if httpMethod != "POST" {
		return false
	}
	if rest, ok := strings.CutPrefix(path, "/v1/login/second-factor/"); ok {
		name, verb, ok := strings.Cut(rest, ":")
		return ok && method.ValidName(name) && (verb == "begin" || verb == "complete") &&
			(r == port.RestrictionSecondFactor || r == port.RestrictionEnroll)
	}
	if rest, ok := strings.CutPrefix(path, "/v1/me/credentials/"); ok {
		name, verb, ok := strings.Cut(rest, ":")
		return ok && method.ValidName(name) && (verb == "enroll-begin" || verb == "enroll-complete") &&
			(r == port.RestrictionEnroll || r == port.RestrictionRecovery)
	}
	return false
}

// rawPayload は要求の payload（object）を方式に渡す JSON にする。無ければ nil。
func rawPayload(p *map[string]any) (json.RawMessage, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(*p)
}

// objectPayload は方式の応答の JSON を応答の object にする（数は丸めない）。
func objectPayload(raw json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func challengeOut(ch credential.Challenge) (publicapi.MethodChallenge, error) {
	p, err := objectPayload(ch.Payload)
	return publicapi.MethodChallenge{FlowId: ch.FlowID, Payload: p, ExpiresAt: ch.ExpiresAt}, err
}

func myCredential(c port.Credential) publicapi.MyCredential {
	return publicapi.MyCredential{Id: c.PublicID, Method: c.Method, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt}
}

// invalidPayload は方式が返した入力の誤り（errs.Invalid）のコード。
func invalidPayload(err error) (string, bool) {
	if !errors.Is(err, errs.Invalid) {
		return "", false
	}
	if c := errCode(err); c != "" {
		return c, true
	}
	return "invalid_request", true
}

func (s publicServer) BeginMethodLogin(ctx context.Context, req publicapi.BeginMethodLoginRequestObject) (publicapi.BeginMethodLoginResponseObject, error) {
	if _, err := s.a.credentials.Method(req.Method, port.UsageFirstFactor); err != nil {
		return publicapi.BeginMethodLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	fail := publicapi.BeginMethodLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	var p json.RawMessage
	if req.Body != nil {
		var err error
		if p, err = rawPayload(req.Body.Payload); err != nil {
			return fail, nil
		}
	}
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, "", req.Method, port.UsageFirstFactor, p)
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.BeginMethodLogin429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if err != nil {
		if errors.Is(err, errs.AuthenticationFailed) || errors.Is(err, errs.Invalid) {
			return fail, nil
		}
		return nil, err
	}
	out, err := challengeOut(ch)
	if err != nil {
		return nil, err
	}
	return publicapi.BeginMethodLogin200JSONResponse(out), nil
}

func (s publicServer) CompleteMethodLogin(ctx context.Context, req publicapi.CompleteMethodLoginRequestObject) (publicapi.CompleteMethodLoginResponseObject, error) {
	if _, err := s.a.credentials.Method(req.Method, port.UsageFirstFactor); err != nil {
		return publicapi.CompleteMethodLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	fail := publicapi.CompleteMethodLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	p, err := rawPayload(req.Body.Payload)
	if err != nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	is, uid, err := s.a.credentials.Login(ctx, s.a.realm.ID, req.Method, req.Body.FlowId, p,
		credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}, s.a.replaceToken(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.CompleteMethodLogin429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.CompleteMethodLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CompleteMethodLogin200JSONResponse(s.loginResult(ctx, is, uid, false, req.Body.ReturnToken)), nil
}

func (s publicServer) BeginSecondFactorMethod(ctx context.Context, req publicapi.BeginSecondFactorMethodRequestObject) (publicapi.BeginSecondFactorMethodResponseObject, error) {
	fail := publicapi.BeginSecondFactorMethod401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := restricted(ctx)
	if !ok {
		return fail, nil
	}
	if _, err := s.a.credentials.Method(req.Method, port.UsageSecondFactor); err != nil {
		return publicapi.BeginSecondFactorMethod404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var p json.RawMessage
	if req.Body != nil {
		var err error
		if p, err = rawPayload(req.Body.Payload); err != nil {
			return fail, nil
		}
	}
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, au.PrincipalID, req.Method, port.UsageSecondFactor, p)
	switch {
	case errors.Is(err, errs.NotFound):
		// 本人がその方式の認証情報を持たない（本人確認の後なので区別してよい）。
		return publicapi.BeginSecondFactorMethod404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid):
		return fail, nil
	case err != nil:
		return nil, err
	}
	out, err := challengeOut(ch)
	if err != nil {
		return nil, err
	}
	return publicapi.BeginSecondFactorMethod200JSONResponse(out), nil
}

func (s publicServer) CompleteSecondFactorMethod(ctx context.Context, req publicapi.CompleteSecondFactorMethodRequestObject) (publicapi.CompleteSecondFactorMethodResponseObject, error) {
	fail := publicapi.CompleteSecondFactorMethod401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := restricted(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if _, err := s.a.credentials.Method(req.Method, port.UsageSecondFactor); err != nil {
		return publicapi.CompleteSecondFactorMethod404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	p, err := rawPayload(req.Body.Payload)
	if err != nil {
		return fail, nil
	}
	// 2 要素目のコードはアカウント単位のロックアウトで数える（ADR 0105）。
	if err := s.a.secondFactorLocked(ctx, au.PrincipalID); err != nil {
		if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			return publicapi.CompleteSecondFactorMethod429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
		}
		return nil, err
	}
	c := s.a.clientOf(ctx)
	is, err := s.a.credentials.SecondFactor(ctx, s.a.realm.ID, au.PrincipalID, au.SessionID, req.Method, req.Body.FlowId, p,
		credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
	if err == nil || errors.Is(err, errs.AuthenticationFailed) {
		if err := s.a.secondFactorResult(ctx, au, err != nil); err != nil {
			return nil, err
		}
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.CompleteSecondFactorMethod429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.CompleteSecondFactorMethod403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid), errors.Is(err, session.ErrNotRestricted):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.CompleteSecondFactorMethod200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)), nil
}

// enrollable は本人が方式 name を登録できるか。登録だけのセッション（2要素目の登録の要求）では、2要素目に使える方式だけ。
func (s publicServer) enrollable(au auth, name string) bool {
	if _, err := s.a.credentials.Method(name, ""); err != nil {
		return false
	}
	return au.Restriction != port.RestrictionEnroll || s.a.methods.Supports(name, port.UsageSecondFactor)
}

func (s publicServer) BeginEnrollCredential(ctx context.Context, req publicapi.BeginEnrollCredentialRequestObject) (publicapi.BeginEnrollCredentialResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.BeginEnrollCredential401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.stale(ctx, au) {
		return publicapi.BeginEnrollCredential401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if !s.enrollable(au, req.Method) {
		return publicapi.BeginEnrollCredential404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var p json.RawMessage
	if req.Body != nil {
		var err error
		if p, err = rawPayload(req.Body.Payload); err != nil {
			return publicapi.BeginEnrollCredential400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
		}
	}
	ch, err := s.a.credentials.EnrollBegin(ctx, s.a.realm.ID, au.PrincipalID, req.Method, p)
	if code, ok := invalidPayload(err); ok {
		return publicapi.BeginEnrollCredential400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: code}}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.BeginEnrollCredential409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := challengeOut(ch)
	if err != nil {
		return nil, err
	}
	return publicapi.BeginEnrollCredential200JSONResponse(out), nil
}

func (s publicServer) CompleteEnrollCredential(ctx context.Context, req publicapi.CompleteEnrollCredentialRequestObject) (publicapi.CompleteEnrollCredentialResponseObject, error) {
	fail := publicapi.CompleteEnrollCredential401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if s.stale(ctx, au) {
		return publicapi.CompleteEnrollCredential401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if !s.enrollable(au, req.Method) {
		return publicapi.CompleteEnrollCredential404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	p, err := rawPayload(req.Body.Payload)
	if err != nil {
		return publicapi.CompleteEnrollCredential400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	c := s.a.clientOf(ctx)
	var en credential.Enrolled
	var is session.Issued
	var codes *[]string
	upgrade := au.Restriction == port.RestrictionEnroll
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if en, err = s.a.credentials.EnrollComplete(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Method, req.Body.FlowId, p, au.Actor(), c.RequestID); err != nil {
			return err
		}
		if codes, err = s.initialCodes(ctx, tx, au); err != nil || !upgrade {
			return err
		}
		// 登録だけのセッションは、登録の確認（所持の証明）を2要素目として通常のセッションに替える（TOTP と同じ。ADR 0050）。
		a, err := s.a.credentials.Method(req.Method, port.UsageSecondFactor)
		if err != nil {
			return err
		}
		is, err = s.a.sessions.CompleteSecondFactor(ctx, tx, s.a.realm.ID, au.SessionID, session.SecondFactor{
			AMR: a.Info().AMR, CredentialID: en.Credential.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
		})
		return err
	})
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.CompleteEnrollCredential429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := invalidPayload(err); ok {
		return publicapi.CompleteEnrollCredential400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: code}}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.CompleteEnrollCredential409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, session.ErrNotRestricted):
		return fail, nil
	case err != nil:
		return nil, err
	}
	payload, err := objectPayload(en.Payload)
	if err != nil {
		return nil, err
	}
	out := publicapi.CompleteEnrollCredential200JSONResponse{Credential: myCredential(en.Credential), Payload: payload, RecoveryCodes: codes}
	if upgrade {
		s.a.sessions.Committed(ctx, s.a.realm.ID, is)
		login := s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)
		out.Login = &login
	}
	return out, nil
}

func (s publicServer) RevokeMyCredential(ctx context.Context, req publicapi.RevokeMyCredentialRequestObject) (publicapi.RevokeMyCredentialResponseObject, error) {
	if au, ok := authFrom(ctx); !ok {
		return publicapi.RevokeMyCredential401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	} else if s.stale(ctx, au) {
		return publicapi.RevokeMyCredential401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		_, err := s.a.accounts.RevokeCredential(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.RevokeMyCredential404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.RevokeMyCredential409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.RevokeMyCredential204Response{}, nil
}
