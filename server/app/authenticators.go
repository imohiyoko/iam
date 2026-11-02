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

// pendingInterval は、別の経路からの応答を待つ間に complete を呼び直すまでの秒数（ADR 0104）。
const pendingInterval = 2

// client は要求の接続元（方式の接続元ごとの制限と監査ログ）。
func (s publicServer) client(ctx context.Context) credential.Client {
	c := s.a.clientOf(ctx)
	return credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}
}

// MethodCallback は、別の経路（本人の端末など）からの応答を方式に渡す（ADR 0104）。セッションを要さない。
func (s publicServer) MethodCallback(ctx context.Context, req publicapi.MethodCallbackRequestObject) (publicapi.MethodCallbackResponseObject, error) {
	if _, err := s.a.credentials.Method(req.Method, ""); err != nil {
		return publicapi.MethodCallback404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	bad := publicapi.MethodCallback400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}
	if req.Body == nil {
		return bad, nil
	}
	p, err := rawPayload(req.Body.Payload)
	if err != nil {
		return bad, nil
	}
	out, err := s.a.credentials.Callback(ctx, s.a.realm.ID, req.Method, p, s.client(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.MethodCallback429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := invalidPayload(err); ok {
		return publicapi.MethodCallback400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, credential.ErrUnknownMethod):
		return publicapi.MethodCallback404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return publicapi.MethodCallback401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case err != nil:
		return nil, err
	}
	payload, err := objectPayload(out)
	if err != nil {
		return nil, err
	}
	return publicapi.MethodCallback200JSONResponse{Payload: payload}, nil
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
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, "", req.Method, port.UsageFirstFactor, p, s.client(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.BeginMethodLogin429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if errors.Is(err, port.ErrDeliveryFailed) {
		return publicapi.BeginMethodLogin503JSONResponse{Error: "delivery_failed"}, nil
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
	if errors.Is(err, port.ErrMethodPending) {
		return publicapi.CompleteMethodLogin202JSONResponse{Status: publicapi.MethodPendingStatusPending, Interval: pendingInterval}, nil
	}
	if errors.Is(err, port.ErrNegotiate) {
		challengeNegotiate(ctx)
		return publicapi.CompleteMethodLogin401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: errCode(err)}}, nil
	}
	if errors.Is(err, errs.Unavailable) {
		// 結び付けに使うディレクトリなど、方式の依存先の障害（ADR 0107）。利用者の失敗にしない。
		s.a.deps.Logger.WarnContext(ctx, "method login: dependency unavailable", "method", req.Method, "error", err)
		out := directoryUnavailable()
		if c := errCode(err); c != "" {
			out.Error = c
		}
		return publicapi.CompleteMethodLogin503JSONResponse{DirectoryUnavailableJSONResponse: out}, nil
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
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, au.PrincipalID, req.Method, port.UsageSecondFactor, p, s.client(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.BeginSecondFactorMethod429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	switch {
	case errors.Is(err, port.ErrDeliveryFailed):
		return publicapi.BeginSecondFactorMethod503JSONResponse{Error: "delivery_failed"}, nil
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
	c := s.a.clientOf(ctx)
	is, err := s.a.credentials.SecondFactor(ctx, s.a.realm.ID, au.PrincipalID, au.SessionID, req.Method, req.Body.FlowId, p,
		credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.CompleteSecondFactorMethod429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if errors.Is(err, port.ErrMethodPending) {
		return publicapi.CompleteSecondFactorMethod202JSONResponse{Status: publicapi.MethodPendingStatusPending, Interval: pendingInterval}, nil
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

// knowledge は方式 name が知識の要素か。パスワードは、フィーチャーが止まっていても知識の要素として扱う（ADR 0101）。
func (s publicServer) knowledge(name string) bool {
	if a, ok := s.a.methods.Get(name); ok {
		return a.Info().Kind == port.FactorKnowledge
	}
	return name == method.Password
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
	// 汎用のパスは直近の認証を求める（stale）ので RecentAuth。復旧専用のセッションでは、今の秘密を求めない再設定になる（ADR 0101）。
	ch, err := s.a.credentials.EnrollBegin(ctx, s.a.realm.ID, au.PrincipalID, req.Method, p,
		credential.EnrollOptions{Recovery: au.Restriction == port.RestrictionRecovery, RecentAuth: true, Client: s.client(ctx)})
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.BeginEnrollCredential429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if errors.Is(err, port.ErrDeliveryFailed) {
		return publicapi.BeginEnrollCredential503JSONResponse{Error: "delivery_failed"}, nil
	}
	if errors.Is(err, port.ErrNegotiate) {
		challengeNegotiate(ctx)
		return publicapi.BeginEnrollCredential401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: errCode(err)}}, nil
	}
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
		if en, err = s.a.credentials.EnrollComplete(ctx, tx, credential.EnrollInput{RealmID: s.a.realm.ID, UserID: au.PrincipalID,
			Method: req.Method, FlowID: req.Body.FlowId, Payload: p, Actor: au.Actor(), RequestID: c.RequestID, KeepSession: au.SessionID}); err != nil {
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
	if errors.Is(err, port.ErrMethodPending) {
		return publicapi.CompleteEnrollCredential202JSONResponse{Status: publicapi.MethodPendingStatusPending, Interval: pendingInterval}, nil
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
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, en.RevokedSessions)
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
	var revoked []string
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		c, err := s.a.accounts.RevokeCredential(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
		if err != nil || !s.knowledge(c.Method) {
			return err
		}
		// 知識の要素（パスワード）を外したら、今のセッション以外を失効させる（5.2。方式専用のパスと同じ）。
		revoked, err = s.a.sessions.RevokeAllTx(ctx, tx, s.a.realm.ID, au.PrincipalID, au.SessionID, session.ReasonCredentialChanged, au.Actor(), requestID(ctx))
		return err
	})
	s.a.sessions.ForgetIDs(ctx, s.a.realm.ID, revoked)
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
