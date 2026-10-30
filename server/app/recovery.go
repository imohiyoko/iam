package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/loginlink"
	"github.com/imohiyoko/iam/authn/recovery"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// アカウントの復旧（design.md 4.12、ADR 0054）。どの経路も復旧専用のセッションを出し、新しい認証手段の登録の後に
// /v1/recovery:complete で終える。

// 復旧の経路（security.recovery.methods）。
const (
	recoveryByCode  = "recovery_code"
	recoveryByEmail = "email"
	recoveryByLink  = "operator_link"
)

func (a *App) recoveryAllows(method string) bool {
	if method == recoveryByEmail && !a.accounts.Allows(port.VerifiedViaCode) {
		return false
	}
	return a.cfg.Security.Recovery.Allows(method)
}

// replaceToken はブラウザが Cookie で持っていたセッションのトークン（ログイン・復旧で ID を入れ替える）。
func (a *App) replaceToken(ctx context.Context) string {
	if tok, viaCookie := a.sessionToken(httpFrom(ctx).r); viaCookie {
		return tok
	}
	return ""
}

// initialCodes は最初の強い認証手段の登録の後に、リカバリーコードを作って返す（4.12）。持っていれば nil。
// 復旧専用のセッションでは作らない（完了のときに作り直す）。
func (s publicServer) initialCodes(ctx context.Context, tx port.Tx, au auth) (*[]string, error) {
	if au.Restriction == port.RestrictionRecovery {
		return nil, nil
	}
	codes, err := s.a.recovery.Initial(ctx, tx, s.a.realm.ID, au.PrincipalID, au.Actor(), requestID(ctx))
	if err != nil || codes == nil {
		return nil, err
	}
	return &codes, nil
}

func (s publicServer) RedeemRecoveryCode(ctx context.Context, req publicapi.RedeemRecoveryCodeRequestObject) (publicapi.RedeemRecoveryCodeResponseObject, error) {
	if !s.a.recoveryAllows(recoveryByCode) {
		return publicapi.RedeemRecoveryCode404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	fail := publicapi.RedeemRecoveryCode401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	is, uid, err := s.a.recovery.Redeem(ctx, s.a.realm.ID, req.Body.Email, req.Body.Code,
		recovery.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}, s.a.replaceToken(ctx))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.RedeemRecoveryCode429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.RedeemRecoveryCode403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	if errors.Is(err, errs.AuthenticationFailed) {
		return fail, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RedeemRecoveryCode200JSONResponse(s.loginResult(ctx, is, uid, false, req.Body.ReturnToken)), nil
}

func (s publicServer) StartEmailRecovery(ctx context.Context, req publicapi.StartEmailRecoveryRequestObject) (publicapi.StartEmailRecoveryResponseObject, error) {
	if !s.a.recoveryAllows(recoveryByEmail) {
		return publicapi.StartEmailRecovery404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.StartEmailRecovery400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	st, err := s.a.email.StartRecovery(ctx, s.a.realm.ID, req.Body.Email, s.a.clientOf(ctx))
	if errors.Is(err, account.ErrEmailInvalid) {
		return publicapi.StartEmailRecovery400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_email"}}, nil
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.StartEmailRecovery429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.a.deps.Clock.Now()
	setCookie(ctx, &http.Cookie{Name: s.a.cookie(flowCookie), Value: st.FlowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: max(int(st.ExpiresAt.Sub(now)/time.Second), 1)})
	return publicapi.StartEmailRecovery200JSONResponse{FlowId: st.FlowID, ExpiresAt: st.ExpiresAt}, nil
}

func (s publicServer) VerifyEmailRecovery(ctx context.Context, req publicapi.VerifyEmailRecoveryRequestObject) (publicapi.VerifyEmailRecoveryResponseObject, error) {
	if !s.a.recoveryAllows(recoveryByEmail) {
		return publicapi.VerifyEmailRecovery404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	fail := publicapi.VerifyEmailRecovery401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	in := emailflow.Verify{FlowID: deref(req.Body.FlowId), Code: deref(req.Body.Code), LinkToken: deref(req.Body.Token),
		Client: s.a.clientOf(ctx), ReplaceToken: s.a.replaceToken(ctx)}
	if in.FlowID == "" {
		in.FlowID = cookie(ctx, s.a.cookie(flowCookie))
	}
	v, err := s.a.email.VerifyRecovery(ctx, s.a.realm.ID, in)
	if errors.Is(err, errs.AuthenticationFailed) {
		return fail, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.VerifyEmailRecovery403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	if err != nil {
		return nil, err
	}
	setCookie(ctx, &http.Cookie{Name: s.a.cookie(flowCookie), Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	return publicapi.VerifyEmailRecovery200JSONResponse(s.loginResult(ctx, v.Session, v.UserID, false, req.Body.ReturnToken)), nil
}

func (s publicServer) RedeemRecoveryLink(ctx context.Context, req publicapi.RedeemRecoveryLinkRequestObject) (publicapi.RedeemRecoveryLinkResponseObject, error) {
	if !s.a.recoveryAllows(recoveryByLink) {
		return publicapi.RedeemRecoveryLink404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	fail := publicapi.RedeemRecoveryLink401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	is, uid, err := s.a.links.RedeemRecovery(ctx, s.a.realm.ID, req.Body.Token,
		loginlink.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}, s.a.replaceToken(ctx))
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.RedeemRecoveryLink403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	if errors.Is(err, errs.AuthenticationFailed) {
		return fail, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RedeemRecoveryLink200JSONResponse(s.loginResult(ctx, is, uid, false, req.Body.ReturnToken)), nil
}

func (s publicServer) CompleteRecovery(ctx context.Context, _ publicapi.CompleteRecoveryRequestObject) (publicapi.CompleteRecoveryResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok || au.Restriction != port.RestrictionRecovery {
		return publicapi.CompleteRecovery401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	c := s.a.clientOf(ctx)
	codes, revoked, err := s.a.recovery.Complete(ctx, s.a.realm.ID, au.SessionID, recovery.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
	switch {
	case errors.Is(err, recovery.ErrNoNewMethod):
		return publicapi.CompleteRecovery409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, recovery.ErrNotRecovery):
		return publicapi.CompleteRecovery401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	case err != nil:
		return nil, err
	}
	setCookie(ctx, s.a.clearSessionCookie())
	return publicapi.CompleteRecovery200JSONResponse{RecoveryCodes: codes, SessionsRevoked: len(revoked)}, nil
}

func (s publicServer) RegenerateMyRecoveryCodes(ctx context.Context, _ publicapi.RegenerateMyRecoveryCodesRequestObject) (publicapi.RegenerateMyRecoveryCodesResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok || au.Restriction != port.RestrictionNone {
		return publicapi.RegenerateMyRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.recent(au) {
		return publicapi.RegenerateMyRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: publicapi.UnauthenticatedJSONResponse{Error: "reauthentication_required"}}, nil
	}
	var codes []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		codes, err = s.a.recovery.Generate(ctx, tx, s.a.realm.ID, au.PrincipalID, au.Actor(), requestID(ctx))
		return err
	})
	if err != nil {
		return nil, err
	}
	return publicapi.RegenerateMyRecoveryCodes200JSONResponse{RecoveryCodes: codes}, nil
}

func (s adminServer) IssueRecoveryLink(ctx context.Context, req adminapi.IssueRecoveryLinkRequestObject) (adminapi.IssueRecoveryLinkResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersRecover)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.IssueRecoveryLink401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.IssueRecoveryLink403JSONResponse(d.Body), nil
	case !s.a.recoveryAllows(recoveryByLink):
		return adminapi.IssueRecoveryLink404JSONResponse(adminError("not_found", "operator_link recovery is disabled")), nil
	case req.Body == nil || strings.TrimSpace(req.Body.Reason) == "" || utf8.RuneCountInString(req.Body.Reason) > 1000:
		return adminapi.IssueRecoveryLink400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_reason", ""))}, nil
	}
	ttl := loginLinkTTL
	if req.Body.TtlSeconds != nil {
		ttl, _ = loginlink.TTLSeconds(int64(*req.Body.TtlSeconds)) // 範囲の外は 0 で、次の ValidTTL が拒む
	}
	if err := loginlink.ValidTTL(ttl); err != nil {
		return adminapi.IssueRecoveryLink400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_ttl", err.Error()))}, nil
	}
	exp := s.a.deps.Clock.Now().Add(ttl)
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if u.Status != port.UserActive {
			return errs.New(errs.KindNotFound, "user cannot recover")
		}
		if err := s.a.outranks(ctx, tx, p, u.ID); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "recovery.link_issued", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"user_id": u.PublicID, "reason": req.Body.Reason, "expires_at": exp.UTC().Format(time.RFC3339)},
		})
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.IssueRecoveryLink404JSONResponse(adminError("not_found", "")), nil
	}
	if errors.Is(err, errOutranked) {
		return adminapi.IssueRecoveryLink403JSONResponse(adminError(errs.CodePermissionDenied, "")), nil
	}
	if err != nil {
		return nil, err
	}
	tok, err := loginlink.IssueRecovery(ctx, s.a.pii, s.a.realm.ID, req.Id, exp)
	if err != nil {
		return nil, err
	}
	return adminapi.IssueRecoveryLink200JSONResponse{Token: tok, ExpiresAt: exp}, nil
}
