package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/totp"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// 2段階認証（design.md 4.1、2.8）。1要素目の後のセッションが制限つきなら、2要素目で通常のセッションに替える。

// restrictedAllowed は制限つきのセッションで使える API。他の API では未ログインとして扱う。
// 復旧専用のセッション（4.12）は新しい認証手段の登録と復旧の完了だけ。外部 ID の連携は戻り先の扱いが別なので含めない。
var restrictedAllowed = map[string][]port.SessionRestriction{
	"POST /v1/login/second-factor/passkey:start": {port.RestrictionSecondFactor, port.RestrictionEnroll},
	"POST /v1/login/second-factor:verify":        {port.RestrictionSecondFactor, port.RestrictionEnroll},
	"POST /v1/logout":                            {port.RestrictionSecondFactor, port.RestrictionEnroll, port.RestrictionRecovery, port.RestrictionDeletion},
	"POST /v1/me/account:cancel-deletion":        {port.RestrictionDeletion},
	"GET /v1/me/methods":                         {port.RestrictionEnroll, port.RestrictionRecovery},
	"POST /v1/me/passkeys:start":                 {port.RestrictionEnroll, port.RestrictionRecovery},
	"POST /v1/me/passkeys:finish":                {port.RestrictionEnroll, port.RestrictionRecovery},
	"POST /v1/me/totp:start":                     {port.RestrictionEnroll, port.RestrictionRecovery},
	"POST /v1/me/totp:confirm":                   {port.RestrictionEnroll, port.RestrictionRecovery},
	"POST /v1/me/password:set":                   {port.RestrictionRecovery},
	"POST /v1/recovery:complete":                 {port.RestrictionRecovery},
}

func restrictionAllows(r port.SessionRestriction, method, path string) bool {
	return r == port.RestrictionNone || slices.Contains(restrictedAllowed[method+" "+path], r)
}

// loginResult は発行したセッションを応答の形にし、Cookie を差し替える。
func (s publicServer) loginResult(ctx context.Context, is session.Issued, userID string, created bool, returnToken *bool) publicapi.LoginResult {
	out := publicapi.LoginResult{SessionId: is.Session.ID, ExpiresAt: is.Session.ExpiresAt, UserId: userID, Created: created,
		Warnings: warningsOut(is.Warnings)}
	if is.OrgPublicID != "" {
		out.OrgId = &is.OrgPublicID
	}
	if len(is.OrgChoices) > 0 {
		choices := slices.Clone(is.OrgChoices)
		out.OrgChoices = &choices
	}
	switch is.Session.Restriction {
	case port.RestrictionSecondFactor:
		next, methods := publicapi.SecondFactor, slices.Clone(is.SecondFactorMethods)
		out.Next, out.SecondFactorMethods = &next, &methods
	case port.RestrictionEnroll:
		next := publicapi.Enroll
		out.Next = &next
	case port.RestrictionRecovery:
		next := publicapi.Recovery
		out.Next = &next
	case port.RestrictionDeletion:
		next := publicapi.CancelDeletion
		out.Next = &next
	}
	if deref(returnToken) {
		out.Token = &is.Token
	}
	// return_token でも Cookie は差し替える。送られてきた Cookie のセッションは入れ替えで失効しているため。
	setCookie(ctx, s.a.sessionCookieFor(is.Token, is.Session.ExpiresAt, s.a.deps.Clock.Now()))
	return out
}

// restricted は制限つきのセッションを返す。
func restricted(ctx context.Context) (auth, bool) {
	au, ok := authFrom(ctx)
	return au, ok && au.Restriction != port.RestrictionNone
}

func (s publicServer) StartSecondFactorPasskey(ctx context.Context, _ publicapi.StartSecondFactorPasskeyRequestObject) (publicapi.StartSecondFactorPasskeyResponseObject, error) {
	au, ok := restricted(ctx)
	if !ok {
		return publicapi.StartSecondFactorPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.passkeys == nil {
		return publicapi.StartSecondFactorPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	st, err := s.a.passkeys.BeginVerify(ctx, s.a.realm.ID, au.PrincipalID)
	if errors.Is(err, errs.NotFound) {
		return publicapi.StartSecondFactorPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, st)
	if err != nil {
		return nil, err
	}
	return publicapi.StartSecondFactorPasskey200JSONResponse(out), nil
}

func (s publicServer) VerifySecondFactor(ctx context.Context, req publicapi.VerifySecondFactorRequestObject) (publicapi.VerifySecondFactorResponseObject, error) {
	fail := publicapi.VerifySecondFactor401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := restricted(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	f := session.SecondFactor{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}
	usePasskey := deref(req.Body.TotpCode) == "" && req.Body.Credential != nil && s.a.passkeys != nil
	var is session.Issued
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		switch {
		case deref(req.Body.TotpCode) != "":
			t, err := s.a.totp.Verify(ctx, tx, s.a.realm.ID, au.PrincipalID, *req.Body.TotpCode)
			if err != nil {
				return err
			}
			f.AMR, f.CredentialID = []string{totp.AMR}, t.ID
		case usePasskey:
			resp, err := json.Marshal(*req.Body.Credential)
			if err != nil {
				return passkey.ErrAuthFailed
			}
			p, err := s.a.passkeys.Verify(ctx, tx, s.a.realm.ID, au.PrincipalID, passkeyFlowID(ctx, req.Body.FlowId), resp)
			if err != nil {
				return err
			}
			f.AMR, f.CredentialID = []string{passkey.AMRKey}, p.ID
		default:
			return totp.ErrAuthFailed
		}
		var err error
		is, err = s.a.sessions.CompleteSecondFactor(ctx, tx, s.a.realm.ID, au.SessionID, f)
		return err
	})
	if usePasskey {
		// 失敗でもフローは使い終わったので Cookie を消す。
		setPasskeyCookie(ctx, "", -1)
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.VerifySecondFactor429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.VerifySecondFactor403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, session.ErrNotRestricted):
		return fail, nil
	case err != nil:
		return nil, err
	}
	s.a.sessions.Committed(ctx, s.a.realm.ID, is)
	return publicapi.VerifySecondFactor200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)), nil
}

func (s publicServer) StartRegisterTOTP(ctx context.Context, _ publicapi.StartRegisterTOTPRequestObject) (publicapi.StartRegisterTOTPResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	e, err := s.a.totp.BeginEnroll(ctx, s.a.realm.ID, au.PrincipalID)
	if code, ok := stateCode(err); ok {
		return publicapi.StartRegisterTOTP409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.StartRegisterTOTP200JSONResponse{FlowId: e.FlowID, Secret: e.Secret, Uri: e.URI, ExpiresAt: e.ExpiresAt}, nil
}

func (s publicServer) ConfirmRegisterTOTP(ctx context.Context, req publicapi.ConfirmRegisterTOTPRequestObject) (publicapi.ConfirmRegisterTOTPResponseObject, error) {
	fail := publicapi.ConfirmRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	c := s.a.clientOf(ctx)
	var t port.TOTPCredential
	var is session.Issued
	var codes *[]string
	upgrade := au.Restriction == port.RestrictionEnroll
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		t, err = s.a.totp.ConfirmEnroll(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Body.FlowId, req.Body.Code, au.Actor(), c.RequestID)
		if err != nil {
			return err
		}
		if codes, err = s.initialCodes(ctx, tx, au); err != nil || !upgrade {
			return err
		}
		// 登録だけのセッションは、登録に使ったコードを2要素目として通常のセッションに替える。
		is, err = s.a.sessions.CompleteSecondFactor(ctx, tx, s.a.realm.ID, au.SessionID, session.SecondFactor{
			AMR: []string{totp.AMR}, CredentialID: t.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
		})
		return err
	})
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.ConfirmRegisterTOTP429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.ConfirmRegisterTOTP409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, session.ErrNotRestricted):
		return fail, nil
	case err != nil:
		return nil, err
	}
	out := publicapi.ConfirmRegisterTOTP200JSONResponse{Totp: myTOTP(t), RecoveryCodes: codes}
	if upgrade {
		s.a.sessions.Committed(ctx, s.a.realm.ID, is)
		login := s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)
		out.Login = &login
	}
	return out, nil
}

func (s publicServer) RevokeMyTOTP(ctx context.Context, req publicapi.RevokeMyTOTPRequestObject) (publicapi.RevokeMyTOTPResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.RevokeMyTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	nf, _, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		_, err := s.a.accounts.RevokeTOTP(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.RevokeMyTOTP404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	return publicapi.RevokeMyTOTP204Response{}, nil
}

func myTOTP(t port.TOTPCredential) publicapi.MyTOTP {
	return publicapi.MyTOTP{Id: t.PublicID, CreatedAt: t.CreatedAt}
}
