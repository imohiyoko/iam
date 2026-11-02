package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/imohiyoko/iam/authn/credential"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	totpm "github.com/imohiyoko/iam/authn/method/totp"
	"github.com/imohiyoko/iam/authn/session"
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
	// RP-Initiated Logout（ADR 0094）。POST /v1/logout と同じく、どの制限つきのセッションでもログアウトできる。
	"GET " + oidcEndSession:         allRestrictions,
	"POST " + oidcEndSession:        allRestrictions,
	"POST " + oidcEndSessionConfirm: allRestrictions,
}

var allRestrictions = []port.SessionRestriction{port.RestrictionSecondFactor, port.RestrictionEnroll, port.RestrictionRecovery, port.RestrictionDeletion}

func restrictionAllows(r port.SessionRestriction, method, path string) bool {
	return r == port.RestrictionNone || slices.Contains(restrictedAllowed[method+" "+path], r) || methodRestricted(r, method, path)
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
	if s.a.passkey() == nil {
		return publicapi.StartSecondFactorPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	// 汎用の方式（ADR 0106）。フロー ID は汎用の `/v1/login/second-factor/passkey:complete` でも使える。
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, au.PrincipalID, passkeym.Name, port.UsageSecondFactor, nil, s.client(ctx))
	if errors.Is(err, errs.NotFound) {
		return publicapi.StartSecondFactorPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, ch)
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
	if code := deref(req.Body.TotpCode); code != "" {
		// TOTP は汎用の方式（ADR 0101）を、フロー無しの1回の要求で呼ぶ。
		p, err := json.Marshal(map[string]string{"code": code})
		if err != nil {
			return nil, err
		}
		is, err := s.a.credentials.SecondFactorOnce(ctx, s.a.realm.ID, au.PrincipalID, au.SessionID, totpm.Name, p,
			credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
		if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			return publicapi.VerifySecondFactor429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
		}
		if d, ok := errors.AsType[errs.Denial](err); ok {
			return publicapi.VerifySecondFactor403JSONResponse{DeniedJSONResponse: denied(d)}, nil
		}
		switch {
		case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, session.ErrNotRestricted), errors.Is(err, credential.ErrUnknownMethod):
			return fail, nil
		case err != nil:
			return nil, err
		}
		return publicapi.VerifySecondFactor200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)), nil
	}
	if req.Body.Credential == nil || s.a.passkey() == nil {
		return fail, nil
	}
	// passkey は汎用の方式（ADR 0106）を、方式専用の開始（second-factor/passkey:start）のフローで呼ぶ。
	p, err := passkeyPayload(*req.Body.Credential, "")
	if err != nil {
		return fail, nil
	}
	is, err := s.a.credentials.SecondFactor(ctx, s.a.realm.ID, au.PrincipalID, au.SessionID, passkeym.Name, s.passkeyFlowID(ctx, req.Body.FlowId), p,
		credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
	// 失敗でもフローは使い終わったので Cookie を消す。
	s.setPasskeyCookie(ctx, "", -1)
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.VerifySecondFactor429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.VerifySecondFactor403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid), errors.Is(err, session.ErrNotRestricted), errors.Is(err, credential.ErrUnknownMethod):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.VerifySecondFactor200JSONResponse(s.loginResult(ctx, is, au.PublicID, false, req.Body.ReturnToken)), nil
}

func (s publicServer) StartRegisterTOTP(ctx context.Context, _ publicapi.StartRegisterTOTPRequestObject) (publicapi.StartRegisterTOTPResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.stale(ctx, au) {
		return publicapi.StartRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	// 汎用の方式の登録（ADR 0101）。フロー ID は汎用の `/v1/me/credentials/totp:enroll-complete` でも使える。
	ch, err := s.a.credentials.EnrollBegin(ctx, s.a.realm.ID, au.PrincipalID, totpm.Name, nil, credential.EnrollOptions{RecentAuth: true})
	if code, ok := stateCode(err); ok {
		return publicapi.StartRegisterTOTP409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	if err := json.Unmarshal(ch.Payload, &out); err != nil {
		return nil, err
	}
	return publicapi.StartRegisterTOTP200JSONResponse{FlowId: ch.FlowID, Secret: out.Secret, Uri: out.URI, ExpiresAt: ch.ExpiresAt}, nil
}

func (s publicServer) ConfirmRegisterTOTP(ctx context.Context, req publicapi.ConfirmRegisterTOTPRequestObject) (publicapi.ConfirmRegisterTOTPResponseObject, error) {
	fail := publicapi.ConfirmRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if s.stale(ctx, au) {
		return publicapi.ConfirmRegisterTOTP401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	c := s.a.clientOf(ctx)
	p, err := json.Marshal(map[string]string{"code": req.Body.Code})
	if err != nil {
		return nil, err
	}
	var t port.Credential
	var is session.Issued
	var codes *[]string
	upgrade := au.Restriction == port.RestrictionEnroll
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		en, err := s.a.credentials.EnrollComplete(ctx, tx, credential.EnrollInput{RealmID: s.a.realm.ID, UserID: au.PrincipalID,
			Method: totpm.Name, FlowID: req.Body.FlowId, Payload: p, Actor: au.Actor(), RequestID: c.RequestID})
		if err != nil {
			return err
		}
		t = en.Credential
		if codes, err = s.initialCodes(ctx, tx, au); err != nil || !upgrade {
			return err
		}
		// 登録だけのセッションは、登録に使ったコードを2要素目として通常のセッションに替える。
		is, err = s.a.sessions.CompleteSecondFactor(ctx, tx, s.a.realm.ID, au.SessionID, session.SecondFactor{
			AMR: []string{totpm.AMR}, CredentialID: t.ID, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
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
	if au, ok := authFrom(ctx); !ok {
		return publicapi.RevokeMyTOTP401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	} else if s.stale(ctx, au) {
		return publicapi.RevokeMyTOTP401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
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

func myTOTP(t port.Credential) publicapi.MyTOTP {
	return publicapi.MyTOTP{Id: t.PublicID, CreatedAt: t.CreatedAt}
}
