package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/credential"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// passkeyCookie は passkey のフロー ID を要求したブラウザにだけ渡す Cookie。
const passkeyCookie = "__Host-iam_passkey" // #nosec G101 -- Cookie の名前で、秘密ではない

// passkey は動いている passkey の方式（ADR 0106）。Relying Party が決まらない構成（public_url も rp_id も無い）か、realm の設定で
// 止めていれば nil。
func (a *App) passkey() *passkeym.Method {
	m, _ := a.methods.Get(passkeym.Name)
	pk, _ := m.(*passkeym.Method)
	return pk
}

func (s publicServer) setPasskeyCookie(ctx context.Context, flowID string, maxAge int) {
	setCookie(ctx, &http.Cookie{Name: s.a.cookie(passkeyCookie), Value: flowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// ceremony は方式のフローを応答の形にし、フロー ID を Cookie でも渡す。options は方式の Payload（{"publicKey": …}）。
func (s publicServer) ceremony(ctx context.Context, ch credential.Challenge) (publicapi.PasskeyCeremony, error) {
	var opts map[string]any
	if err := json.Unmarshal(ch.Payload, &opts); err != nil {
		return publicapi.PasskeyCeremony{}, err
	}
	s.setPasskeyCookie(ctx, ch.FlowID, max(int(ch.ExpiresAt.Sub(s.a.deps.Clock.Now())/time.Second), 1))
	return publicapi.PasskeyCeremony{FlowId: ch.FlowID, Options: opts, ExpiresAt: ch.ExpiresAt}, nil
}

// flowID は本文か Cookie のフロー ID。
func (s publicServer) passkeyFlowID(ctx context.Context, body *string) string {
	if v := deref(body); v != "" {
		return v
	}
	return cookie(ctx, s.a.cookie(passkeyCookie))
}

// passkeyPayload は方式に渡す入力（{"credential": …, "name": …}）。
func passkeyPayload(cred map[string]any, name string) (json.RawMessage, error) {
	in := map[string]any{"credential": cred}
	if name != "" {
		in["name"] = name
	}
	return json.Marshal(in)
}

func myPasskey(v passkeym.Summary) publicapi.MyPasskey {
	return publicapi.MyPasskey{Id: v.ID, Name: v.Name, CreatedAt: v.CreatedAt, LastUsedAt: v.LastUsedAt, BackupEligible: v.BackupEligible}
}

// passkeyView は authn_credentials の passkey を本人に見せる形にする。
func (a *App) passkeyView(ctx context.Context, tx port.Tx, c port.Credential) (passkeym.Summary, error) {
	mc, d, err := passkeym.Read(ctx, tx, a.pii, c)
	if err != nil {
		return passkeym.Summary{}, err
	}
	return passkeym.View(mc, d), nil
}

func (s publicServer) GetWebAuthnRelatedOrigins(context.Context, publicapi.GetWebAuthnRelatedOriginsRequestObject) (publicapi.GetWebAuthnRelatedOriginsResponseObject, error) {
	pk := s.a.passkey()
	if pk == nil {
		return publicapi.GetWebAuthnRelatedOrigins404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	origins, err := pk.RelatedOrigins()
	if err != nil {
		return nil, err
	}
	return publicapi.GetWebAuthnRelatedOrigins200JSONResponse{Origins: origins}, nil
}

// StartPasskeyLogin は passkey の1要素目を始める（方式専用の互換のパス。汎用の /v1/login/methods/passkey:begin と同じフロー）。
func (s publicServer) StartPasskeyLogin(ctx context.Context, _ publicapi.StartPasskeyLoginRequestObject) (publicapi.StartPasskeyLoginResponseObject, error) {
	if s.a.passkey() == nil {
		return publicapi.StartPasskeyLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	ch, err := s.a.credentials.Begin(ctx, s.a.realm.ID, "", passkeym.Name, port.UsageFirstFactor, nil, s.client(ctx))
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, ch)
	if err != nil {
		return nil, err
	}
	return publicapi.StartPasskeyLogin200JSONResponse(out), nil
}

func (s publicServer) FinishPasskeyLogin(ctx context.Context, req publicapi.FinishPasskeyLoginRequestObject) (publicapi.FinishPasskeyLoginResponseObject, error) {
	fail := publicapi.FinishPasskeyLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if s.a.passkey() == nil || req.Body == nil {
		return fail, nil
	}
	p, err := passkeyPayload(req.Body.Credential, "")
	if err != nil {
		return fail, nil
	}
	is, uid, err := s.a.credentials.Login(ctx, s.a.realm.ID, passkeym.Name, s.passkeyFlowID(ctx, req.Body.FlowId), p, s.client(ctx), s.a.replaceToken(ctx))
	// 失敗でもフローは使い終わったので Cookie を消す。
	s.setPasskeyCookie(ctx, "", -1)
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.FinishPasskeyLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.FinishPasskeyLogin200JSONResponse(s.loginResult(ctx, is, uid, false, req.Body.ReturnToken)), nil
}

// enrollOptions は方式専用の登録のパスの条件（汎用のパスと同じ。直近の認証は stale で確かめてある）。
func (s publicServer) enrollOptions(ctx context.Context, au auth) credential.EnrollOptions {
	return credential.EnrollOptions{Recovery: au.Restriction == port.RestrictionRecovery, RecentAuth: true, Client: s.client(ctx)}
}

func (s publicServer) StartRegisterPasskey(ctx context.Context, _ publicapi.StartRegisterPasskeyRequestObject) (publicapi.StartRegisterPasskeyResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.stale(ctx, au) {
		return publicapi.StartRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.passkey() == nil {
		return publicapi.StartRegisterPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	ch, err := s.a.credentials.EnrollBegin(ctx, s.a.realm.ID, au.PrincipalID, passkeym.Name, nil, s.enrollOptions(ctx, au))
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, ch)
	if err != nil {
		return nil, err
	}
	return publicapi.StartRegisterPasskey200JSONResponse(out), nil
}

func (s publicServer) FinishRegisterPasskey(ctx context.Context, req publicapi.FinishRegisterPasskeyRequestObject) (publicapi.FinishRegisterPasskeyResponseObject, error) {
	fail := publicapi.FinishRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if s.stale(ctx, au) {
		return publicapi.FinishRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.passkey() == nil {
		return fail, nil
	}
	name := deref(req.Body.Name)
	if name != "" {
		// 名前の誤りはフローを使う前に返すので、Cookie は消さない（直して送り直せる）。
		if _, err := account.PasskeyName(name); err != nil {
			return publicapi.FinishRegisterPasskey400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_name"}}, nil
		}
	}
	p, err := passkeyPayload(req.Body.Credential, name)
	if err != nil {
		return fail, nil
	}
	c := s.client(ctx)
	var en credential.Enrolled
	var out publicapi.FinishRegisterPasskey200JSONResponse
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if en, err = s.a.credentials.EnrollComplete(ctx, tx, credential.EnrollInput{RealmID: s.a.realm.ID, UserID: au.PrincipalID,
			Method: passkeym.Name, FlowID: s.passkeyFlowID(ctx, req.Body.FlowId), Payload: p, Actor: au.Actor(), RequestID: c.RequestID,
			KeepSession: au.SessionID}); err != nil {
			return err
		}
		v, err := s.a.passkeyView(ctx, tx, en.Credential)
		if err != nil {
			return err
		}
		m := myPasskey(v)
		out = publicapi.FinishRegisterPasskey200JSONResponse{Id: m.Id, Name: m.Name, CreatedAt: m.CreatedAt, LastUsedAt: m.LastUsedAt,
			BackupEligible: m.BackupEligible}
		out.RecoveryCodes, err = s.initialCodes(ctx, tx, au)
		return err
	})
	s.setPasskeyCookie(ctx, "", -1)
	if err != nil {
		s.a.credentials.EnrollFailed(ctx, s.a.realm.ID, passkeym.Name, c, err)
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.FinishRegisterPasskey429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	if code, ok := stateCode(err); ok {
		return publicapi.FinishRegisterPasskey409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed), errors.Is(err, errs.Invalid):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return out, nil
}

func (s publicServer) RenameMyPasskey(ctx context.Context, req publicapi.RenameMyPasskeyRequestObject) (publicapi.RenameMyPasskeyResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.RenameMyPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if req.Body == nil {
		return publicapi.RenameMyPasskey400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	var p passkeym.Summary
	nf, _, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		var err error
		p, err = s.a.accounts.RenamePasskey(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, req.Body.Name, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, account.ErrPasskeyName):
		return publicapi.RenameMyPasskey400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_name"}}, nil
	case err != nil:
		return nil, err
	case nf:
		return publicapi.RenameMyPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	return publicapi.RenameMyPasskey200JSONResponse(myPasskey(p)), nil
}

func (s publicServer) RevokeMyPasskey(ctx context.Context, req publicapi.RevokeMyPasskeyRequestObject) (publicapi.RevokeMyPasskeyResponseObject, error) {
	if au, ok := authFrom(ctx); !ok {
		return publicapi.RevokeMyPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	} else if s.stale(ctx, au) {
		return publicapi.RevokeMyPasskey401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	nf, code, err := s.change(ctx, func(ctx context.Context, tx port.Tx, au auth) error {
		_, err := s.a.accounts.RevokePasskey(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), requestID(ctx))
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case nf:
		return publicapi.RevokeMyPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case code != "":
		return publicapi.RevokeMyPasskey409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	return publicapi.RevokeMyPasskey204Response{}, nil
}
