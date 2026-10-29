package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// passkeyCookie は passkey のフロー ID を要求したブラウザにだけ渡す Cookie。
const passkeyCookie = "__Host-iam_passkey" // #nosec G101 -- Cookie の名前で、秘密ではない

func (s publicServer) passkeyClient(ctx context.Context) passkey.Client {
	c := s.a.clientOf(ctx)
	return passkey.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}
}

func setPasskeyCookie(ctx context.Context, flowID string, maxAge int) {
	setCookie(ctx, &http.Cookie{Name: passkeyCookie, Value: flowID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// ceremony はフローを応答の形にし、フロー ID を Cookie でも渡す。
func (s publicServer) ceremony(ctx context.Context, st passkey.Started) (publicapi.PasskeyCeremony, error) {
	var opts map[string]any
	if err := json.Unmarshal(st.Options, &opts); err != nil {
		return publicapi.PasskeyCeremony{}, err
	}
	setPasskeyCookie(ctx, st.FlowID, max(int(st.ExpiresAt.Sub(s.a.deps.Clock.Now())/time.Second), 1))
	return publicapi.PasskeyCeremony{FlowId: st.FlowID, Options: opts, ExpiresAt: st.ExpiresAt}, nil
}

// flowID は本文か Cookie のフロー ID。
func passkeyFlowID(ctx context.Context, body *string) string {
	if v := deref(body); v != "" {
		return v
	}
	return cookie(ctx, passkeyCookie)
}

func myPasskey(p port.Passkey) publicapi.MyPasskey {
	return publicapi.MyPasskey{Id: p.PublicID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
		BackupEligible: p.Flags&0x08 != 0}
}

func (s publicServer) GetWebAuthnRelatedOrigins(context.Context, publicapi.GetWebAuthnRelatedOriginsRequestObject) (publicapi.GetWebAuthnRelatedOriginsResponseObject, error) {
	if s.a.passkeys == nil {
		return publicapi.GetWebAuthnRelatedOrigins404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	origins, err := s.a.passkeys.RelatedOrigins()
	if err != nil {
		return nil, err
	}
	return publicapi.GetWebAuthnRelatedOrigins200JSONResponse{Origins: origins}, nil
}

func (s publicServer) StartPasskeyLogin(ctx context.Context, _ publicapi.StartPasskeyLoginRequestObject) (publicapi.StartPasskeyLoginResponseObject, error) {
	if s.a.passkeys == nil {
		return publicapi.StartPasskeyLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	st, err := s.a.passkeys.BeginLogin(ctx, s.a.realm.ID)
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, st)
	if err != nil {
		return nil, err
	}
	return publicapi.StartPasskeyLogin200JSONResponse(out), nil
}

func (s publicServer) FinishPasskeyLogin(ctx context.Context, req publicapi.FinishPasskeyLoginRequestObject) (publicapi.FinishPasskeyLoginResponseObject, error) {
	fail := publicapi.FinishPasskeyLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if s.a.passkeys == nil || req.Body == nil {
		return fail, nil
	}
	resp, err := json.Marshal(req.Body.Credential)
	if err != nil {
		return fail, nil
	}
	in := passkey.Login{FlowID: passkeyFlowID(ctx, req.Body.FlowId), Response: resp, Client: s.passkeyClient(ctx)}
	if tok, viaCookie := s.a.sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	res, err := s.a.passkeys.FinishLogin(ctx, s.a.realm.ID, in)
	// 失敗でもフローは使い終わったので Cookie を消す。
	setPasskeyCookie(ctx, "", -1)
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.FinishPasskeyLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.FinishPasskeyLogin200JSONResponse(s.loginResult(ctx, res.Session, res.UserID, false, req.Body.ReturnToken)), nil
}

func (s publicServer) StartRegisterPasskey(ctx context.Context, _ publicapi.StartRegisterPasskeyRequestObject) (publicapi.StartRegisterPasskeyResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.StartRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.stale(au) {
		return publicapi.StartRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.passkeys == nil {
		return publicapi.StartRegisterPasskey404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	st, err := s.a.passkeys.BeginRegister(ctx, s.a.realm.ID, au.PrincipalID)
	if err != nil {
		return nil, err
	}
	out, err := s.ceremony(ctx, st)
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
	if s.stale(au) {
		return publicapi.FinishRegisterPasskey401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.passkeys == nil {
		return fail, nil
	}
	resp, err := json.Marshal(req.Body.Credential)
	if err != nil {
		return fail, nil
	}
	in := passkey.Register{FlowID: passkeyFlowID(ctx, req.Body.FlowId), Response: resp, Name: deref(req.Body.Name), Client: s.passkeyClient(ctx)}
	p, err := s.a.passkeys.FinishRegister(ctx, s.a.realm.ID, au.PrincipalID, in)
	if errors.Is(err, account.ErrPasskeyName) {
		// 名前の誤りはフローを使う前に返すので、Cookie は消さない（直して送り直せる）。
		return publicapi.FinishRegisterPasskey400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_name"}}, nil
	}
	setPasskeyCookie(ctx, "", -1)
	if code, ok := stateCode(err); ok {
		return publicapi.FinishRegisterPasskey409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: code}}, nil
	}
	switch {
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	m := myPasskey(p)
	out := publicapi.FinishRegisterPasskey200JSONResponse{Id: m.Id, Name: m.Name, CreatedAt: m.CreatedAt, LastUsedAt: m.LastUsedAt,
		BackupEligible: m.BackupEligible}
	// passkey は別のトランザクションで登録済み。コードを作れなくても登録は成功で、本人は作り直せる。
	if err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out.RecoveryCodes, err = s.initialCodes(ctx, tx, au)
		return err
	}); err != nil {
		s.a.deps.Logger.WarnContext(ctx, "could not issue recovery codes", "error", err)
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
	var p port.Passkey
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
	} else if s.stale(au) {
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
