package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 運営者による認証情報の無効化（design.md 4.6、ADR 0052）。

func (s adminServer) ListUserCredentials(ctx context.Context, req adminapi.ListUserCredentialsRequestObject) (adminapi.ListUserCredentialsResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ListUserCredentials401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.ListUserCredentials403JSONResponse(d.Body), nil
	}
	out := adminapi.UserCredentials{Passkeys: []adminapi.UserPasskey{}, Identities: []adminapi.UserIdentity{}, Totp: []adminapi.UserTOTP{}}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		m, err := s.a.accounts.ListMethods(ctx, tx, s.a.realm.ID, u.ID)
		if err != nil {
			return err
		}
		slugs, err := connectionSlugs(ctx, tx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, p := range m.Passkeys {
			out.Passkeys = append(out.Passkeys, adminapi.UserPasskey{Id: p.PublicID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
		}
		for _, i := range m.Identities {
			out.Identities = append(out.Identities, adminapi.UserIdentity{Id: i.PublicID, Connection: slugs[i.ConnectionID], CreatedAt: i.CreatedAt})
		}
		for _, t := range m.TOTP {
			out.Totp = append(out.Totp, adminapi.UserTOTP{Id: t.PublicID, CreatedAt: t.CreatedAt})
		}
		if m.Password != nil {
			out.Password = &adminapi.UserPassword{CreatedAt: m.Password.CreatedAt}
		}
		return nil
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.ListUserCredentials404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.ListUserCredentials200JSONResponse(out), nil
}

func (s adminServer) RevokeUserCredential(ctx context.Context, req adminapi.RevokeUserCredentialRequestObject) (adminapi.RevokeUserCredentialResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.RevokeUserCredential401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.RevokeUserCredential403JSONResponse(d.Body), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.accounts.AdminRevokeCredential(ctx, tx, s.a.realm.ID, u, req.CredentialId, p.Actor, requestID(ctx))
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.RevokeUserCredential404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.RevokeUserCredential204Response{}, nil
}

// revokeUserSessions はユーザーの全セッションを失効させ、その数を返す。
func (s adminServer) revokeUserSessions(ctx context.Context, userID string, p adminPrincipal) (int, error) {
	ids, err := s.a.sessions.RevokeAll(ctx, s.a.realm.ID, userID, "", session.ReasonAdmin, p.Actor, requestID(ctx))
	return len(ids), err
}

func (s adminServer) RevokeUserPassword(ctx context.Context, req adminapi.RevokeUserPasswordRequestObject) (adminapi.RevokeUserPasswordResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.RevokeUserPassword401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.RevokeUserPassword403JSONResponse(d.Body), nil
	}
	var u port.User
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		return s.a.accounts.AdminRevokePassword(ctx, tx, s.a.realm.ID, u, p.Actor, requestID(ctx))
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.RevokeUserPassword404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	// パスワードはセッションの認証情報に入れないので、全セッションを失効させる（ADR 0051）。
	if _, err := s.revokeUserSessions(ctx, u.ID, p); err != nil {
		return nil, err
	}
	return adminapi.RevokeUserPassword204Response{}, nil
}

func (s adminServer) RevokeAllUserCredentials(ctx context.Context, req adminapi.RevokeAllUserCredentialsRequestObject) (adminapi.RevokeAllUserCredentialsResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.RevokeAllUserCredentials401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.RevokeAllUserCredentials403JSONResponse(d.Body), nil
	}
	var u port.User
	var r account.Revoked
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		r, err = s.a.accounts.RevokeAllCredentials(ctx, tx, s.a.realm.ID, u, p.Actor, requestID(ctx))
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.RevokeAllUserCredentials404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	n, err := s.revokeUserSessions(ctx, u.ID, p)
	if err != nil {
		return nil, err
	}
	return adminapi.RevokeAllUserCredentials200JSONResponse{Passkeys: r.Passkeys, Identities: r.Identities, Totp: r.TOTP,
		Password: r.Password, Sessions: n}, nil
}
