package app

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/loginlink"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// loginLinkTTL はログイン用リンクの既定の有効期間。
const loginLinkTTL = 15 * time.Minute

// Operator は CLI で作った運営者と、最初のログインに使うリンクのトークン。
type Operator struct {
	UserID    string // 公開 ID
	Created   bool   // 新しく登録したか（false なら既存のユーザーにロールを足した）
	LinkToken string
	ExpiresAt time.Time
}

// CreateOperator は運営者を作る（`iam operator create`。design.md 2.5）。メールの所有は CLI を実行する人が
// 確かめたものとし（経路 admin）、ロールを付与し、1回限りのログイン用リンクを発行する。
// アドレスが登録済みなら、そのユーザーにロールを足す（自動リンクではなく、運営者による明示的な操作）。
func (a *App) CreateOperator(ctx context.Context, email, roleName string, ttl time.Duration) (Operator, error) {
	return a.createOperator(ctx, email, roleName, ttl, audit.Actor{Type: "operator_cli"}, "")
}

// createOperator は CreateOperator の本体。actor と requestID は監査ログに残す。
func (a *App) createOperator(ctx context.Context, email, roleName string, ttl time.Duration, actor audit.Actor, requestID string) (Operator, error) {
	if !role.Known(roleName) || roleName == role.NotificationDelivery {
		return Operator{}, errs.New(errs.KindInvalid, "unknown operator role %q", roleName)
	}
	if err := loginlink.ValidTTL(ttl); err != nil {
		return Operator{}, errs.Wrap(errs.KindInvalid, err, "ttl")
	}
	var op Operator
	now := a.deps.Clock.Now()
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var u port.User
		c, err := a.accounts.CreateWithEmail(ctx, tx, a.realm.ID, email, port.VerifiedViaAdmin, actor, requestID)
		switch {
		case err == nil:
			u, op.Created = c.User, true
		case errors.Is(err, errs.Conflict):
			e, err := a.accounts.FindByEmail(ctx, tx, a.realm.ID, email)
			if err != nil {
				return err
			}
			if u, err = tx.Users().Get(ctx, a.realm.ID, e.UserID); err != nil {
				return err
			}
		default:
			return err
		}
		has, err := hasRole(ctx, tx, a.realm.ID, u.ID, roleName)
		if err != nil {
			return err
		}
		if !has {
			if err := role.Grant(ctx, tx, a.realm.ID, roleName, port.PrincipalUser, u.ID, now); err != nil {
				return err
			}
			if _, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
				Type: "role.granted", Result: audit.ResultSuccess, RealmID: a.realm.ID, Actor: actor, RequestID: requestID,
				Details: map[string]any{"role": roleName, "principal_type": string(port.PrincipalUser), "principal_id": u.PublicID},
			}); err != nil {
				return err
			}
		}
		op.UserID = u.PublicID
		return a.recordLoginLink(ctx, tx, actor, u.PublicID, requestID)
	})
	if err != nil {
		return Operator{}, err
	}
	op.ExpiresAt = now.Add(ttl)
	op.LinkToken, err = loginlink.Issue(ctx, a.pii, a.realm.ID, op.UserID, op.ExpiresAt)
	return op, err
}

func hasRole(ctx context.Context, tx port.Tx, realmID, userID, roleName string) (bool, error) {
	bs, err := tx.RoleBindings().ListByPrincipal(ctx, realmID, port.PrincipalUser, userID)
	for _, b := range bs {
		if b.OrgID == "" && b.Role == roleName {
			return true, err
		}
	}
	return false, err
}

// recordLoginLink は発行を監査ログに残す（トークンは残さない）。
func (a *App) recordLoginLink(ctx context.Context, tx port.Tx, actor audit.Actor, publicUserID, requestID string) error {
	_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
		Type: "login_link.issued", Result: audit.ResultSuccess, RealmID: a.realm.ID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"user_id": publicUserID},
	})
	return err
}

func adminError(code, msg string) adminapi.Error {
	e := adminapi.Error{Error: code}
	if msg != "" {
		e.Message = &msg
	}
	return e
}

func (s adminServer) CreateUser(ctx context.Context, req adminapi.CreateUserRequestObject) (adminapi.CreateUserResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersCreate)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateUser401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateUser403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.CreateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	var c account.Created
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		c, err = s.a.accounts.CreateWithEmail(ctx, tx, s.a.realm.ID, req.Body.Email, port.VerifiedViaAdmin, p.Actor, requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, errs.Conflict):
		return adminapi.CreateUser409JSONResponse(adminError("email_exists", "")), nil
	case errors.Is(err, account.ErrEmailInvalid), errors.Is(err, account.ErrViaNotAllowed):
		var e *errs.Error
		errors.As(err, &e)
		return adminapi.CreateUser400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(e.Code, ""))}, nil
	case err != nil:
		return nil, err
	}
	return adminapi.CreateUser201JSONResponse{UserId: c.User.PublicID}, nil
}

func (s adminServer) IssueLoginLink(ctx context.Context, req adminapi.IssueLoginLinkRequestObject) (adminapi.IssueLoginLinkResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersLoginLink)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.IssueLoginLink401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.IssueLoginLink403JSONResponse(d.Body), nil
	}
	ttl := loginLinkTTL
	if req.Body != nil && req.Body.TtlSeconds != nil {
		ttl, _ = loginlink.TTLSeconds(int64(*req.Body.TtlSeconds)) // 範囲の外は 0 で、次の ValidTTL が拒む
	}
	if err := loginlink.ValidTTL(ttl); err != nil {
		return adminapi.IssueLoginLink400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_ttl", err.Error()))}, nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if u.Status != port.UserActive {
			return errs.New(errs.KindNotFound, "user cannot log in")
		}
		if err := s.a.outranks(ctx, tx, p, u.ID); err != nil {
			return err
		}
		return s.a.recordLoginLink(ctx, tx, p.Actor, u.PublicID, requestID(ctx))
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.IssueLoginLink404JSONResponse(adminError("not_found", "")), nil
	}
	if errors.Is(err, errOutranked) {
		return adminapi.IssueLoginLink403JSONResponse(adminError(errs.CodePermissionDenied, "")), nil
	}
	if err != nil {
		return nil, err
	}
	exp := s.a.deps.Clock.Now().Add(ttl)
	tok, err := loginlink.Issue(ctx, s.a.pii, s.a.realm.ID, req.Id, exp)
	if err != nil {
		return nil, err
	}
	return adminapi.IssueLoginLink200JSONResponse{Token: tok, ExpiresAt: exp}, nil
}

func (s adminServer) RevokeSession(ctx context.Context, req adminapi.RevokeSessionRequestObject) (adminapi.RevokeSessionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermSessionsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.RevokeSession401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.RevokeSession403JSONResponse(d.Body), nil
	}
	err = s.a.sessions.Revoke(ctx, s.a.realm.ID, req.Id, "", session.ReasonAdmin, p.Actor, requestID(ctx))
	if errors.Is(err, errs.NotFound) {
		return adminapi.RevokeSession404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.RevokeSession204Response{}, nil
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s adminServer) CreateConnection(ctx context.Context, req adminapi.CreateConnectionRequestObject) (adminapi.CreateConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateConnection401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateConnection403JSONResponse(d.Body), nil
	}
	bad := func(msg string) adminapi.CreateConnectionResponseObject {
		return adminapi.CreateConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_connection", msg))}
	}
	if req.Body == nil {
		return bad("body is required"), nil
	}
	b := req.Body
	if !slugPattern.MatchString(b.Slug) {
		return bad("slug must match " + slugPattern.String()), nil
	}
	c, err := s.a.oauth.NewConnection(ctx, s.a.realm.ID, b.Slug, b.Preset, b.ClientId, b.ClientSecret, b.RedirectUris)
	if errors.Is(err, errs.Invalid) {
		var e *errs.Error
		errors.As(err, &e)
		return bad(e.Msg), nil
	}
	if err != nil {
		return nil, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Connections().Create(ctx, c); err != nil {
			return err
		}
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "connection.created", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "preset": b.Preset},
		})
		return err
	})
	if errors.Is(err, errs.Conflict) {
		return adminapi.CreateConnection409JSONResponse(adminError("slug_exists", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.CreateConnection201JSONResponse{Id: c.ID, Slug: c.Slug}, nil
}

// errOutranked は、対象のユーザーが呼び出し側の持たない権限のロールを持つこと。
var errOutranked = errors.New("target holds permissions the caller lacks")

// outranks は、対象になりすませる操作の前に、呼び出し側が対象のロールの権限をすべて持つかを確かめる。
func (a *App) outranks(ctx context.Context, tx port.Tx, p adminPrincipal, targetUserID string) error {
	return a.outranksPrincipal(ctx, tx, p, check.Principal{Type: port.PrincipalUser, ID: targetUserID}, "")
}

// outranksPrincipal は outranks を任意の主体に広げる。orgID が空でなければその Org の範囲の付与も比べる。
func (a *App) outranksPrincipal(ctx context.Context, tx port.Tx, p adminPrincipal, target check.Principal, orgID string) error {
	// 対象の範囲全体の権限を集め、呼び出し側がすべて持つかを確かめる（Group から効く権限も含む）。
	gs, err := a.authz.Grants(ctx, tx, a.realm.ID, target, orgID)
	if err != nil {
		return err
	}
	var need []string
	for _, g := range gs {
		if g.ResourceType == "" {
			need = append(need, g.Permissions...)
		}
	}
	ok, err := a.authz.Holds(ctx, tx, a.realm.ID, check.Principal{Type: p.Type, ID: p.ID}, orgID, need)
	if err != nil {
		return err
	}
	if !ok {
		return errOutranked
	}
	return nil
}
