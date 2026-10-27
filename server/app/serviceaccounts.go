package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 汎用サービスアカウントの管理 API と、client credentials のトークンのエンドポイント（design.md 11.2、ADR 0074）。

// serviceAccountsOff はフィーチャー service_accounts が動いていなければ 404 を返す。
func (s adminServer) serviceAccountsOff() (outcome, bool) {
	if !s.a.serviceAccounts.Enabled {
		return failed(http.StatusNotFound, "service_accounts_disabled"), true
	}
	return outcome{}, false
}

// manageServiceAccount は権限 service_accounts:manage を確かめ、トランザクションの中で ID のサービスアカウントを fn に渡す。
func (s adminServer) manageServiceAccount(ctx context.Context, saID string, fn func(ctx context.Context, tx port.Tx, p adminPrincipal, sa port.ServiceAccount) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermServiceAccountsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if o, off := s.serviceAccountsOff(); off {
		return o, nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, saID)
		if err != nil {
			return err
		}
		return fn(ctx, tx, p, sa)
	})
	o, _, err := outcomeOf(nil, err)
	return o, err
}

func (s adminServer) serviceAccountView(ctx context.Context, tx port.Tx, sa port.ServiceAccount) (adminapi.ServiceAccount, error) {
	v := adminapi.ServiceAccount{Id: sa.ID, Name: sa.Name, ValidFrom: sa.ValidFrom, ValidUntil: sa.ValidUntil, CreatedAt: sa.CreatedAt,
		Deleted: sa.DeletedAt != nil, DeletedAt: sa.DeletedAt}
	if sa.CreatedBy != "" {
		v.CreatedBy = &sa.CreatedBy
	}
	if sa.OrgID != "" {
		o, err := tx.Orgs().Get(ctx, sa.RealmID, sa.OrgID)
		if err != nil {
			return adminapi.ServiceAccount{}, err
		}
		v.OrgId = &o.PublicID
	}
	return v, nil
}

func (s adminServer) credentialView(c port.ServiceAccountCredential) adminapi.ServiceAccountCredential {
	now := s.a.deps.Clock.Now()
	v := adminapi.ServiceAccountCredential{Id: c.ID, Type: adminapi.ServiceAccountCredentialType(c.Type), CreatedAt: c.CreatedAt,
		ExpiresAt: c.ExpiresAt, RevokedAt: c.RevokedAt, Active: c.RevokedAt == nil && (c.ExpiresAt == nil || now.Before(*c.ExpiresAt))}
	if c.Alg != "" {
		v.Alg = &c.Alg
	}
	if len(c.PublicKey) > 0 {
		var k map[string]any
		if json.Unmarshal(c.PublicKey, &k) == nil {
			v.PublicKey = &k
		}
	}
	return v
}

func (s adminServer) ListServiceAccounts(ctx context.Context, req adminapi.ListServiceAccountsRequestObject) (adminapi.ListServiceAccountsResponseObject, error) {
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	_, d, err := s.a.authorize(ctx, role.PermServiceAccountsManage)
	o, ok, err := outcomeOf(d, err)
	if ok {
		if off, isOff := s.serviceAccountsOff(); isOff {
			o, ok = off, false
		} else if limit < 1 || limit > 200 {
			o, ok = outcome{status: http.StatusBadRequest, body: adminError("invalid_request", "limit must be within [1, 200]")}, false
		}
	}
	out := adminapi.ListServiceAccounts200JSONResponse{ServiceAccounts: []adminapi.ServiceAccount{}}
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			// 1件多く取り、続きがあるかを知る。
			ss, err := tx.ServiceAccounts().List(ctx, s.a.realm.ID, deref(req.Params.After), limit+1)
			if err != nil {
				return err
			}
			if len(ss) > limit {
				ss = ss[:limit]
				next := ss[limit-1].ID
				out.NextCursor = &next
			}
			for _, sa := range ss {
				v, err := s.serviceAccountView(ctx, tx, sa)
				if err != nil {
					return err
				}
				out.ServiceAccounts = append(out.ServiceAccounts, v)
			}
			return nil
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return out, nil
	case o.status == http.StatusBadRequest:
		return adminapi.ListServiceAccounts400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListServiceAccounts401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.ListServiceAccounts403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListServiceAccounts404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateServiceAccount(ctx context.Context, req adminapi.CreateServiceAccountRequestObject) (adminapi.CreateServiceAccountResponseObject, error) {
	var out adminapi.ServiceAccount
	o, err := func() (outcome, error) {
		if req.Body == nil {
			return failed(http.StatusBadRequest, "invalid_request"), nil
		}
		p, d, err := s.a.authorize(ctx, role.PermServiceAccountsManage)
		if o, ok, err := outcomeOf(d, err); !ok {
			return o, err
		}
		if o, off := s.serviceAccountsOff(); off {
			return o, nil
		}
		if o, off := s.orgsOff(req.Body.OrgId != nil); off {
			return o, nil
		}
		in := serviceaccount.Input{Name: req.Body.Name, ValidFrom: req.Body.ValidFrom, ValidUntil: req.Body.ValidUntil}
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			if req.Body.OrgId != nil {
				o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *req.Body.OrgId)
				if errors.Is(err, errs.NotFound) || (err == nil && o.DeletedAt != nil) {
					return errs.WithCode(errs.KindInvalid, "invalid_org", "org not found")
				}
				if err != nil {
					return err
				}
				if err := org.Suspendable(o); err != nil {
					return errs.WithCode(errs.KindInvalid, "invalid_org", "personal org")
				}
				in.Org = &o
			}
			sa, err := s.a.serviceAccounts.Create(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
			if err != nil {
				return err
			}
			out, err = s.serviceAccountView(ctx, tx, sa)
			return err
		})
		o, ok, err := outcomeOf(nil, err)
		if ok {
			o.status = http.StatusCreated
		}
		return o, err
	}()
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusCreated:
		return adminapi.CreateServiceAccount201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateServiceAccount400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateServiceAccount401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateServiceAccount403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateServiceAccount404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetServiceAccount(ctx context.Context, req adminapi.GetServiceAccountRequestObject) (adminapi.GetServiceAccountResponseObject, error) {
	var out adminapi.ServiceAccount
	o, err := s.manageServiceAccount(ctx, req.Id, func(ctx context.Context, tx port.Tx, _ adminPrincipal, sa port.ServiceAccount) error {
		var err error
		out, err = s.serviceAccountView(ctx, tx, sa)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == 0:
		return adminapi.GetServiceAccount200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetServiceAccount401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetServiceAccount403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetServiceAccount404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteServiceAccount(ctx context.Context, req adminapi.DeleteServiceAccountRequestObject) (adminapi.DeleteServiceAccountResponseObject, error) {
	var out adminapi.ServiceAccount
	o, err := s.manageServiceAccount(ctx, req.Id, func(ctx context.Context, tx port.Tx, p adminPrincipal, sa port.ServiceAccount) error {
		sa, err := s.a.serviceAccounts.Delete(ctx, tx, sa, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = s.serviceAccountView(ctx, tx, sa)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == 0:
		return adminapi.DeleteServiceAccount200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteServiceAccount401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteServiceAccount403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteServiceAccount404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListServiceAccountCredentials(ctx context.Context, req adminapi.ListServiceAccountCredentialsRequestObject) (adminapi.ListServiceAccountCredentialsResponseObject, error) {
	out := adminapi.ListServiceAccountCredentials200JSONResponse{Credentials: []adminapi.ServiceAccountCredential{}}
	o, err := s.manageServiceAccount(ctx, req.Id, func(ctx context.Context, tx port.Tx, _ adminPrincipal, sa port.ServiceAccount) error {
		cs, err := tx.ServiceAccounts().ListCredentials(ctx, s.a.realm.ID, sa.ID)
		for _, c := range cs {
			out.Credentials = append(out.Credentials, s.credentialView(c))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == 0:
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListServiceAccountCredentials401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListServiceAccountCredentials403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListServiceAccountCredentials404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateServiceAccountCredential(ctx context.Context, req adminapi.CreateServiceAccountCredentialRequestObject) (adminapi.CreateServiceAccountCredentialResponseObject, error) {
	var out adminapi.ServiceAccountCredential
	var o outcome
	var err error
	if req.Body == nil {
		o = failed(http.StatusBadRequest, "invalid_request")
	} else {
		in := serviceaccount.CredentialInput{Type: string(req.Body.Type), ExpiresAt: req.Body.ExpiresAt}
		if req.Body.Alg != nil {
			in.Alg = string(*req.Body.Alg)
		}
		if req.Body.PublicKey != nil {
			if in.PublicKey, err = json.Marshal(*req.Body.PublicKey); err != nil {
				return nil, err
			}
		}
		o, err = s.manageServiceAccount(ctx, req.Id, func(ctx context.Context, tx port.Tx, p adminPrincipal, sa port.ServiceAccount) error {
			c, secret, err := s.a.serviceAccounts.AddCredential(ctx, tx, sa, in, p.Actor, requestID(ctx))
			if err != nil {
				return err
			}
			out = s.credentialView(c)
			if secret != "" {
				out.Secret = &secret
			}
			return nil
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == 0:
		return adminapi.CreateServiceAccountCredential201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateServiceAccountCredential400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateServiceAccountCredential401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateServiceAccountCredential403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateServiceAccountCredential404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateServiceAccountCredential409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RevokeServiceAccountCredential(ctx context.Context, req adminapi.RevokeServiceAccountCredentialRequestObject) (adminapi.RevokeServiceAccountCredentialResponseObject, error) {
	var out adminapi.ServiceAccountCredential
	o, err := s.manageServiceAccount(ctx, req.Id, func(ctx context.Context, tx port.Tx, p adminPrincipal, sa port.ServiceAccount) error {
		c, err := s.a.serviceAccounts.RevokeCredential(ctx, tx, sa, req.CredentialId, p.Actor, requestID(ctx))
		out = s.credentialView(c)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == 0:
		return adminapi.RevokeServiceAccountCredential200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.RevokeServiceAccountCredential401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.RevokeServiceAccountCredential403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.RevokeServiceAccountCredential404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// serviceAccountSubject は停止の対象のサービスアカウント（削除済みは対象にしない）。
func (s adminServer) serviceAccountSubject(saID string) resolveFunc {
	return func(ctx context.Context, tx port.Tx) (subject, error) {
		sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, saID)
		if err == nil && sa.DeletedAt != nil {
			err = errs.New(errs.KindNotFound, "service account")
		}
		return subject{target: serviceaccount.Target(sa)}, err
	}
}

func (s adminServer) SuspendServiceAccount(ctx context.Context, req adminapi.SuspendServiceAccountRequestObject) (adminapi.SuspendServiceAccountResponseObject, error) {
	out, o, err := s.suspend(ctx, req.Body, false, s.serviceAccountSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SuspendServiceAccount200JSONResponse(out), nil
	case o.status == http.StatusCreated:
		return adminapi.SuspendServiceAccount201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SuspendServiceAccount400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SuspendServiceAccount401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SuspendServiceAccount403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SuspendServiceAccount404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.SuspendServiceAccount409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListServiceAccountSuspensions(ctx context.Context, req adminapi.ListServiceAccountSuspensionsRequestObject) (adminapi.ListServiceAccountSuspensionsResponseObject, error) {
	out, o, err := s.listSuspensions(ctx, false, s.serviceAccountSubject(req.Id))
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListServiceAccountSuspensions200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListServiceAccountSuspensions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListServiceAccountSuspensions403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListServiceAccountSuspensions404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// IssueServiceAccountToken は client credentials のトークンのエンドポイント（RFC 6749 4.4、RFC 7523）。
func (s adminServer) IssueServiceAccountToken(ctx context.Context, req adminapi.IssueServiceAccountTokenRequestObject) (adminapi.IssueServiceAccountTokenResponseObject, error) {
	if o, off := s.serviceAccountsOff(); off {
		return adminapi.IssueServiceAccountToken404JSONResponse(o.body), nil
	}
	if req.Body == nil {
		return adminapi.IssueServiceAccountToken400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	tr := serviceaccount.TokenRequest{GrantType: req.Body.GrantType, ClientID: deref(req.Body.ClientId), ClientSecret: deref(req.Body.ClientSecret),
		AssertionType: deref(req.Body.ClientAssertionType), Assertion: deref(req.Body.ClientAssertion)}
	if h := deref(req.Params.Authorization); h != "" {
		id, secret, ok := basicAuth(h)
		if !ok || tr.ClientSecret != "" || (tr.ClientID != "" && tr.ClientID != id) {
			return adminapi.IssueServiceAccountToken400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
		}
		tr.ClientID, tr.ClientSecret = id, secret
	}
	var is serviceaccount.Issued
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		is, err = s.a.serviceAccounts.Token(ctx, tx, s.a.realm.ID, tr, requestID(ctx))
		return err
	})
	switch {
	case errors.Is(err, serviceaccount.ErrInvalidClient):
		return adminapi.IssueServiceAccountToken401JSONResponse(adminError("invalid_client", "")), nil
	case errors.Is(err, errs.Invalid):
		return adminapi.IssueServiceAccountToken400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCode(err), ""))}, nil
	case err != nil:
		return nil, err
	}
	noStore := "no-store"
	out := adminapi.IssueServiceAccountToken200JSONResponse{Headers: adminapi.IssueServiceAccountToken200ResponseHeaders{CacheControl: &noStore}}
	out.Body.AccessToken, out.Body.TokenType, out.Body.ExpiresIn = is.Token, "Bearer", int(is.ExpiresIn.Seconds())
	return out, nil
}

// basicAuth は client_secret_basic（RFC 6749 2.3.1。client_id と client_secret は form-urlencoded してから Basic にする）を読む。
func basicAuth(h string) (string, string, bool) {
	raw, ok := strings.CutPrefix(h, "Basic ")
	if !ok {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	u, p, ok := strings.Cut(string(b), ":")
	if !ok {
		return "", "", false
	}
	id, err1 := url.QueryUnescape(u)
	secret, err2 := url.QueryUnescape(p)
	return id, secret, ok && err1 == nil && err2 == nil && id != "" && secret != ""
}

// deliveryOnly は通知の配信用のサービスアカウント（realm に属し、ロールの付与が system:notification_delivery だけ）かを返す（2.4）。
func deliveryOnly(ctx context.Context, tx port.Tx, sa port.ServiceAccount) (bool, error) {
	if sa.OrgID != "" {
		return false, nil
	}
	bs, err := tx.RoleBindings().ListByPrincipal(ctx, sa.RealmID, port.PrincipalServiceAccount, sa.ID)
	if err != nil {
		return false, err
	}
	for _, b := range bs {
		if b.Role != role.NotificationDelivery {
			return false, nil
		}
	}
	return len(bs) > 0, nil
}

// CreatedServiceAccount は CLI で作ったサービスアカウントと、1回だけ表示する API キー。
type CreatedServiceAccount struct {
	ID, APIKey string
}

// CreateServiceAccount は CLI（`iam service-account create`）でサービスアカウントを作り、roleName を付与して API キーを返す。
// フィーチャー service_accounts が動いていなければ、通知の配信用（system:notification_delivery）だけを作れる（2.4）。
func (a *App) CreateServiceAccount(ctx context.Context, name, roleName string) (CreatedServiceAccount, error) {
	if !role.Known(roleName) {
		return CreatedServiceAccount{}, errs.New(errs.KindInvalid, "unknown role %q", roleName)
	}
	if roleName != role.NotificationDelivery && !a.serviceAccounts.Enabled {
		return CreatedServiceAccount{}, errs.New(errs.KindInvalid, "feature service_accounts is not active: only %s can be created", role.NotificationDelivery)
	}
	actor := audit.Actor{Type: "operator_cli"}
	var out CreatedServiceAccount
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		sa, err := a.serviceAccounts.Create(ctx, tx, a.realm.ID, serviceaccount.Input{Name: name}, actor, "")
		if err != nil {
			return err
		}
		if out.APIKey, err = serviceaccount.AddKey(ctx, tx, a.realm.ID, sa.ID, a.deps.Clock.Now()); err != nil {
			return err
		}
		out.ID = sa.ID
		if err := role.Grant(ctx, tx, a.realm.ID, roleName, port.PrincipalServiceAccount, sa.ID, a.deps.Clock.Now()); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "role.granted", Result: audit.ResultSuccess, RealmID: a.realm.ID, Actor: actor,
			Details: map[string]any{"role": roleName, "principal_type": string(port.PrincipalServiceAccount), "principal_id": sa.ID},
		})
		return err
	})
	return out, err
}
