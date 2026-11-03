package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/workloadidentity"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Workload Identity Federation（フィーチャー workload_identity。ADR 0116）の管理 API と、POST /v1/admin/token の交換。

// 交換（RFC 8693）の識別子。
const (
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          // #nosec G101 -- RFC 8693 の識別子で、秘密ではない
	tokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"     // #nosec G101 -- RFC 8693 の識別子で、秘密ではない
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- RFC 8693 の識別子で、秘密ではない
)

// workloadExchange は交換の要求を確かめ、外部の JWT を確かめて tr に結び付けを入れる。応答のエラーの code を返す（空なら続ける）。
// ストレージの障害は error。
func (s adminServer) workloadExchange(ctx context.Context, body *adminapi.IssueServiceAccountTokenFormdataRequestBody, authz string,
	tr *serviceaccount.TokenRequest) (string, error) {
	if s.a.workloadIdentity == nil {
		return "unsupported_grant_type", nil
	}
	switch {
	case authz != "" || tr.ClientSecret != "" || tr.Assertion != "" || tr.AssertionType != "" || deref(body.ActorToken) != "" ||
		deref(body.ActorTokenType) != "" || deref(body.SubjectToken) == "":
		return "invalid_request", nil
	case deref(body.SubjectTokenType) != tokenTypeJWT && deref(body.SubjectTokenType) != tokenTypeIDToken:
		return "invalid_request", nil
	case body.RequestedTokenType != nil && *body.RequestedTokenType != tokenTypeAccessToken:
		return "invalid_request", nil
	case body.Audience != nil && len(*body.Audience) > 0:
		return "invalid_target", nil
	}
	ident, err := s.a.workloadIdentity.Verify(ctx, s.a.realm.ID, *body.SubjectToken, tr.ClientID, requestID(ctx))
	if errors.Is(err, workloadidentity.ErrInvalidGrant) {
		return "invalid_grant", nil
	}
	if err != nil {
		return "", err
	}
	tr.Federated = &serviceaccount.Federated{ProviderID: ident.ProviderID, BindingID: ident.BindingID, AccountID: ident.AccountID,
		Subject: ident.Subject}
	return "", nil
}

// workloadDenied は交換で選んだサービスアカウントが使えなかったことを監査ログに残す（Token のトランザクションは巻き戻るため、別に書く）。
func (s adminServer) workloadDenied(ctx context.Context, f *serviceaccount.Federated) {
	ident := workloadidentity.Identity{ProviderID: f.ProviderID, BindingID: f.BindingID, AccountID: f.AccountID, Subject: f.Subject}
	if err := s.a.workloadIdentity.RecordDenied(ctx, s.a.realm.ID, ident, workloadidentity.DeniedUnavailable, requestID(ctx)); err != nil {
		s.a.deps.Logger.WarnContext(ctx, "workload identity: could not record a denied exchange", "error", err)
	}
}

// ---------------------------------------------------------------------------
// 管理 API。

// workloadOp は service_accounts:manage を確かめ、フィーチャーが動いていれば fn を1つのトランザクションで実行する。成功なら status は 200。
// 入力の誤りは 400 にし、メッセージを返す。
func (s adminServer) workloadOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermServiceAccountsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.workloadIdentity == nil {
		return failed(http.StatusNotFound, "workload_identity_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_request"), e.Msg)}, nil
	}
	if errors.Is(err, errOutranked) {
		return failed(http.StatusForbidden, errs.CodePermissionDenied), nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func workloadProviderOut(p port.WorkloadIdentityProvider) (adminapi.WorkloadIdentityProvider, error) {
	cfg, err := workloadidentity.ParseConfig(p.Config)
	if err != nil {
		return adminapi.WorkloadIdentityProvider{}, err
	}
	out := adminapi.WorkloadIdentityProvider{Id: p.ID, Name: p.Name, Issuer: p.Issuer, Audiences: cfg.Audiences, Algorithms: cfg.Algorithms,
		MaxTokenLifetime: cfg.MaxTokenLifetime, Disabled: p.Disabled, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	if cfg.JWKSURI != "" {
		out.JwksUri = &cfg.JWKSURI
	}
	if len(cfg.JWKS) > 0 {
		var m map[string]any
		if err := json.Unmarshal(cfg.JWKS, &m); err != nil {
			return adminapi.WorkloadIdentityProvider{}, err
		}
		out.Jwks = &m
	}
	return out, nil
}

func workloadProviderIn(b *adminapi.WorkloadIdentityProviderInput) (workloadidentity.ProviderInput, error) {
	if b == nil {
		return workloadidentity.ProviderInput{}, errs.WithCode(errs.KindInvalid, "invalid_provider", "body is required")
	}
	in := workloadidentity.ProviderInput{Name: b.Name, Issuer: b.Issuer, Config: workloadidentity.Config{Audiences: b.Audiences,
		JWKSURI: deref(b.JwksUri)}}
	if b.Disabled != nil {
		in.Disabled = *b.Disabled
	}
	if b.MaxTokenLifetime != nil {
		in.MaxTokenLifetime = *b.MaxTokenLifetime
		if in.MaxTokenLifetime == 0 {
			in.MaxTokenLifetime = -1 // 0 を明示したら既定にせず誤りにする
		}
	}
	if b.Algorithms != nil {
		for _, a := range *b.Algorithms {
			in.Algorithms = append(in.Algorithms, string(a))
		}
	}
	if b.Jwks != nil {
		raw, err := json.Marshal(*b.Jwks)
		if err != nil {
			return workloadidentity.ProviderInput{}, errs.WithCode(errs.KindInvalid, "invalid_provider", "jwks must be a JSON Web Key Set")
		}
		in.JWKS = raw
	}
	return in, nil
}

func workloadBindingOut(b port.WorkloadIdentityBinding) (adminapi.WorkloadIdentityBinding, error) {
	out := adminapi.WorkloadIdentityBinding{Id: b.ID, ProviderId: b.ProviderID, ServiceAccountId: b.ServiceAccountID, CreatedAt: b.CreatedAt,
		Conditions: []adminapi.WorkloadIdentityCondition{}}
	cs, err := workloadidentity.ParseConditions(b.Conditions)
	if err != nil {
		return adminapi.WorkloadIdentityBinding{}, err
	}
	for _, c := range cs {
		v := adminapi.WorkloadIdentityCondition{Claim: c.Claim, Equals: c.Equals, Prefix: c.Prefix}
		if c.In != nil {
			in := c.In
			v.In = &in
		}
		out.Conditions = append(out.Conditions, v)
	}
	return out, nil
}

// workloadProvider はトランザクションの中で発行者を引く。
func (s adminServer) workloadProvider(ctx context.Context, tx port.Tx, providerID string) (port.WorkloadIdentityProvider, error) {
	return tx.WorkloadIdentity().GetProvider(ctx, s.a.realm.ID, providerID)
}

func (s adminServer) ListWorkloadIdentityProviders(ctx context.Context, _ adminapi.ListWorkloadIdentityProvidersRequestObject) (adminapi.ListWorkloadIdentityProvidersResponseObject, error) {
	out := adminapi.WorkloadIdentityProviders{Providers: []adminapi.WorkloadIdentityProvider{}}
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		ps, err := tx.WorkloadIdentity().ListProviders(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, p := range ps {
			v, err := workloadProviderOut(p)
			if err != nil {
				return err
			}
			out.Providers = append(out.Providers, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListWorkloadIdentityProviders200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListWorkloadIdentityProviders401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListWorkloadIdentityProviders403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListWorkloadIdentityProviders404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateWorkloadIdentityProvider(ctx context.Context, req adminapi.CreateWorkloadIdentityProviderRequestObject) (adminapi.CreateWorkloadIdentityProviderResponseObject, error) {
	var out adminapi.WorkloadIdentityProvider
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		in, err := workloadProviderIn(req.Body)
		if err != nil {
			return err
		}
		x, err := s.a.workloadIdentity.CreateProvider(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = workloadProviderOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateWorkloadIdentityProvider201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateWorkloadIdentityProvider400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateWorkloadIdentityProvider401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateWorkloadIdentityProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateWorkloadIdentityProvider404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateWorkloadIdentityProvider409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetWorkloadIdentityProvider(ctx context.Context, req adminapi.GetWorkloadIdentityProviderRequestObject) (adminapi.GetWorkloadIdentityProviderResponseObject, error) {
	var out adminapi.WorkloadIdentityProvider
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		out, err = workloadProviderOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetWorkloadIdentityProvider200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetWorkloadIdentityProvider401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetWorkloadIdentityProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetWorkloadIdentityProvider404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateWorkloadIdentityProvider(ctx context.Context, req adminapi.UpdateWorkloadIdentityProviderRequestObject) (adminapi.UpdateWorkloadIdentityProviderResponseObject, error) {
	var out adminapi.WorkloadIdentityProvider
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		in, err := workloadProviderIn(req.Body)
		if err != nil {
			return err
		}
		// 発行者・鍵・audience を差し替えると、結び付け済みのサービスアカウントを新しい鍵の持ち主が使える。
		// 結び付けの作成と同じく、結び付け先をすべて outranks するときだけ許す。
		if err := s.outranksProviderBindings(ctx, tx, p, x.ID); err != nil {
			return err
		}
		if x, err = s.a.workloadIdentity.UpdateProvider(ctx, tx, x, in, p.Actor, requestID(ctx)); err != nil {
			return err
		}
		out, err = workloadProviderOut(x)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateWorkloadIdentityProvider200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateWorkloadIdentityProvider400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateWorkloadIdentityProvider401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateWorkloadIdentityProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateWorkloadIdentityProvider404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateWorkloadIdentityProvider409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteWorkloadIdentityProvider(ctx context.Context, req adminapi.DeleteWorkloadIdentityProviderRequestObject) (adminapi.DeleteWorkloadIdentityProviderResponseObject, error) {
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		// 結び付けも消えるので、認証情報の失効と同じく結び付け先をすべて outranks するときだけ許す。
		if err := s.outranksProviderBindings(ctx, tx, p, x.ID); err != nil {
			return err
		}
		return s.a.workloadIdentity.DeleteProvider(ctx, tx, x, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteWorkloadIdentityProvider204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteWorkloadIdentityProvider401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteWorkloadIdentityProvider403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteWorkloadIdentityProvider404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) ListWorkloadIdentityBindings(ctx context.Context, req adminapi.ListWorkloadIdentityBindingsRequestObject) (adminapi.ListWorkloadIdentityBindingsResponseObject, error) {
	out := adminapi.WorkloadIdentityBindings{Bindings: []adminapi.WorkloadIdentityBinding{}}
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		bs, err := tx.WorkloadIdentity().ListBindings(ctx, s.a.realm.ID, x.ID)
		if err != nil {
			return err
		}
		for _, b := range bs {
			v, err := workloadBindingOut(b)
			if err != nil {
				return err
			}
			out.Bindings = append(out.Bindings, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListWorkloadIdentityBindings200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListWorkloadIdentityBindings401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListWorkloadIdentityBindings403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListWorkloadIdentityBindings404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateWorkloadIdentityBinding(ctx context.Context, req adminapi.CreateWorkloadIdentityBindingRequestObject) (adminapi.CreateWorkloadIdentityBindingResponseObject, error) {
	var out adminapi.WorkloadIdentityBinding
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_conditions", "body is required")
		}
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, req.Body.ServiceAccountId)
		if err != nil {
			return err
		}
		if sa.DeletedAt != nil {
			return serviceaccount.ErrAccountDeleted
		}
		// service_accounts:manage だけで、強いサービスアカウントを外の主体に使わせない（認証情報の追加と同じ。ADR 0074）。
		if err := s.outranksServiceAccount(ctx, tx, p, sa); err != nil {
			return err
		}
		conds, err := json.Marshal(req.Body.Conditions)
		if err != nil {
			return err
		}
		b, err := s.a.workloadIdentity.CreateBinding(ctx, tx, x, sa.ID, conds, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = workloadBindingOut(b)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateWorkloadIdentityBinding201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateWorkloadIdentityBinding400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateWorkloadIdentityBinding401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateWorkloadIdentityBinding403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateWorkloadIdentityBinding404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateWorkloadIdentityBinding409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteWorkloadIdentityBinding(ctx context.Context, req adminapi.DeleteWorkloadIdentityBindingRequestObject) (adminapi.DeleteWorkloadIdentityBindingResponseObject, error) {
	o, err := s.workloadOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		x, err := s.workloadProvider(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		b, err := tx.WorkloadIdentity().GetBinding(ctx, s.a.realm.ID, req.BindingId)
		if err != nil {
			return err
		}
		if b.ProviderID != x.ID {
			return errs.New(errs.KindNotFound, "workload identity binding")
		}
		// 認証情報の失効と同じく、結び付け先を outranks するときだけ消せる。
		if err := s.outranksBoundServiceAccount(ctx, tx, p, b.ServiceAccountID); err != nil {
			return err
		}
		return s.a.workloadIdentity.DeleteBinding(ctx, tx, b, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteWorkloadIdentityBinding204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteWorkloadIdentityBinding401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteWorkloadIdentityBinding403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteWorkloadIdentityBinding404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// outranksProviderBindings は、発行者の結び付け先のサービスアカウントを、呼び出し側がすべて outranks するかを確かめる。
// service_accounts:manage だけで、強いサービスアカウントに結び付いた発行者を自分の鍵に向け直させない。
func (s adminServer) outranksProviderBindings(ctx context.Context, tx port.Tx, p adminPrincipal, providerID string) error {
	bs, err := tx.WorkloadIdentity().ListBindings(ctx, s.a.realm.ID, providerID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, b := range bs {
		if seen[b.ServiceAccountID] {
			continue
		}
		seen[b.ServiceAccountID] = true
		if err := s.outranksBoundServiceAccount(ctx, tx, p, b.ServiceAccountID); err != nil {
			return err
		}
	}
	return nil
}

// outranksBoundServiceAccount は、結び付け先のサービスアカウントを呼び出し側が outranks するかを確かめる。
// 削除済みのサービスアカウントはトークンを得られないので確かめない。
func (s adminServer) outranksBoundServiceAccount(ctx context.Context, tx port.Tx, p adminPrincipal, id string) error {
	sa, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, id)
	if errs.KindOf(err) == errs.KindNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if sa.DeletedAt != nil {
		return nil
	}
	return s.outranksServiceAccount(ctx, tx, p, sa)
}
