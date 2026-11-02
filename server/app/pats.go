package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 本人の Personal Access Token（フィーチャー personal_access_tokens。ADR 0109）。作る・取り消すのは公開 API（セッション）、
// 使えるのは管理 API の Bearer・判定の API の access_token・イントロスペクション。スコープは判定の文脈で本人の権限を絞る。

// newPATs はフィーチャーが動いていれば PAT のサービスを返す。
func newPATs(cfg config.Config, d Deps, plan feature.Plan) *pat.Service {
	if !plan.IsActive(feature.PersonalAccessTokens) {
		return nil
	}
	return &pat.Service{Clock: d.Clock, Config: pat.Config{MaxPerUser: cfg.PersonalAccessTokens.MaxPerUser, MaxLifetime: cfg.PersonalAccessTokens.MaxLifetime.D()},
		Scopes: pat.ScopeRules{Valid: role.ValidPermission, Covered: role.Covered}}
}

// patContext は PAT で認証した主体の判定の文脈：amr は pat、要素は 1、認証の時刻はトークンの作成、権限はスコープに絞る。
func patContext(a pat.Authenticated) *check.AuthContext {
	return &check.AuthContext{AMR: []string{pat.AMR}, Factors: 1, AuthTime: a.Token.CreatedAt, Attested: true, Scoped: true,
		Scopes: slices.Clone(a.Scopes)}
}

// authenticatePAT は PAT を確かめる。フィーチャーが動いていなければ pat.ErrInvalid。
func (a *App) authenticatePAT(ctx context.Context, tx port.Tx, token string) (pat.Authenticated, error) {
	if a.pats == nil {
		return pat.Authenticated{}, pat.ErrInvalid
	}
	return a.pats.Authenticate(ctx, tx, a.realm.ID, token)
}

// patIntrospection は PAT のイントロスペクションの結果（RFC 7662）。使えなければ active: false。連携先に結び付かないので
// client_id・aud は出さない。
func (a *App) patIntrospection(ctx context.Context, tx port.Tx, token string) (provider.Introspection, error) {
	au, err := a.authenticatePAT(ctx, tx, token)
	if errors.Is(err, pat.ErrInvalid) {
		return provider.Introspection{}, nil
	}
	if err != nil {
		return provider.Introspection{}, err
	}
	out := provider.Introspection{Active: true, Scope: strings.Join(au.Scopes, " "), TokenType: pat.TokenType, Iat: au.Token.CreatedAt.Unix(),
		Sub: au.User.PublicID, Iss: a.issuer, AuthTime: au.Token.CreatedAt.Unix(), AMR: []string{pat.AMR}}
	if au.ExpiresAt != nil {
		out.Exp = au.ExpiresAt.Unix()
	}
	return out, nil
}

// patCleaner はフィーチャー personal_access_tokens の片付け。トークンと realm のポリシーを消す。
var patCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.PersonalAccessTokens().Count(ctx) },
	Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
		return tx.PersonalAccessTokens().Purge(ctx, limit)
	},
}

// patView は API の形（公開 API と管理 API で同じ形）。
type patView struct {
	ID, Name                         string
	Scopes                           []string
	CreatedAt                        time.Time
	ExpiresAt, LastUsedAt, RevokedAt *time.Time
	RevokeReason                     string
}

func patViewOf(t port.PersonalAccessToken) patView {
	scopes := slices.Clone(t.Scopes)
	if scopes == nil {
		scopes = []string{}
	}
	return patView{ID: t.ID, Name: t.Name, Scopes: scopes, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt,
		RevokedAt: t.RevokedAt, RevokeReason: t.RevokeReason}
}

func (v patView) public() publicapi.PersonalAccessToken {
	out := publicapi.PersonalAccessToken{Id: v.ID, Name: v.Name, Scopes: v.Scopes, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
		LastUsedAt: v.LastUsedAt, RevokedAt: v.RevokedAt}
	if v.RevokeReason != "" {
		r := publicapi.PersonalAccessTokenRevokeReason(v.RevokeReason)
		out.RevokeReason = &r
	}
	return out
}

func (v patView) admin() adminapi.PersonalAccessToken {
	out := adminapi.PersonalAccessToken{Id: v.ID, Name: v.Name, Scopes: v.Scopes, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
		LastUsedAt: v.LastUsedAt, RevokedAt: v.RevokedAt}
	if v.RevokeReason != "" {
		r := adminapi.PersonalAccessTokenRevokeReason(v.RevokeReason)
		out.RevokeReason = &r
	}
	return out
}

// patRequest は監査ログの行為者と接続元。
func (a *App) patRequest(ctx context.Context, actor audit.Actor) pat.Request {
	c := a.clientOf(ctx)
	return pat.Request{Actor: actor, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}
}

// ---------------------------------------------------------------------------
// 公開 API

func (s publicServer) ListMyPersonalAccessTokens(ctx context.Context, _ publicapi.ListMyPersonalAccessTokensRequestObject) (publicapi.ListMyPersonalAccessTokensResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyPersonalAccessTokens401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.pats == nil {
		return publicapi.ListMyPersonalAccessTokens404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var ts []port.PersonalAccessToken
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ts, err = s.a.pats.List(ctx, tx, s.a.realm.ID, au.PrincipalID)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := publicapi.ListMyPersonalAccessTokens200JSONResponse{PersonalAccessTokens: make([]publicapi.PersonalAccessToken, 0, len(ts))}
	for _, t := range ts {
		out.PersonalAccessTokens = append(out.PersonalAccessTokens, patViewOf(t).public())
	}
	return out, nil
}

func (s publicServer) CreateMyPersonalAccessToken(ctx context.Context, req publicapi.CreateMyPersonalAccessTokenRequestObject) (publicapi.CreateMyPersonalAccessTokenResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CreateMyPersonalAccessToken401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.pats == nil {
		return publicapi.CreateMyPersonalAccessToken404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.CreateMyPersonalAccessToken400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	if !s.recent(ctx, au, role.ActionMePersonalAccessTokens) {
		return publicapi.CreateMyPersonalAccessToken401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	var c pat.Created
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		c, err = s.a.pats.Create(ctx, tx, pat.CreateInput{RealmID: s.a.realm.ID, User: u, Name: req.Body.Name, Scopes: req.Body.Scopes,
			ExpiresAt: req.Body.ExpiresAt, Request: s.a.patRequest(ctx, au.Actor())})
		return err
	})
	if e, ok := errors.AsType[*errs.Error](err); ok && e.Code != "" {
		switch e.Kind {
		case errs.KindInvalid:
			return publicapi.CreateMyPersonalAccessToken400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: e.Code}}, nil
		case errs.KindConflict:
			return publicapi.CreateMyPersonalAccessToken409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: e.Code}}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return publicapi.CreateMyPersonalAccessToken201JSONResponse{Token: c.Token, PersonalAccessToken: patViewOf(c.PAT).public()}, nil
}

func (s publicServer) RevokeMyPersonalAccessToken(ctx context.Context, req publicapi.RevokeMyPersonalAccessTokenRequestObject) (publicapi.RevokeMyPersonalAccessTokenResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RevokeMyPersonalAccessToken401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.pats == nil {
		return publicapi.RevokeMyPersonalAccessToken404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, s.a.realm.ID, au.PrincipalID)
		if err != nil {
			return err
		}
		return s.a.pats.Revoke(ctx, tx, s.a.realm.ID, u, req.Id, pat.ReasonUser, s.a.patRequest(ctx, au.Actor()))
	})
	if errors.Is(err, errs.NotFound) {
		return publicapi.RevokeMyPersonalAccessToken404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RevokeMyPersonalAccessToken204Response{}, nil
}

func (s publicServer) GetMyPersonalAccessTokenPolicy(ctx context.Context, _ publicapi.GetMyPersonalAccessTokenPolicyRequestObject) (publicapi.GetMyPersonalAccessTokenPolicyResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.GetMyPersonalAccessTokenPolicy401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.pats == nil {
		return publicapi.GetMyPersonalAccessTokenPolicy404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var p pat.Policy
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		p, err = s.a.pats.Policy(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	scopes := slices.Clone(p.AllowedScopes)
	if scopes == nil {
		scopes = []string{}
	}
	return publicapi.GetMyPersonalAccessTokenPolicy200JSONResponse{MaxLifetimeSeconds: int64(s.a.pats.EffectiveMaxLifetime(p) / time.Second),
		AllowedScopes: scopes, RequireExpiry: p.RequireExpiry}, nil
}

// ---------------------------------------------------------------------------
// 管理 API

// patOff はフィーチャーが動いていなければ 404 を返す。
func (s adminServer) patOff() (outcome, bool) {
	if s.a.pats == nil {
		return failed(http.StatusNotFound, "not_found"), true
	}
	return outcome{}, false
}

func (s adminServer) ListUserPersonalAccessTokens(ctx context.Context, req adminapi.ListUserPersonalAccessTokensRequestObject) (adminapi.ListUserPersonalAccessTokensResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	o, ok, err := outcomeOf(d, err)
	if ok {
		o, ok = s.patOff()
		ok = !ok
	}
	out := adminapi.ListUserPersonalAccessTokens200JSONResponse{PersonalAccessTokens: []adminapi.PersonalAccessToken{}}
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			ts, err := s.a.pats.List(ctx, tx, s.a.realm.ID, u.ID)
			for _, t := range ts {
				out.PersonalAccessTokens = append(out.PersonalAccessTokens, patViewOf(t).admin())
			}
			return err
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListUserPersonalAccessTokens401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListUserPersonalAccessTokens403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListUserPersonalAccessTokens404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RevokeUserPersonalAccessToken(ctx context.Context, req adminapi.RevokeUserPersonalAccessTokenRequestObject) (adminapi.RevokeUserPersonalAccessTokenResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	o, ok, err := outcomeOf(d, err)
	if ok {
		o, ok = s.patOff()
		ok = !ok
	}
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			if err := s.a.outranks(ctx, tx, p, u.ID); err != nil {
				return err
			}
			return s.a.pats.Revoke(ctx, tx, s.a.realm.ID, u, req.TokenId, pat.ReasonOperator, s.a.patRequest(ctx, p.Actor))
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.RevokeUserPersonalAccessToken204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.RevokeUserPersonalAccessToken401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.RevokeUserPersonalAccessToken403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.RevokeUserPersonalAccessToken404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// patPolicyOut は管理 API のポリシーの形。
func (s adminServer) patPolicyOut(p pat.Policy) adminapi.PersonalAccessTokenPolicy {
	scopes := slices.Clone(p.AllowedScopes)
	if scopes == nil {
		scopes = []string{}
	}
	return adminapi.PersonalAccessTokenPolicy{MaxLifetimeSeconds: int64(p.MaxLifetime / time.Second), AllowedScopes: scopes, RequireExpiry: p.RequireExpiry,
		HostMaxLifetimeSeconds: int64(s.a.pats.Config.MaxLifetime / time.Second), EffectiveMaxLifetimeSeconds: int64(s.a.pats.EffectiveMaxLifetime(p) / time.Second),
		UpdatedAt: p.UpdatedAt}
}

func (s adminServer) GetPersonalAccessTokenPolicy(ctx context.Context, _ adminapi.GetPersonalAccessTokenPolicyRequestObject) (adminapi.GetPersonalAccessTokenPolicyResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermPersonalAccessTokensManage)
	o, ok, err := outcomeOf(d, err)
	if ok {
		o, ok = s.patOff()
		ok = !ok
	}
	var p pat.Policy
	if ok {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			p, err = s.a.pats.Policy(ctx, tx, s.a.realm.ID)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.GetPersonalAccessTokenPolicy200JSONResponse(s.patPolicyOut(p)), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetPersonalAccessTokenPolicy401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetPersonalAccessTokenPolicy403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetPersonalAccessTokenPolicy404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) PutPersonalAccessTokenPolicy(ctx context.Context, req adminapi.PutPersonalAccessTokenPolicyRequestObject) (adminapi.PutPersonalAccessTokenPolicyResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermPersonalAccessTokensManage)
	o, ok, err := outcomeOf(d, err)
	if ok {
		o, ok = s.patOff()
		ok = !ok
	}
	if ok && req.Body == nil {
		o, ok = failed(http.StatusBadRequest, "invalid_request"), false
	}
	var out pat.Policy
	if ok {
		b := req.Body
		if b.MaxLifetimeSeconds < 0 || b.MaxLifetimeSeconds > int64(1<<62/time.Second) {
			o, ok = failed(http.StatusBadRequest, "invalid_policy"), false
		}
	}
	if ok {
		b := req.Body
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			out, err = s.a.pats.SetPolicy(ctx, tx, s.a.realm.ID, pat.Policy{MaxLifetime: time.Duration(b.MaxLifetimeSeconds) * time.Second,
				AllowedScopes: b.AllowedScopes, RequireExpiry: b.RequireExpiry}, s.a.patRequest(ctx, p.Actor))
			return err
		})
		o, ok, err = outcomeOf(nil, err)
	}
	switch {
	case err != nil:
		return nil, err
	case ok:
		return adminapi.PutPersonalAccessTokenPolicy200JSONResponse(s.patPolicyOut(out)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.PutPersonalAccessTokenPolicy400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.PutPersonalAccessTokenPolicy401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.PutPersonalAccessTokenPolicy403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.PutPersonalAccessTokenPolicy404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
