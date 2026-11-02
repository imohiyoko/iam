package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Token Exchange（RFC 8693）の委任となりすまし（フィーチャー token_exchange・impersonation。ADR 0099）。

// TokenExchange は token エンドポイントの交換（grant_type=urn:ietf:params:oauth:grant-type:token-exchange）。
// 連携先の認証と grant_type の許可（交換を許した連携先だけ）は op が VerifyClient と GrantTypes で確かめた。
func (s *oidcServer) TokenExchange(ctx context.Context, r *op.ClientRequest[oidc.TokenExchangeRequest]) (*op.Response, error) {
	cl := r.Client.(opClient).c
	if !s.a.tokens.TokenExchange {
		return nil, oidc.ErrUnsupportedGrantType()
	}
	d := r.Data
	in := provider.ExchangeRequest{SubjectToken: d.SubjectToken, SubjectTokenType: string(d.SubjectTokenType), ActorToken: d.ActorToken,
		ActorTokenType: string(d.ActorTokenType), RequestedTokenType: string(d.RequestedTokenType), Audiences: d.Audience, Resources: d.Resource,
		Scopes: d.Scopes}
	if r.Form != nil {
		in.RequestedSubject = r.Form.Get("requested_subject")
	}
	var out provider.Issued
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.tokens.ExchangeToken(ctx, tx, cl, in, requestID(ctx))
		return err
	})
	if denied, ok := errors.AsType[*provider.ImpersonationDenied](err); ok {
		return nil, s.impersonationDenied(ctx, denied)
	}
	switch {
	case errors.Is(err, provider.ErrInvalidGrant):
		return nil, oidc.ErrInvalidGrant()
	case errors.Is(err, provider.ErrExchangeNotAllowed):
		return nil, oidc.ErrUnauthorizedClient().WithDescription("token exchange is not allowed for this client")
	case errors.Is(err, provider.ErrInvalidTarget):
		return nil, oidc.ErrInvalidTarget().WithDescription("audience is not allowed")
	case errors.Is(err, provider.ErrInvalidScope):
		return nil, oidc.ErrInvalidScope().WithDescription("scope exceeds the subject token")
	case errors.Is(err, provider.ErrUnsupportedTokenType):
		return nil, oidc.ErrInvalidRequest().WithDescription("unsupported token type")
	case err != nil:
		return nil, s.fail(ctx, err)
	}
	// #nosec G115 -- ExpiresIn は正の寿命
	resp := op.NewResponse(&oidc.TokenExchangeResponse{AccessToken: out.AccessToken, IssuedTokenType: oidc.AccessTokenType, TokenType: oidc.BearerToken,
		ExpiresIn: uint64(out.ExpiresIn / time.Second), Scopes: out.Scopes})
	resp.Header.Set("Pragma", "no-cache")
	return resp, nil
}

// impersonationDenied は拒んだなりすましを監査ログに残し、OAuth のエラーにする。理由は返さない。step-up が要るときだけ、
// 連携先が運営者に再認証を促せるように説明を付ける。
func (s *oidcServer) impersonationDenied(ctx context.Context, d *provider.ImpersonationDenied) error {
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.a.tokens.RecordImpersonationDenied(ctx, tx, d, requestID(ctx))
	})
	if err != nil {
		s.a.deps.Logger.WarnContext(ctx, "oidc: could not record denied impersonation", "error", err)
	}
	switch d.Reason {
	case provider.ImpersonationDeniedStepUp:
		return oidc.ErrInvalidGrant().WithDescription("step-up authentication required")
	case provider.ImpersonationDeniedRateLimit:
		return op.NewStatusError(oidc.ErrInvalidRequest().WithDescription("too many requests"), http.StatusTooManyRequests)
	}
	return oidc.ErrInvalidGrant()
}

// exchangeGrantTypes は交換を許した連携先の grant_type（op が grant_type の許可を確かめるのに使う）。
func exchangeGrantTypes() []oidc.GrantType {
	return append(slices.Clone(grantTypes), oidc.GrantTypeTokenExchange)
}

// authorizeImpersonation は運営者がなりすましてよいかを確かめる（provider.Impersonation.Authorize）。拒むなら理由を返す。
// 順に、運営者ごとのレートリミット、step-up（直近の認証と要素の数）、権限 users:impersonate（認証の文脈と名前空間の要件。
// ADR 0084）、対象のロールの権限をすべて持つこと（outranks。ADR 0052）。
func (a *App) authorizeImpersonation(ctx context.Context, tx port.Tx, in provider.ImpersonationCheck) (string, error) {
	if err := a.impersonationLimit.Allow(ctx, "impersonation:"+a.realm.ID+":"+in.Operator.ID); err != nil {
		if _, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			return provider.ImpersonationDeniedRateLimit, nil
		}
		return "", err
	}
	im, sess := a.cfg.OIDC.Impersonation, in.Session
	if a.deps.Clock.Now().Sub(sess.AuthenticatedAt) > im.MaxAuthAge.D() || check.Factors(sess.AuthMethods) < im.MinFactors {
		return provider.ImpersonationDeniedStepUp, nil
	}
	risk, err := session.Risk(ctx, tx, sess)
	if err != nil {
		return "", err
	}
	actx := &check.AuthContext{AMR: sess.AuthMethods, Factors: check.Factors(sess.AuthMethods), AuthTime: sess.AuthenticatedAt, Risk: risk, Attested: true}
	caller := check.Principal{Type: port.PrincipalUser, ID: in.Operator.ID}
	ok, err := a.authz.CheckTx(ctx, tx, a.realm.ID, check.Request{Principal: caller, Action: role.PermUsersImpersonate, Context: actx})
	if err != nil {
		return "", err
	}
	if !ok {
		return provider.ImpersonationDeniedPermission, nil
	}
	if in.Target.ID == "" {
		return "", nil
	}
	err = a.outranks(ctx, tx, adminPrincipal{Type: port.PrincipalUser, ID: in.Operator.ID, Context: actx}, in.Target.ID)
	if errors.Is(err, errOutranked) {
		return provider.ImpersonationDeniedOutranked, nil
	}
	return "", err
}

// ---------------------------------------------------------------------------
// 管理 API：連携先に許す交換。

func exchangePolicyOut(p provider.ExchangePolicy) adminapi.TokenExchangePolicy {
	out := adminapi.TokenExchangePolicy{Audiences: p.Audiences}
	if out.Audiences == nil {
		out.Audiences = []string{}
	}
	if len(p.SubjectClients) > 0 {
		sc := slices.Clone(p.SubjectClients)
		out.SubjectClients = &sc
	}
	if p.Impersonation {
		out.Impersonation = &p.Impersonation
	}
	return out
}

// exchangeOff はフィーチャー token_exchange が動いていなければ 404 token_exchange_disabled を返す。
func (s adminServer) exchangeOff() (outcome, bool) {
	if !s.a.tokens.TokenExchange {
		return failed(http.StatusNotFound, "token_exchange_disabled"), true
	}
	return outcome{}, false
}

func (s adminServer) GetClientTokenExchange(ctx context.Context, req adminapi.GetClientTokenExchangeRequestObject) (adminapi.GetClientTokenExchangeResponseObject, error) {
	var out adminapi.TokenExchangePolicy
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		if o, off := s.exchangeOff(); off {
			return outcomeError{o}
		}
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		p, _ := provider.ParseExchangePolicy(c.TokenExchange)
		out = exchangePolicyOut(p)
		return nil
	})
	o, err = unwrapOutcome(o, err)
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetClientTokenExchange200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetClientTokenExchange401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetClientTokenExchange403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetClientTokenExchange404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) SetClientTokenExchange(ctx context.Context, req adminapi.SetClientTokenExchangeRequestObject) (adminapi.SetClientTokenExchangeResponseObject, error) {
	var out adminapi.TokenExchangePolicy
	o, err := s.clientOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if o, off := s.exchangeOff(); off {
			return outcomeError{o}
		}
		if req.Body == nil {
			return provider.ErrInvalidClient
		}
		in := provider.ExchangePolicy{Audiences: req.Body.Audiences}
		if req.Body.SubjectClients != nil {
			in.SubjectClients = *req.Body.SubjectClients
		}
		if req.Body.Impersonation != nil {
			in.Impersonation = *req.Body.Impersonation
		}
		c, err := tx.Clients().GetByPublicID(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		_, np, err := s.a.clients.SetTokenExchange(ctx, tx, c, in, s.a.tokens.Impersonation != nil, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		if np != nil {
			out = exchangePolicyOut(*np)
		} else {
			out = exchangePolicyOut(provider.ExchangePolicy{})
		}
		return nil
	})
	o, err = unwrapOutcome(o, err)
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.SetClientTokenExchange200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.SetClientTokenExchange400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.SetClientTokenExchange401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.SetClientTokenExchange403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.SetClientTokenExchange404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// outcomeError はトランザクションの中から決まった応答を返すためのエラー（clientOp の fn から返す）。
type outcomeError struct{ o outcome }

func (e outcomeError) Error() string { return "admin outcome " + e.o.body.Error }

// unwrapOutcome は outcomeError を応答の状態に戻す。
func unwrapOutcome(o outcome, err error) (outcome, error) {
	if e, ok := errors.AsType[outcomeError](err); ok {
		return e.o, nil
	}
	return o, err
}

// ---------------------------------------------------------------------------
// フィーチャーの無効化（11.12）：交換の認可と、連携先の許可を片付ける。

// eachExchangePolicy は全 realm の連携先の許可に fn を呼び、true を返した数を数える。purge なら許可を書き換える
// （fn が許可を変え、変えた許可を保存する）。limit が 0 以上なら、その数で止める。
func eachExchangePolicy(ctx context.Context, tx port.Tx, limit int, now time.Time, purge bool,
	fn func(p *provider.ExchangePolicy) bool) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		cs, err := tx.Clients().List(ctx, r.ID)
		if err != nil {
			return n, err
		}
		for _, c := range cs {
			if len(c.TokenExchange) == 0 {
				continue
			}
			if limit >= 0 && n >= limit {
				return n, nil
			}
			p, ok := provider.ParseExchangePolicy(c.TokenExchange)
			// 読めない許可は何も許さないので、片付けの対象にする。
			if ok && !fn(&p) {
				continue
			}
			n++
			if !purge {
				continue
			}
			c.TokenExchange, c.UpdatedAt = nil, now
			if ok && len(p.Audiences) > 0 {
				if c.TokenExchange, err = json.Marshal(p); err != nil {
					return n, err
				}
			}
			if err := tx.Clients().Update(ctx, c); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// exchangeCleaner はフィーチャー token_exchange の片付け。連携先の許可（なりすましの許可も）と、交換の認可を消す。
var exchangeCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachExchangePolicy(ctx, tx, -1, time.Time{}, false, func(*provider.ExchangePolicy) bool { return true })
		if err != nil {
			return 0, err
		}
		for _, k := range []string{port.ExchangeDelegation, port.ExchangeImpersonation} {
			c, err := tx.Grants().CountExchanged(ctx, k)
			if err != nil {
				return 0, err
			}
			n += c
		}
		return n, nil
	},
	Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachExchangePolicy(ctx, tx, limit, now, true, func(p *provider.ExchangePolicy) bool {
			*p = provider.ExchangePolicy{}
			return true
		})
		for _, k := range []string{port.ExchangeDelegation, port.ExchangeImpersonation} {
			if err != nil || n >= limit {
				return n, err
			}
			var c int
			c, err = tx.Grants().PurgeExchanged(ctx, k, limit-n)
			n += c
		}
		return n, err
	},
}

// impersonationCleaner はフィーチャー impersonation の片付け。連携先のなりすましの許可と、なりすましの認可を消す。
var impersonationCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachExchangePolicy(ctx, tx, -1, time.Time{}, false, func(p *provider.ExchangePolicy) bool { return p.Impersonation })
		if err != nil {
			return 0, err
		}
		c, err := tx.Grants().CountExchanged(ctx, port.ExchangeImpersonation)
		return n + c, err
	},
	Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachExchangePolicy(ctx, tx, limit, now, true, func(p *provider.ExchangePolicy) bool {
			was := p.Impersonation
			p.Impersonation = false
			return was
		})
		if err != nil || n >= limit {
			return n, err
		}
		c, err := tx.Grants().PurgeExchanged(ctx, port.ExchangeImpersonation, limit-n)
		return n + c, err
	},
}
