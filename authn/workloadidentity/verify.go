package workloadidentity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 外部の JWT の確かめと、結び付けの選び方（ADR 0116）。

const (
	// MaxSubjectToken は subject_token の長さの上限。
	MaxSubjectToken = 16 << 10
	// leeway は時刻のずれの許容。
	leeway = 60 * time.Second
)

// 拒んだ理由（監査ログ workload_identity.exchange_denied。署名を確かめた後だけ）。
const (
	DeniedNoBinding   = "no_matching_binding"
	DeniedAmbiguous   = "ambiguous_binding"
	DeniedReplay      = "replay"
	DeniedUnavailable = "service_account_unavailable"
)

// Identity は確かめた外部の主体と、選んだ結び付け。
type Identity struct {
	ProviderID string
	BindingID  string
	AccountID  string
	// Subject は JWT の sub（監査ログ）。
	Subject string
	// Issuer は JWT の iss。
	Issuer string
}

// Verify は外部の JWT（subject_token）を確かめ、結び付けを選ぶ。accountID（要求の client_id）があれば、そのサービスアカウントの
// 結び付けに限る。確かめられなければ ErrInvalidGrant（理由はアプリケーションログと、署名を確かめた後なら監査ログに出す）。
// ストレージと EphemeralStore の障害はそれ以外のエラー。トランザクションの外で呼ぶ（JWKS の取得でネットワークに出るため）。
func (s *Service) Verify(ctx context.Context, realmID, token, accountID, requestID string) (Identity, error) {
	reject := func(reason string, err error) (Identity, error) {
		s.log().InfoContext(ctx, "workload identity: exchange rejected", "reason", reason, "error", err)
		return Identity{}, ErrInvalidGrant
	}
	if token == "" || len(token) > MaxSubjectToken {
		return reject("size", nil)
	}
	if accountID != "" && !id.Valid(id.ServiceAccount, accountID) {
		return reject("client_id", nil)
	}
	tok, err := jwt.ParseSigned(token, Algorithms)
	if err != nil || len(tok.Headers) != 1 {
		return reject("malformed", err)
	}
	var pre struct {
		Issuer string `json:"iss"`
	}
	if err := tok.UnsafeClaimsWithoutVerification(&pre); err != nil || pre.Issuer == "" {
		return reject("issuer", err)
	}
	// 署名を確かめる前に、iss で発行者を引く。知らない・止めた発行者ではネットワークに出ない。
	var p port.WorkloadIdentityProvider
	var bindings []port.WorkloadIdentityBinding
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if p, err = tx.WorkloadIdentity().GetProviderByIssuer(ctx, realmID, pre.Issuer); err != nil {
			return err
		}
		bindings, err = tx.WorkloadIdentity().ListBindings(ctx, realmID, p.ID)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return reject("unknown_issuer", nil)
	}
	if err != nil {
		return Identity{}, err
	}
	if p.Disabled {
		return reject("provider_disabled", nil)
	}
	cfg, err := ParseConfig(p.Config)
	if err != nil {
		return reject("provider_config", err)
	}
	h := tok.Headers[0]
	if !containsString(cfg.Algorithms, h.Algorithm) {
		return reject("alg", nil)
	}
	claims, raw, err := s.verifySignature(ctx, tok, p, cfg, h)
	if err != nil {
		return reject("signature", err)
	}
	now := s.now()
	if err := checkClaims(claims, p.Issuer, cfg, now); err != nil {
		return reject("claims", err)
	}
	// ここから先は、発行者が署名したトークンの拒否なので監査ログにも残す。
	ident := Identity{ProviderID: p.ID, Issuer: p.Issuer, Subject: claims.Subject}
	b, reason := selectBinding(bindings, raw, accountID)
	if reason != "" {
		return s.deny(ctx, realmID, ident, reason, requestID)
	}
	ident.BindingID, ident.AccountID = b.ID, b.ServiceAccountID
	if claims.ID != "" {
		// exp（とずれ）まで覚える。exp を過ぎたトークンは checkClaims で拒むので、それより長く覚える必要は無い。
		ok, err := s.consume(ctx, p.ID, claims.ID, max(claims.Expiry.Time().Sub(now), 0)+2*leeway)
		if err != nil {
			return Identity{}, err
		}
		if !ok {
			return s.deny(ctx, realmID, ident, DeniedReplay, requestID)
		}
	}
	return ident, nil
}

// verifySignature は鍵を選んで署名を確かめ、クレームを返す。知らない kid なら（固定の JWKS でなければ）1 回だけ取得し直す。
func (s *Service) verifySignature(ctx context.Context, tok *jwt.JSONWebToken, p port.WorkloadIdentityProvider, cfg Config,
	h jose.Header) (jwt.Claims, map[string]any, error) {
	ks, err := s.keys(ctx, p, cfg, false)
	if err != nil {
		return jwt.Claims{}, nil, err
	}
	cs := candidates(ks, h.KeyID, h.Algorithm)
	if len(cs) == 0 && len(cfg.JWKS) == 0 && h.KeyID != "" {
		if ks, err = s.keys(ctx, p, cfg, true); err != nil {
			return jwt.Claims{}, nil, err
		}
		cs = candidates(ks, h.KeyID, h.Algorithm)
	}
	for _, k := range cs {
		var claims jwt.Claims
		var raw map[string]any
		if err := tok.Claims(k.Key, &claims, &raw); err == nil {
			return claims, raw, nil
		}
	}
	return jwt.Claims{}, nil, errors.New("workload identity: no key verifies the signature")
}

// checkClaims は iss・aud・exp・nbf・iat と寿命を確かめる。
func checkClaims(c jwt.Claims, issuer string, cfg Config, now time.Time) error {
	if c.Expiry == nil || c.IssuedAt == nil {
		return errors.New("workload identity: exp and iat are required")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: cfg.Audiences, Time: now}, leeway); err != nil {
		return err
	}
	if c.Issuer != issuer {
		return jwt.ErrInvalidIssuer
	}
	limit := time.Duration(cfg.MaxTokenLifetime) * time.Second
	exp, iat := c.Expiry.Time(), c.IssuedAt.Time()
	if exp.Sub(iat) > limit || exp.Sub(now) > limit || !exp.After(iat) {
		return errors.New("workload identity: token lifetime exceeds max_token_lifetime")
	}
	return nil
}

// selectBinding は条件を満たす結び付けを選ぶ。accountID があればそのサービスアカウントのものに限る。無ければ、満たす
// 結び付けのサービスアカウントが 1 つのときだけ選ぶ。選べなければ理由を返す。読めない条件の結び付けは使わない。
func selectBinding(bs []port.WorkloadIdentityBinding, claims map[string]any, accountID string) (port.WorkloadIdentityBinding, string) {
	var found []port.WorkloadIdentityBinding
	for _, b := range bs {
		if accountID != "" && b.ServiceAccountID != accountID {
			continue
		}
		cs, err := ParseConditions(b.Conditions)
		if err != nil || !MatchAll(cs, claims) {
			continue
		}
		found = append(found, b)
	}
	if len(found) == 0 {
		return port.WorkloadIdentityBinding{}, DeniedNoBinding
	}
	for _, b := range found[1:] {
		if b.ServiceAccountID != found[0].ServiceAccountID {
			return port.WorkloadIdentityBinding{}, DeniedAmbiguous
		}
	}
	return found[0], ""
}

// consume は発行者の jti を使用済みにする。2 回目なら false。
func (s *Service) consume(ctx context.Context, providerID, jti string, ttl time.Duration) (bool, error) {
	h := sha256.Sum256([]byte(providerID + "\x00" + jti))
	n, err := s.Cache.Incr(ctx, "wif:jti:v1:"+base64.RawURLEncoding.EncodeToString(h[:]), ttl)
	if err != nil {
		return false, errs.Wrap(errs.KindUnavailable, err, "workload identity: jti replay")
	}
	return n == 1, nil
}

// deny は署名を確かめた後の拒否を監査ログ（workload_identity.exchange_denied）に残し、ErrInvalidGrant を返す。
func (s *Service) deny(ctx context.Context, realmID string, ident Identity, reason, requestID string) (Identity, error) {
	if err := s.RecordDenied(ctx, realmID, ident, reason, requestID); err != nil {
		return Identity{}, err
	}
	s.log().InfoContext(ctx, "workload identity: exchange denied", "reason", reason, "provider_id", ident.ProviderID)
	return Identity{}, ErrInvalidGrant
}

// RecordDenied は交換の拒否を監査ログに残す（サービスアカウントが使えないときは呼び出し側が呼ぶ）。
func (s *Service) RecordDenied(ctx context.Context, realmID string, ident Identity, reason, requestID string) error {
	details := map[string]any{"provider_id": ident.ProviderID, "issuer": ident.Issuer, "external_subject": ident.Subject, "reason": reason}
	if ident.BindingID != "" {
		details["binding_id"], details["service_account_id"] = ident.BindingID, ident.AccountID
	}
	return s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: "workload_identity.exchange_denied", Result: audit.ResultFailure,
			RealmID: realmID, Actor: audit.Actor{Type: "anonymous"}, RequestID: requestID, Details: details})
		return err
	})
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
