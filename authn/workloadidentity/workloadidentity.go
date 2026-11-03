// Package workloadidentity は Workload Identity Federation（フィーチャー workload_identity。ADR 0116）。
//
// CI・Kubernetes・クラウドの基盤がワークロードに渡す署名付きの JWT を、発行者（issuer・aud・鍵）と結び付け（条件と
// サービスアカウント）で確かめ、サービスアカウントのアクセストークン（ADR 0074）に替える。交換の入口は `POST /v1/admin/token`
// の RFC 8693 で、トークンの発行は authn/serviceaccount が受け持つ。JWKS は発行者の Discovery から公開のアドレスに限って取得するか、
// 固定の JWKS を登録する。
package workloadidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー workload_identity の宣言（既定オフ。サービスアカウントに依存する。ADR 0089、0116）。
var Feature = feature.Feature{Name: feature.WorkloadIdentity, DataVersion: 1, Requires: []string{feature.ServiceAccounts}}

// 上限と既定。
const (
	MaxNameLength      = 100
	MaxURLLength       = 2048
	MaxAudiences       = 10
	MaxAudienceLength  = 1024
	MaxBindings        = 100
	DefaultMaxLifetime = 3600  // 秒
	MinMaxLifetime     = 60    // 秒
	MaxMaxLifetime     = 86400 // 秒
	maxStaticJWKS      = 64 << 10
)

var (
	// ErrIssuerExists は realm の中で issuer が重複する。
	ErrIssuerExists = errs.WithCode(errs.KindConflict, "issuer_exists", "a workload identity provider with this issuer exists")
	// ErrTooManyBindings は発行者の結び付けが上限に達した。
	ErrTooManyBindings = errs.WithCode(errs.KindConflict, "too_many_bindings", "too many bindings for this provider")
	// ErrInvalidGrant は交換を拒む（RFC 6749 5.2）。理由は返さない。
	ErrInvalidGrant = errs.WithCode(errs.KindInvalid, "invalid_grant", "invalid grant")
)

func invalidProvider(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_provider", "invalid provider: "+msg)
}

// Config は発行者の設定（authn_workload_identity_providers の config。JSON）。
type Config struct {
	// Audiences は JWT の aud が含むべき値（どれか 1 つ）。
	Audiences []string `json:"audiences"`
	// JWKSURI は鍵の URL（Discovery を飛ばす）。JWKS とは併せない。
	JWKSURI string `json:"jwks_uri,omitempty"`
	// JWKS は固定の鍵（ネットワークに出ない）。
	JWKS json.RawMessage `json:"jwks,omitempty"`
	// Algorithms は受け付ける署名の方式（Algorithms の部分集合）。
	Algorithms []string `json:"algorithms"`
	// MaxTokenLifetime は exp − iat と、今から exp までの上限（秒）。
	MaxTokenLifetime int `json:"max_token_lifetime"`
}

// ProviderInput は作る・置き換える発行者。
type ProviderInput struct {
	Name     string
	Issuer   string
	Disabled bool
	Config
}

// ParseConfig は保存した設定を読む。読めない設定は使わない（fail closed）。
func ParseConfig(b []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	if len(c.Audiences) == 0 || len(c.Algorithms) == 0 || c.MaxTokenLifetime <= 0 {
		return Config{}, errors.New("workload identity: incomplete provider config")
	}
	return c, nil
}

// ValidHTTPSURL は s が https の絶対 URL（ホストあり、クエリ・フラグメント・利用者情報なし）かを返す。
func ValidHTTPSURL(s string) bool {
	if s == "" || len(s) > MaxURLLength {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" &&
		u.Fragment == "" && !u.ForceQuery && !strings.Contains(s, "#") && u.Opaque == ""
}

// ValidateProvider は入力を確かめ、既定を補う。
func ValidateProvider(in ProviderInput) (ProviderInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > MaxNameLength {
		return in, invalidProvider("name is required and at most 100 characters")
	}
	if !ValidHTTPSURL(in.Issuer) {
		return in, invalidProvider("issuer must be an https URL without query, fragment or user info")
	}
	if len(in.Audiences) == 0 || len(in.Audiences) > MaxAudiences {
		return in, invalidProvider("audiences must have 1 to 10 values")
	}
	auds := make([]string, 0, len(in.Audiences))
	for _, a := range in.Audiences {
		if a == "" || len(a) > MaxAudienceLength {
			return in, invalidProvider("audiences must be non-empty strings of at most 1024 bytes")
		}
		if !slices.Contains(auds, a) {
			auds = append(auds, a)
		}
	}
	in.Audiences = auds
	if in.JWKSURI != "" && len(in.JWKS) > 0 {
		return in, invalidProvider("jwks and jwks_uri cannot both be set")
	}
	if in.JWKSURI != "" && !ValidHTTPSURL(in.JWKSURI) {
		return in, invalidProvider("jwks_uri must be an https URL without query, fragment or user info")
	}
	if len(in.JWKS) > 0 {
		if len(in.JWKS) > maxStaticJWKS {
			return in, invalidProvider("jwks is too large")
		}
		if _, err := parseKeySet(in.JWKS, true); err != nil {
			return in, err
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, in.JWKS); err != nil {
			return in, invalidProvider("jwks must be a JSON Web Key Set")
		}
		in.JWKS = compact.Bytes()
	}
	if len(in.Algorithms) == 0 {
		in.Algorithms = slices.Clone(DefaultAlgorithms)
	}
	algs := make([]string, 0, len(in.Algorithms))
	for _, a := range in.Algorithms {
		if !allowedAlg(a) {
			return in, invalidProvider("algorithms must be among RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA")
		}
		if !slices.Contains(algs, a) {
			algs = append(algs, a)
		}
	}
	in.Algorithms = algs
	if in.MaxTokenLifetime == 0 {
		in.MaxTokenLifetime = DefaultMaxLifetime
	}
	if in.MaxTokenLifetime < MinMaxLifetime || in.MaxTokenLifetime > MaxMaxLifetime {
		return in, invalidProvider("max_token_lifetime must be within [60, 86400] seconds")
	}
	return in, nil
}

// Service は発行者と結び付けの管理、外部の JWT の確かめ。
type Service struct {
	Storage port.Storage
	// Cache は取得した JWKS、取得の回数の上限、jti の 1 回だけの扱い（共有できる EphemeralStore）。
	Cache port.EphemeralStore
	Clock clock.Clock
	// HTTP は JWKS の取得に使うクライアント（テスト用）。nil なら公開のアドレスに限るクライアント。
	HTTP *http.Client
	// AllowPrivateNetworks は公開でないアドレスの発行者を許す（開発ビルドだけ）。
	AllowPrivateNetworks bool
	Log                  *slog.Logger

	once    sync.Once
	guarded *http.Client
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) record(ctx context.Context, tx port.Tx, typ, realmID string, actor audit.Actor, requestID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor,
		RequestID: requestID, Details: details})
	return err
}

func apply(p port.WorkloadIdentityProvider, in ProviderInput) (port.WorkloadIdentityProvider, error) {
	b, err := json.Marshal(in.Config)
	if err != nil {
		return p, err
	}
	p.Name, p.Issuer, p.Disabled, p.Config = in.Name, in.Issuer, in.Disabled, b
	return p, nil
}

func providerDetails(p port.WorkloadIdentityProvider) map[string]any {
	return map[string]any{"provider_id": p.ID, "issuer": p.Issuer, "name": p.Name, "disabled": p.Disabled}
}

// CreateProvider は発行者を作る（監査ログ workload_identity.provider.created）。
func (s *Service) CreateProvider(ctx context.Context, tx port.Tx, realmID string, in ProviderInput, actor audit.Actor, requestID string) (port.WorkloadIdentityProvider, error) {
	in, err := ValidateProvider(in)
	if err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	now := s.Clock.Now()
	p, err := apply(port.WorkloadIdentityProvider{ID: id.NewExternal(id.WorkloadIdentityProvider), RealmID: realmID, CreatedAt: now, UpdatedAt: now}, in)
	if err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	if err := tx.WorkloadIdentity().CreateProvider(ctx, p); errors.Is(err, errs.Conflict) {
		return port.WorkloadIdentityProvider{}, ErrIssuerExists
	} else if err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	return p, s.record(ctx, tx, "workload_identity.provider.created", realmID, actor, requestID, providerDetails(p))
}

// UpdateProvider は発行者を置き換える（監査ログ workload_identity.provider.updated）。止めれば、発行済みのトークンも次の検証から使えない。
func (s *Service) UpdateProvider(ctx context.Context, tx port.Tx, p port.WorkloadIdentityProvider, in ProviderInput, actor audit.Actor, requestID string) (port.WorkloadIdentityProvider, error) {
	in, err := ValidateProvider(in)
	if err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	if p, err = apply(p, in); err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	p.UpdatedAt = s.Clock.Now()
	if err := tx.WorkloadIdentity().UpdateProvider(ctx, p); errors.Is(err, errs.Conflict) {
		return port.WorkloadIdentityProvider{}, ErrIssuerExists
	} else if err != nil {
		return port.WorkloadIdentityProvider{}, err
	}
	return p, s.record(ctx, tx, "workload_identity.provider.updated", p.RealmID, actor, requestID, providerDetails(p))
}

// DeleteProvider は発行者とその結び付けを消す（監査ログ workload_identity.provider.deleted）。
func (s *Service) DeleteProvider(ctx context.Context, tx port.Tx, p port.WorkloadIdentityProvider, actor audit.Actor, requestID string) error {
	if err := tx.WorkloadIdentity().DeleteProvider(ctx, p.RealmID, p.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, "workload_identity.provider.deleted", p.RealmID, actor, requestID, providerDetails(p))
}

// CreateBinding は発行者 p の結び付けを作る（監査ログ workload_identity.binding.created）。サービスアカウントが使えること
// （削除していない）と、呼び出し側がそのロールの権限をすべて持つことは呼び出し側が確かめる。
func (s *Service) CreateBinding(ctx context.Context, tx port.Tx, p port.WorkloadIdentityProvider, serviceAccountID string, conditions []byte,
	actor audit.Actor, requestID string) (port.WorkloadIdentityBinding, error) {
	cs, err := ParseConditions(conditions)
	if err != nil {
		return port.WorkloadIdentityBinding{}, err
	}
	b, err := MarshalConditions(cs)
	if err != nil {
		return port.WorkloadIdentityBinding{}, err
	}
	existing, err := tx.WorkloadIdentity().ListBindings(ctx, p.RealmID, p.ID)
	if err != nil {
		return port.WorkloadIdentityBinding{}, err
	}
	if len(existing) >= MaxBindings {
		return port.WorkloadIdentityBinding{}, ErrTooManyBindings
	}
	x := port.WorkloadIdentityBinding{ID: id.NewExternal(id.WorkloadIdentityBinding), RealmID: p.RealmID, ProviderID: p.ID,
		ServiceAccountID: serviceAccountID, Conditions: b, CreatedAt: s.Clock.Now()}
	if err := tx.WorkloadIdentity().CreateBinding(ctx, x); err != nil {
		return port.WorkloadIdentityBinding{}, err
	}
	return x, s.record(ctx, tx, "workload_identity.binding.created", p.RealmID, actor, requestID, bindingDetails(x, cs))
}

// DeleteBinding は結び付けを消す（監査ログ workload_identity.binding.deleted）。発行済みのトークンも次の検証から使えない。
func (s *Service) DeleteBinding(ctx context.Context, tx port.Tx, b port.WorkloadIdentityBinding, actor audit.Actor, requestID string) error {
	if err := tx.WorkloadIdentity().DeleteBinding(ctx, b.RealmID, b.ID); err != nil {
		return err
	}
	cs, _ := ParseConditions(b.Conditions)
	return s.record(ctx, tx, "workload_identity.binding.deleted", b.RealmID, actor, requestID, bindingDetails(b, cs))
}

func bindingDetails(b port.WorkloadIdentityBinding, cs []Condition) map[string]any {
	claims := make([]string, 0, len(cs))
	for _, c := range cs {
		claims = append(claims, c.Claim)
	}
	return map[string]any{"binding_id": b.ID, "provider_id": b.ProviderID, "service_account_id": b.ServiceAccountID, "claims": claims}
}

// BindingLive は結び付けが残っていて、発行者が止まっていなければ、そのサービスアカウントの ID と true を返す
// （serviceaccount.Federation。発行済みのトークンの検証のたびに呼ぶ）。
func (s *Service) BindingLive(ctx context.Context, tx port.Tx, realmID, bindingID string) (string, bool, error) {
	if !id.Valid(id.WorkloadIdentityBinding, bindingID) {
		return "", false, nil
	}
	b, err := tx.WorkloadIdentity().GetBinding(ctx, realmID, bindingID)
	if errors.Is(err, errs.NotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	p, err := tx.WorkloadIdentity().GetProvider(ctx, realmID, b.ProviderID)
	if errors.Is(err, errs.NotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if p.Disabled {
		return "", false, nil
	}
	return b.ServiceAccountID, true, nil
}

// now は Clock の今。
func (s *Service) now() time.Time { return s.Clock.Now() }
