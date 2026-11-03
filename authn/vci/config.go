package vci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 資格情報の定義（Credential Configuration。ADR 0119）。

// クレームの出どころ。
const (
	SourceUserID        = "user_id"
	SourceEmail         = "email"
	SourceEmailVerified = "email_verified"
	SourceConst         = "const"
	// SourceAttributePrefix の後ろにカスタム属性のキーを付ける（attribute:<key>）。
	SourceAttributePrefix = "attribute:"
)

// 有効期間。
const (
	DefaultValidity = 90 * 24 * time.Hour
	MinValidity     = time.Hour
	MaxValidity     = 5 * 365 * 24 * time.Hour
)

// 大きさの上限。
const (
	maxClaims     = 64
	maxDisplays   = 16
	maxVCT        = 256
	maxText       = 256
	maxConstValue = 4 << 10
)

// Display は表示名（メタデータの display）。
type Display struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
}

// Claim は資格情報のクレーム（最上位）の対応。
type Claim struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Value は Source が const のときの値（JSON）。
	Value json.RawMessage `json:"value,omitempty"`
	// SelectivelyDisclosable は選択的に開示できるクレームにするか。
	SelectivelyDisclosable bool      `json:"selectively_disclosable"`
	Mandatory              bool      `json:"mandatory,omitempty"`
	Display                []Display `json:"display,omitempty"`
}

// Config は定義の設定（vci_credential_configurations.config）。
type Config struct {
	Format        string    `json:"format"`
	VCT           string    `json:"vct"`
	Display       []Display `json:"display,omitempty"`
	Claims        []Claim   `json:"claims"`
	ValiditySecs  int64     `json:"validity"`
	RequireTxCode bool      `json:"require_tx_code,omitempty"`
}

// Validity は有効期間。
func (c Config) Validity() time.Duration { return time.Duration(c.ValiditySecs) * time.Second }

// Input は管理 API の入力。
type Input struct {
	ConfigurationID string
	Scope           string
	Format          string
	VCT             string
	Display         []Display
	Claims          []ClaimInput
	// Validity は有効期間（0 なら既定）。
	Validity      time.Duration
	RequireTxCode bool
}

// ClaimInput はクレームの入力。SelectivelyDisclosable が nil なら真。
type ClaimInput struct {
	Name                   string
	Source                 string
	Value                  json.RawMessage
	SelectivelyDisclosable *bool
	Mandatory              bool
	Display                []Display
}

var (
	configurationIDRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	// scopeRE は RFC 6749 3.3 の scope-token（空白と " と \ を除く印字できる ASCII）。
	scopeRE     = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,128}$`)
	claimNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	localeRE    = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`)
)

// reservedClaims は名前にできないクレーム（SD-JWT VC と SD-JWT が決めるもの）。
var reservedClaims = append(slices.Clone(sdjwt.Reserved), "iat", "_sd", "_sd_alg", "...")

// reservedScopes は定義のスコープにできない名前（OIDC と iam のスコープ）。
var reservedScopes = []string{"openid", "email", "attributes", "profile", "address", "phone", "offline_access"}

func invalid(format string, a ...any) error {
	return errs.WithCode(errs.KindInvalid, codeInvalidCredentialConfiguration, fmt.Sprintf(format, a...))
}

func validText(s string) bool {
	if s == "" || len(s) > maxText || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validDisplays(ds []Display) error {
	if len(ds) > maxDisplays {
		return invalid("too many display entries")
	}
	seen := map[string]bool{}
	for _, d := range ds {
		if !validText(d.Name) {
			return invalid("display name must be 1-%d printable characters", maxText)
		}
		if d.Locale != "" && !localeRE.MatchString(d.Locale) {
			return invalid("display locale %q is not a language tag", d.Locale)
		}
		if seen[d.Locale] {
			return invalid("display locale %q appears twice", d.Locale)
		}
		seen[d.Locale] = true
	}
	return nil
}

// validate は入力を確かめ、保存する設定を返す。
func validate(in Input) (Config, error) {
	if !configurationIDRE.MatchString(in.ConfigurationID) {
		return Config{}, invalid("configuration_id must be 1-128 characters of A-Z a-z 0-9 . _ : -")
	}
	if in.Scope != "" {
		if !scopeRE.MatchString(in.Scope) {
			return Config{}, invalid("scope must be a single scope token")
		}
		if slices.Contains(reservedScopes, in.Scope) {
			return Config{}, invalid("scope %q is reserved", in.Scope)
		}
	}
	if in.Format != FormatSDJWT {
		return Config{}, errs.WithCode(errs.KindInvalid, codeUnsupportedFormat, fmt.Sprintf("format %q is not supported (only %s)", in.Format, FormatSDJWT))
	}
	if !validText(in.VCT) || len(in.VCT) > maxVCT || strings.ContainsAny(in.VCT, " ") {
		return Config{}, invalid("vct must be 1-%d printable characters without spaces", maxVCT)
	}
	if err := validDisplays(in.Display); err != nil {
		return Config{}, err
	}
	validity := in.Validity
	if validity == 0 {
		validity = DefaultValidity
	}
	if validity < MinValidity || validity > MaxValidity || validity%time.Second != 0 {
		return Config{}, invalid("validity must be whole seconds between %s and %s", MinValidity, MaxValidity)
	}
	if len(in.Claims) == 0 || len(in.Claims) > maxClaims {
		return Config{}, invalid("claims must have 1-%d entries", maxClaims)
	}
	c := Config{Format: in.Format, VCT: in.VCT, Display: in.Display, ValiditySecs: int64(validity / time.Second), RequireTxCode: in.RequireTxCode}
	seen := map[string]bool{}
	for _, x := range in.Claims {
		cl, err := validateClaim(x)
		if err != nil {
			return Config{}, err
		}
		if seen[cl.Name] {
			return Config{}, invalid("claim %q appears twice", cl.Name)
		}
		seen[cl.Name] = true
		c.Claims = append(c.Claims, cl)
	}
	return c, nil
}

func validateClaim(x ClaimInput) (Claim, error) {
	if !claimNameRE.MatchString(x.Name) || slices.Contains(reservedClaims, x.Name) {
		return Claim{}, invalid("claim name %q is not allowed", x.Name)
	}
	if err := validDisplays(x.Display); err != nil {
		return Claim{}, err
	}
	cl := Claim{Name: x.Name, Source: x.Source, SelectivelyDisclosable: x.SelectivelyDisclosable == nil || *x.SelectivelyDisclosable,
		Mandatory: x.Mandatory, Display: x.Display}
	switch {
	case x.Source == SourceUserID, x.Source == SourceEmail, x.Source == SourceEmailVerified:
	case strings.HasPrefix(x.Source, SourceAttributePrefix):
		if !attributeKeyRE.MatchString(strings.TrimPrefix(x.Source, SourceAttributePrefix)) {
			return Claim{}, invalid("claim %q: attribute key is malformed", x.Name)
		}
	case x.Source == SourceConst:
		if len(x.Value) == 0 || len(x.Value) > maxConstValue {
			return Claim{}, invalid("claim %q: value is required for const (up to %d bytes)", x.Name, maxConstValue)
		}
		v, err := sdjwt.DecodeJSON(x.Value)
		if err != nil || v == nil {
			return Claim{}, invalid("claim %q: value is not a JSON value", x.Name)
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, x.Value); err != nil {
			return Claim{}, invalid("claim %q: value is not a JSON value", x.Name)
		}
		cl.Value = buf.Bytes()
	default:
		return Claim{}, invalid("claim %q: unknown source %q", x.Name, x.Source)
	}
	if x.Source != SourceConst && len(x.Value) > 0 {
		return Claim{}, invalid("claim %q: value is only for const", x.Name)
	}
	return cl, nil
}

// attributeKeyRE はカスタム属性のキー（ADR 0080 の形より広くてよい。無いキーは値が無いだけ）。
var attributeKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Parse は保存した定義の設定を読む。
func Parse(c port.VCICredentialConfiguration) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return Config{}, fmt.Errorf("vci: configuration %s: %w", c.ID, err)
	}
	return cfg, nil
}

// checkScope は realm の他の定義とスコープが重ならないかを確かめる。
func checkScope(ctx context.Context, tx port.Tx, realmID, selfID, scope string) error {
	if scope == "" {
		return nil
	}
	cs, err := tx.VCI().ListConfigurations(ctx, realmID)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.ID != selfID && c.Scope == scope {
			return errs.WithCode(errs.KindConflict, codeScopeExists, fmt.Sprintf("scope %q is used by another configuration", scope))
		}
	}
	return nil
}

// conflictErr は configuration_id の重複を configuration_exists にする。
func conflictErr(err error) error {
	if errors.Is(err, errs.Conflict) {
		return errs.WithCode(errs.KindConflict, codeConfigurationExists, "configuration_id exists")
	}
	return err
}

// Create は定義を登録する。
func (s *Service) Create(ctx context.Context, tx port.Tx, realmID string, in Input, actor audit.Actor, requestID string) (port.VCICredentialConfiguration, error) {
	cfg, err := validate(in)
	if err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	if err := checkScope(ctx, tx, realmID, "", in.Scope); err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	now := s.Clock.Now()
	c := port.VCICredentialConfiguration{ID: id.NewExternal(id.VCIConfiguration), RealmID: realmID, ConfigurationID: in.ConfigurationID,
		Scope: in.Scope, Config: b, CreatedAt: now, UpdatedAt: now}
	if err := tx.VCI().CreateConfiguration(ctx, c); err != nil {
		return port.VCICredentialConfiguration{}, conflictErr(err)
	}
	return c, record(ctx, tx, s.Clock, "vci.configuration_created", audit.ResultSuccess, realmID, actor, requestID,
		map[string]any{"configuration_id": c.ConfigurationID, "id": c.ID, "vct": cfg.VCT})
}

// Update は定義を置き換える。発行済みの資格情報はそのまま（次の発行から効く）。
func (s *Service) Update(ctx context.Context, tx port.Tx, old port.VCICredentialConfiguration, in Input, actor audit.Actor, requestID string) (port.VCICredentialConfiguration, error) {
	cfg, err := validate(in)
	if err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	if err := checkScope(ctx, tx, old.RealmID, old.ID, in.Scope); err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return port.VCICredentialConfiguration{}, err
	}
	c := old
	c.ConfigurationID, c.Scope, c.Config, c.UpdatedAt = in.ConfigurationID, in.Scope, b, s.Clock.Now()
	if err := tx.VCI().UpdateConfiguration(ctx, c); err != nil {
		return port.VCICredentialConfiguration{}, conflictErr(err)
	}
	return c, record(ctx, tx, s.Clock, "vci.configuration_updated", audit.ResultSuccess, c.RealmID, actor, requestID,
		map[string]any{"configuration_id": c.ConfigurationID, "id": c.ID, "vct": cfg.VCT})
}

// Delete は定義を消す。発行済みの資格情報は失効させない（記録と status は残る）。
func (s *Service) Delete(ctx context.Context, tx port.Tx, c port.VCICredentialConfiguration, actor audit.Actor, requestID string) error {
	if err := tx.VCI().DeleteConfiguration(ctx, c.RealmID, c.ID); err != nil {
		return err
	}
	return record(ctx, tx, s.Clock, "vci.configuration_deleted", audit.ResultSuccess, c.RealmID, actor, requestID,
		map[string]any{"configuration_id": c.ConfigurationID, "id": c.ID})
}

// Metadata は発行者のメタデータ（OpenID4VCI 12.2.4）。
func (s *Service) Metadata(ctx context.Context, tx port.Tx, realmID string) (map[string]any, error) {
	cs, err := tx.VCI().ListConfigurations(ctx, realmID)
	if err != nil {
		return nil, err
	}
	supported := map[string]any{}
	for _, c := range cs {
		cfg, err := Parse(c)
		if err != nil {
			return nil, err
		}
		supported[c.ConfigurationID] = configurationMetadata(c, cfg)
	}
	return map[string]any{
		"credential_issuer":                   s.Issuer,
		"credential_endpoint":                 s.URL(CredentialPath),
		"nonce_endpoint":                      s.URL(NoncePath),
		"credential_configurations_supported": supported,
	}, nil
}

func displays(ds []Display) []map[string]any {
	out := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		m := map[string]any{"name": d.Name}
		if d.Locale != "" {
			m["locale"] = d.Locale
		}
		out = append(out, m)
	}
	return out
}

func configurationMetadata(c port.VCICredentialConfiguration, cfg Config) map[string]any {
	claims := make([]map[string]any, 0, len(cfg.Claims))
	for _, x := range cfg.Claims {
		m := map[string]any{"path": []string{x.Name}}
		if x.Mandatory {
			m["mandatory"] = true
		}
		if len(x.Display) > 0 {
			m["display"] = displays(x.Display)
		}
		claims = append(claims, m)
	}
	meta := map[string]any{"claims": claims}
	if len(cfg.Display) > 0 {
		meta["display"] = displays(cfg.Display)
	}
	out := map[string]any{
		"format":                                cfg.Format,
		"vct":                                   cfg.VCT,
		"cryptographic_binding_methods_supported": []string{"jwk"},
		"credential_signing_alg_values_supported": []string{port.AlgES256},
		"proof_types_supported": map[string]any{
			"jwt": map[string]any{"proof_signing_alg_values_supported": sdjwt.AlgorithmNames()},
		},
		"credential_metadata": meta,
	}
	if c.Scope != "" {
		out["scope"] = c.Scope
	}
	return out
}
