// Package samlidp は SAML 2.0 の IdP（iam が IdP になる側。フィーチャー saml_idp。ADR 0115）。
//
// SP の登録（Entity ID、ACS、SP の証明書、NameID、属性の対応、署名と暗号化）、AuthnRequest と LogoutRequest の解析と署名の検証
// （HTTP-Redirect と HTTP-POST）、Response（Assertion）と LogoutResponse の組み立てと XML 署名（realm の ES256 の鍵）、
// Assertion の暗号化（SP の RSA の証明書へ）、IdP のメタデータを持つ。HTTP（要求の受け付け、ログイン画面への転送、自動で POST する画面）は
// server が受け持つ。
package samlidp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー saml_idp の宣言（既定オフ。ADR 0089、0115）。
var Feature = feature.Feature{Name: feature.SAMLIdP, DataVersion: 1}

// エンドポイントのパス（realm の issuer からの相対）。
const (
	// SSOPath は SingleSignOnService（AuthnRequest を HTTP-Redirect の GET と HTTP-POST の POST で受ける）。
	SSOPath = "/saml/idp/sso"
	// ResumePath はログイン画面から（または HTTP-POST の要求から）戻って Response を渡すエンドポイント。
	ResumePath = "/saml/idp/sso/resume"
	// InitPath は IdP-initiated のエンドポイント（SP ごとに許したときだけ）。
	InitPath = "/saml/idp/init"
	// SLOPath は SingleLogoutService（LogoutRequest を HTTP-Redirect の GET と HTTP-POST の POST で受ける）。
	SLOPath = "/saml/idp/slo"
	// SLOResumePath は HTTP-POST の LogoutRequest をブラウザのセッションで処理するために戻るエンドポイント。
	SLOResumePath = "/saml/idp/slo/resume"
	// MetadataPath は IdP のメタデータ。
	MetadataPath = "/saml/idp/metadata"
)

// 名前空間と識別子。
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	nameIDEntity      = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

	AttrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttrNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// 値の出どころ（NameID と属性）。
const (
	SourceUserID = "user_id"
	SourceEmail  = "email"
	SourceOrgID  = "org_id"
	SourceAMR    = "amr"
	// SourceAttributePrefix の後ろにカスタム属性のキーを書く（フィーチャー custom_attributes）。
	SourceAttributePrefix = "attribute:"
)

// 登録の上限と既定。
const (
	DefaultAssertionLifetime = 300
	MinAssertionLifetime     = 60
	MaxAssertionLifetime     = 3600
	maxEntityIDLen           = 1024
	maxNameLen               = 100
	maxACS                   = 10
	maxURLLen                = 2048
	maxSigningCerts          = 3
	maxAttributes            = 32
	maxAttrNameLen           = 256
	maxACSIndex              = 65535
)

// Endpoint は SP の ACS か SLO の URL とバインディング。
type Endpoint struct {
	URL     string `json:"url"`
	Binding string `json:"binding"`
	// Index は ACS の番号（AssertionConsumerServiceIndex）。SLO では使わない。
	Index int `json:"index,omitempty"`
	// Default は既定の ACS（AuthnRequest が ACS を指さないときと IdP-initiated で使う）。無ければ最初のもの。
	Default bool `json:"default,omitempty"`
}

// Attribute は属性の対応の1件（SP に出す属性）。
type Attribute struct {
	// Source は値の出どころ（user_id・email・org_id・amr・attribute:<キー>）。
	Source string `json:"source"`
	// Name は属性の名前、NameFormat はその形式（uri・basic・unspecified の URN）、FriendlyName は表示名（任意）。
	Name         string `json:"name"`
	NameFormat   string `json:"name_format"`
	FriendlyName string `json:"friendly_name,omitempty"`
}

// Config は SP の登録の、Entity ID と名前以外（port.SAMLServiceProvider の Config に JSON で置く）。
type Config struct {
	ACS []Endpoint `json:"acs"`
	SLO []Endpoint `json:"slo,omitempty"`
	// SigningCerts は AuthnRequest と LogoutRequest の署名を確かめる SP の証明書（DER）。
	SigningCerts [][]byte `json:"signing_certs,omitempty"`
	// RequireSignedRequests は署名の無い AuthnRequest を受けない。LogoutRequest はいつも署名を求める。
	RequireSignedRequests bool `json:"require_signed_requests,omitempty"`
	// EncryptionCert は Assertion を暗号化する SP の証明書（DER。RSA）。あれば必ず暗号化する。
	EncryptionCert []byte `json:"encryption_cert,omitempty"`
	NameIDFormat   string `json:"name_id_format"`
	// NameIDSource は NameID の値の出どころ（transient では使わない）。
	NameIDSource      string      `json:"name_id_source,omitempty"`
	Attributes        []Attribute `json:"attributes"`
	SignAssertion     bool        `json:"sign_assertion"`
	SignResponse      bool        `json:"sign_response"`
	AllowIdPInitiated bool        `json:"allow_idp_initiated,omitempty"`
	// AssertionLifetime は Assertion の有効期間（秒）。
	AssertionLifetime int `json:"assertion_lifetime"`
	// SigningAlg は Response・Assertion・LogoutResponse の署名（ES256 は ECDSA-SHA256、RS256 は RSA-SHA256）。既定は ES256。
	// RS256 はフィーチャー rs256 が動いているときだけ選べる（ADR 0125）。
	SigningAlg string `json:"signing_alg,omitempty"`
}

// Input は SP の登録の内容（管理 API）。
type Input struct {
	EntityID string
	Name     string
	Config   Config
}

func errInvalid(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_service_provider", msg)
}

// ErrEntityIDExists は同じ Entity ID の SP が realm にあること。
var ErrEntityIDExists = errs.WithCode(errs.KindConflict, "entity_id_exists", "a service provider with this entity id already exists")

var attributeKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Validate は登録の内容を確かめ、既定を埋めたものを返す。now は証明書の期限を確かめる時刻。
func Validate(in Input, now time.Time) (Input, error) {
	out := in
	c := &out.Config
	if err := checkURI(in.EntityID, maxEntityIDLen); err != nil {
		return Input{}, errInvalid("entity_id: " + err.Error())
	}
	if in.Name == "" || utf8.RuneCountInString(in.Name) > maxNameLen || !utf8.ValidString(in.Name) || strings.ContainsFunc(in.Name, isControl) {
		return Input{}, errInvalid("name must be 1 to 100 characters without control characters")
	}
	if len(c.ACS) == 0 || len(c.ACS) > maxACS {
		return Input{}, errInvalid("acs must have 1 to 10 entries")
	}
	c.ACS = slices.Clone(c.ACS)
	defaults := 0
	for i, e := range c.ACS {
		if err := checkEndpointURL(e.URL); err != nil {
			return Input{}, errInvalid("acs: " + err.Error())
		}
		if e.Binding == "" {
			c.ACS[i].Binding = BindingPOST
		} else if e.Binding != BindingPOST {
			// Response は HTTP-POST バインディングだけで送る（Artifact・PAOS は持たない）。
			return Input{}, errInvalid("acs: binding must be HTTP-POST")
		}
		if e.Index < 0 || e.Index > maxACSIndex {
			return Input{}, errInvalid("acs: index must be between 0 and 65535")
		}
		if slices.ContainsFunc(c.ACS[:i], func(x Endpoint) bool { return x.Index == e.Index }) {
			return Input{}, errInvalid("acs: index must not repeat")
		}
		if slices.ContainsFunc(c.ACS[:i], func(x Endpoint) bool { return x.URL == e.URL }) {
			return Input{}, errInvalid("acs: url must not repeat")
		}
		if e.Default {
			defaults++
		}
	}
	if defaults > 1 {
		return Input{}, errInvalid("acs: at most one entry can be the default")
	}
	if len(c.SLO) > 2 {
		return Input{}, errInvalid("slo must have at most 2 entries")
	}
	c.SLO = slices.Clone(c.SLO)
	for i, e := range c.SLO {
		if err := checkEndpointURL(e.URL); err != nil {
			return Input{}, errInvalid("slo: " + err.Error())
		}
		if e.Binding != BindingRedirect && e.Binding != BindingPOST {
			return Input{}, errInvalid("slo: binding must be HTTP-Redirect or HTTP-POST")
		}
		if slices.ContainsFunc(c.SLO[:i], func(x Endpoint) bool { return x.Binding == e.Binding }) {
			return Input{}, errInvalid("slo: binding must not repeat")
		}
		c.SLO[i].Index, c.SLO[i].Default = 0, false
	}
	if len(c.SigningCerts) > maxSigningCerts {
		return Input{}, errInvalid("signing_certificates must have at most 3 entries")
	}
	c.SigningCerts = slices.Clone(c.SigningCerts)
	for _, der := range c.SigningCerts {
		if err := checkCertificate(der, now, false); err != nil {
			return Input{}, errInvalid("signing_certificates: " + err.Error())
		}
	}
	if c.RequireSignedRequests && len(c.SigningCerts) == 0 {
		return Input{}, errInvalid("require_signed_requests needs signing_certificates")
	}
	if len(c.SLO) > 0 && len(c.SigningCerts) == 0 {
		// LogoutRequest はいつも署名を求めるので、確かめる証明書が要る。
		return Input{}, errInvalid("slo needs signing_certificates")
	}
	if len(c.EncryptionCert) > 0 {
		if err := checkCertificate(c.EncryptionCert, now, true); err != nil {
			return Input{}, errInvalid("encryption_certificate: " + err.Error())
		}
	}
	switch c.NameIDFormat {
	case "":
		c.NameIDFormat = NameIDPersistent
	case NameIDPersistent, NameIDEmail, NameIDUnspecified, NameIDTransient:
	default:
		return Input{}, errInvalid("name_id_format is not supported")
	}
	switch {
	case c.NameIDFormat == NameIDTransient:
		c.NameIDSource = ""
	case c.NameIDSource == "" && c.NameIDFormat == NameIDEmail:
		c.NameIDSource = SourceEmail
	case c.NameIDSource == "":
		c.NameIDSource = SourceUserID
	case c.NameIDSource != SourceUserID && c.NameIDSource != SourceEmail && !validAttributeSource(c.NameIDSource):
		// 値が 1 つに決まらない出どころ（org_id は Org の文脈で変わる、amr は複数）は NameID にしない。
		return Input{}, errInvalid("name_id_source must be user_id, email or attribute:<key>")
	}
	if c.NameIDFormat == NameIDEmail && c.NameIDSource == SourceUserID {
		return Input{}, errInvalid("name_id_source user_id cannot be used with the emailAddress format")
	}
	if c.Attributes == nil {
		c.Attributes = []Attribute{}
	}
	c.Attributes = slices.Clone(c.Attributes)
	if len(c.Attributes) > maxAttributes {
		return Input{}, errInvalid("attributes must have at most 32 entries")
	}
	for i, a := range c.Attributes {
		if !validSource(a.Source) {
			return Input{}, errInvalid("attributes: unknown source " + quoteShort(a.Source))
		}
		if a.NameFormat == "" {
			c.Attributes[i].NameFormat = AttrNameFormatURI
		}
		switch c.Attributes[i].NameFormat {
		case AttrNameFormatURI:
			if err := checkURI(a.Name, maxAttrNameLen); err != nil {
				return Input{}, errInvalid("attributes: name: " + err.Error())
			}
		case AttrNameFormatBasic, AttrNameFormatUnspecified:
			if a.Name == "" || len(a.Name) > maxAttrNameLen || !utf8.ValidString(a.Name) || strings.ContainsFunc(a.Name, func(r rune) bool { return isControl(r) || r == ' ' }) {
				return Input{}, errInvalid("attributes: name must be 1 to 256 bytes without spaces")
			}
		default:
			return Input{}, errInvalid("attributes: name_format is not supported")
		}
		if utf8.RuneCountInString(a.FriendlyName) > maxNameLen || !utf8.ValidString(a.FriendlyName) || strings.ContainsFunc(a.FriendlyName, isControl) {
			return Input{}, errInvalid("attributes: friendly_name must be at most 100 characters")
		}
		if slices.ContainsFunc(c.Attributes[:i], func(x Attribute) bool { return x.Name == a.Name }) {
			return Input{}, errInvalid("attributes: names must not repeat")
		}
	}
	if !c.SignAssertion && !c.SignResponse {
		return Input{}, errInvalid("sign_assertion or sign_response must be true")
	}
	switch c.SigningAlg {
	case "":
		c.SigningAlg = port.AlgES256
	case port.AlgES256, port.AlgRS256:
	default:
		return Input{}, errInvalid("signing_alg must be ES256 or RS256")
	}
	switch {
	case c.AssertionLifetime == 0:
		c.AssertionLifetime = DefaultAssertionLifetime
	case c.AssertionLifetime < MinAssertionLifetime || c.AssertionLifetime > MaxAssertionLifetime:
		return Input{}, errInvalid("assertion_lifetime must be between 60 and 3600 seconds")
	}
	return out, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }

func quoteShort(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return `"` + strings.ToValidUTF8(s, "?") + `"`
}

// checkURI は絶対 URI（スキームがある。空白・制御文字なし）で n バイト以内かを確かめる。
func checkURI(s string, n int) error {
	if s == "" || len(s) > n || !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return isControl(r) || r == ' ' }) {
		return errors.New("must be a non-empty URI without spaces")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || (u.Opaque == "" && u.Host == "" && u.Path == "") {
		return errors.New("must be an absolute URI")
	}
	return nil
}

// checkEndpointURL は ACS・SLO の URL（https の絶対 URL、フラグメント・利用者情報なし）かを確かめる。
func checkEndpointURL(s string) error {
	if len(s) > maxURLLen || strings.ContainsFunc(s, func(r rune) bool { return isControl(r) || r == ' ' }) {
		return errors.New("url must be an https URL of at most 2048 bytes")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(s, "#") {
		return errors.New("url must be an absolute https URL without a fragment or user info")
	}
	return nil
}

// checkCertificate は SP の証明書を確かめる。署名には RSA（2048 bit 以上）か ECDSA（P-256・P-384・P-521）、
// 暗号化（encryption）には RSA（2048 bit 以上）だけを受ける。期限切れ・まだ有効でないものは登録しない。
func checkCertificate(der []byte, now time.Time, encryption bool) error {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return errors.New("not a valid X.509 certificate")
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("the certificate is expired or not yet valid")
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA keys must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if encryption {
			return errors.New("the encryption certificate must have an RSA key")
		}
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return errors.New("unsupported elliptic curve")
		}
	default:
		return errors.New("unsupported public key type")
	}
	return nil
}

// ParseCertificate は管理 API で受け取った証明書（PEM か、base64 の DER）を DER にする。
func ParseCertificate(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) > 0 {
			return nil, errInvalid("certificate: expected a single PEM CERTIFICATE block")
		}
		return b.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil || len(der) == 0 {
		return nil, errInvalid("certificate: expected PEM or base64 DER")
	}
	return der, nil
}

func validAttributeSource(s string) bool {
	k, ok := strings.CutPrefix(s, SourceAttributePrefix)
	return ok && attributeKeyRE.MatchString(k)
}

func validSource(s string) bool {
	switch s {
	case SourceUserID, SourceEmail, SourceOrgID, SourceAMR:
		return true
	}
	return validAttributeSource(s)
}

// Service は SP の登録と、要求の解析・応答の組み立て・メタデータ。realm の App ごとに作る。
type Service struct {
	Storage port.Storage
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	Keys    *provider.Keys
	Tokens  *provider.Tokens
	// Issuer は realm の issuer（IdP の Entity ID。エンドポイントはこの下）。
	Issuer string
	// Attributes はフィーチャー custom_attributes が動いているか（attribute:<キー> を出すか）。
	Attributes bool
	// HardwareAAL は AAL3・phrh を求められるか（acr.Supported の hardware。ADR 0093）。
	HardwareAAL bool
	// RequestTTL はログイン画面で待つ間の要求の期限（既定 10 分）。
	RequestTTL time.Duration
	Log        *slog.Logger
}

// SSOURL は SingleSignOnService の URL（AuthnRequest の Destination）。
func (s *Service) SSOURL() string { return s.Issuer + SSOPath }

// SLOURL は SingleLogoutService の URL（LogoutRequest の Destination）。
func (s *Service) SLOURL() string { return s.Issuer + SLOPath }

// validate は Validate に、フィーチャー rs256 が止まっていれば RS256 を拒むことを足す。
func (s *Service) validate(in Input, now time.Time) (Input, error) {
	out, err := Validate(in, now)
	if err != nil {
		return Input{}, err
	}
	if out.Config.SigningAlg == port.AlgRS256 && (s.Keys == nil || !s.Keys.RS256) {
		return Input{}, errInvalid("signing_alg RS256 requires the rs256 feature")
	}
	return out, nil
}

// ConfigOf は SP の登録の設定を読む。
func ConfigOf(sp port.SAMLServiceProvider) (Config, error) {
	var c Config
	if err := json.Unmarshal(sp.Config, &c); err != nil {
		return Config{}, err
	}
	if c.SigningAlg == "" {
		c.SigningAlg = port.AlgES256 // signing_alg の前に登録した SP（ADR 0125）
	}
	return c, nil
}

func apply(sp port.SAMLServiceProvider, in Input) (port.SAMLServiceProvider, error) {
	raw, err := json.Marshal(in.Config)
	if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	sp.EntityID, sp.Name, sp.Config = in.EntityID, in.Name, raw
	return sp, nil
}

func (s *Service) record(ctx context.Context, tx port.Tx, typ, realmID string, actor audit.Actor, requestID string, sp port.SAMLServiceProvider) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"service_provider_id": sp.ID, "entity_id": sp.EntityID}})
	return err
}

// Create は SP を登録する（監査ログ saml_idp.service_provider.created）。Entity ID が重複すれば ErrEntityIDExists。
func (s *Service) Create(ctx context.Context, tx port.Tx, realmID string, in Input, actor audit.Actor, requestID string) (port.SAMLServiceProvider, error) {
	now := s.Clock.Now()
	in, err := s.validate(in, now)
	if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	if err := checkNameIDSource(ctx, tx, realmID, in.Config.NameIDSource); err != nil {
		return port.SAMLServiceProvider{}, err
	}
	sp, err := apply(port.SAMLServiceProvider{ID: id.NewExternal(id.SAMLServiceProvider), RealmID: realmID, CreatedAt: now, UpdatedAt: now}, in)
	if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	if err := tx.SAMLIdP().CreateServiceProvider(ctx, sp); errors.Is(err, errs.Conflict) {
		return port.SAMLServiceProvider{}, ErrEntityIDExists
	} else if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	return sp, s.record(ctx, tx, "saml_idp.service_provider.created", realmID, actor, requestID, sp)
}

// Update は SP の登録を置き換える（監査ログ saml_idp.service_provider.updated）。無ければ errs.NotFound。
func (s *Service) Update(ctx context.Context, tx port.Tx, sp port.SAMLServiceProvider, in Input, actor audit.Actor, requestID string) (port.SAMLServiceProvider, error) {
	now := s.Clock.Now()
	if in.Config.SigningAlg == "" {
		// 省けば今の値を保つ（signing_alg を知らない管理クライアントの更新で RS256 が ES256 に戻らないように）。
		// フィーチャー rs256 が止まっていれば ES256（片付けと同じ。ADR 0125）。
		cur, err := ConfigOf(sp)
		if err != nil {
			return port.SAMLServiceProvider{}, err
		}
		in.Config.SigningAlg = cur.SigningAlg
		if in.Config.SigningAlg == port.AlgRS256 && (s.Keys == nil || !s.Keys.RS256) {
			in.Config.SigningAlg = port.AlgES256
		}
	}
	in, err := s.validate(in, now)
	if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	if err := checkNameIDSource(ctx, tx, sp.RealmID, in.Config.NameIDSource); err != nil {
		return port.SAMLServiceProvider{}, err
	}
	if sp, err = apply(sp, in); err != nil {
		return port.SAMLServiceProvider{}, err
	}
	sp.UpdatedAt = now
	if err := tx.SAMLIdP().UpdateServiceProvider(ctx, sp); errors.Is(err, errs.Conflict) {
		return port.SAMLServiceProvider{}, ErrEntityIDExists
	} else if err != nil {
		return port.SAMLServiceProvider{}, err
	}
	return sp, s.record(ctx, tx, "saml_idp.service_provider.updated", sp.RealmID, actor, requestID, sp)
}

// Delete は SP を消す（監査ログ saml_idp.service_provider.deleted）。
func (s *Service) Delete(ctx context.Context, tx port.Tx, sp port.SAMLServiceProvider, actor audit.Actor, requestID string) error {
	if err := tx.SAMLIdP().DeleteServiceProvider(ctx, sp.RealmID, sp.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, "saml_idp.service_provider.deleted", sp.RealmID, actor, requestID, sp)
}

// lookup は Entity ID の SP と設定を引く。無ければ ErrUnknownSP。
func (s *Service) lookup(ctx context.Context, realmID, entityID string) (port.SAMLServiceProvider, Config, error) {
	if entityID == "" {
		return port.SAMLServiceProvider{}, Config{}, ErrUnknownSP
	}
	var sp port.SAMLServiceProvider
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		sp, err = tx.SAMLIdP().GetServiceProviderByEntityID(ctx, realmID, entityID)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return port.SAMLServiceProvider{}, Config{}, ErrUnknownSP
	}
	if err != nil {
		return port.SAMLServiceProvider{}, Config{}, err
	}
	cfg, err := ConfigOf(sp)
	return sp, cfg, err
}

// defaultACS は既定の ACS（Default のもの、無ければ最初のもの）。
func defaultACS(c Config) (Endpoint, bool) {
	if i := slices.IndexFunc(c.ACS, func(e Endpoint) bool { return e.Default }); i >= 0 {
		return c.ACS[i], true
	}
	if len(c.ACS) == 0 {
		return Endpoint{}, false
	}
	return c.ACS[0], true
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// errEditableNameIDSource は NameID の出どころが、本人が書ける属性であること。
var errEditableNameIDSource = errInvalid("name_id_source must not be a user-editable attribute")

// editableNameIDSource は、NameID の出どころが本人の書ける属性かを返す。本人が書ける値を NameID にすると、
// 本人が値を SP の別の利用者の識別子に変えてなりすませる。定義が無ければ false（値も無いので NameID は出ない）。
func editableNameIDSource(ctx context.Context, tx port.Tx, realmID, source string) (bool, error) {
	key, ok := strings.CutPrefix(source, SourceAttributePrefix)
	if !ok {
		return false, nil
	}
	d, err := tx.Attributes().GetDef(ctx, realmID, key)
	if errors.Is(err, errs.NotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return d.UserEditable, nil
}

// checkNameIDSource は、登録のときに本人が書ける属性を NameID の出どころにさせない。
func checkNameIDSource(ctx context.Context, tx port.Tx, realmID, source string) error {
	editable, err := editableNameIDSource(ctx, tx, realmID, source)
	if err != nil {
		return err
	}
	if editable {
		return errEditableNameIDSource
	}
	return nil
}
