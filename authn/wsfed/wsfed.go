// Package wsfed は WS-Federation のパッシブ要求者プロファイル（WS-Federation 1.2 の 13 章）で、iam が IdP（STS）になる側
// （フィーチャー wsfed。ADR 0110）。
//
// RP（wtrealm と wreply の許可リスト、クレームの対応、トークンの種類）の登録、要求の引数の解析、SAML 1.1 / 2.0 の Assertion を
// 入れた RequestSecurityTokenResponse の組み立てと XML 署名（realm の ES256 の鍵）、フェデレーションのメタデータを持つ。
// HTTP（要求の受け付け、ログイン画面への転送、自動で POST する画面）は server が受け持つ。
package wsfed

import (
	"context"
	"encoding/json"
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

// Feature はフィーチャー wsfed の宣言（既定オフ。ADR 0089、0110）。
var Feature = feature.Feature{Name: feature.WSFed, DataVersion: 1}

// エンドポイントのパス（realm の issuer からの相対）。
const (
	// PassivePath はパッシブ要求者のエンドポイント（wa=wsignin1.0 と wsignout1.0）。
	PassivePath = "/wsfed"
	// ResumePath はログイン画面から戻ってトークンを渡すエンドポイント。
	ResumePath = "/wsfed/resume"
	// MetadataPath はフェデレーションのメタデータ（ADFS と同じパス）。
	MetadataPath = "/FederationMetadata/2007-06/FederationMetadata.xml"
)

// トークンの種類。
const (
	TokenSAML11 = "saml11"
	TokenSAML20 = "saml20"
)

// クレームの出どころ。
const (
	SourceUserID = "user_id"
	SourceEmail  = "email"
	SourceOrgID  = "org_id"
	SourceAMR    = "amr"
	// SourceAttributePrefix の後ろにカスタム属性のキーを書く（フィーチャー custom_attributes）。
	SourceAttributePrefix = "attribute:"
)

// ClaimEmailAddress はメールのクレームの種類（WIF・ADFS の既定の名前）。
const ClaimEmailAddress = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

// 登録の上限と既定。
const (
	DefaultTokenLifetime = 3600
	MinTokenLifetime     = 300
	MaxTokenLifetime     = 86400
	maxRealmLen          = 1024
	maxNameLen           = 100
	maxReplyURLs         = 10
	maxReplyURLLen       = 2048
	maxClaims            = 32
	maxClaimTypeLen      = 512
)

// Claim はクレームの対応の1件（RP に出す属性）。
type Claim struct {
	// Source は値の出どころ（user_id・email・org_id・amr・attribute:<キー>）。
	Source string `json:"source"`
	// Type はクレームの種類（絶対 URI）。SAML 1.1 では最後の "/" で AttributeNamespace と AttributeName に分ける。
	Type string `json:"type"`
}

// DefaultClaims は登録でクレームを省いたときの対応（確認済みのメールを emailaddress に出す）。
func DefaultClaims() []Claim { return []Claim{{Source: SourceEmail, Type: ClaimEmailAddress}} }

// Input は RP の登録の内容（管理 API）。
type Input struct {
	Realm     string
	Name      string
	ReplyURLs []string
	// TokenType は saml11 か saml20。空なら saml11。
	TokenType string
	// Claims は nil なら DefaultClaims。空の配列ならクレームを出さない（主体だけ）。
	Claims []Claim
	// TokenLifetime は秒。0 なら DefaultTokenLifetime。
	TokenLifetime int
	// SigningAlg は署名（ES256 は ECDSA-SHA256、RS256 は RSA-SHA256）。空なら ES256。RS256 はフィーチャー rs256 が
	// 動いているときだけ選べる（ADR 0125）。
	SigningAlg string
}

// ErrInvalidRelyingParty は登録の内容が正しくないこと。
func errInvalid(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_relying_party", msg)
}

// ErrRealmExists は同じ wtrealm の RP が realm にあること。
var ErrRealmExists = errs.WithCode(errs.KindConflict, "realm_exists", "a relying party with this realm already exists")

var attributeKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Validate は登録の内容を確かめ、既定を埋めたものを返す。
func Validate(in Input) (Input, error) {
	out := in
	if err := checkURI(in.Realm, maxRealmLen); err != nil {
		return Input{}, errInvalid("realm: " + err.Error())
	}
	if in.Name == "" || utf8.RuneCountInString(in.Name) > maxNameLen || !utf8.ValidString(in.Name) || strings.ContainsFunc(in.Name, isControl) {
		return Input{}, errInvalid("name must be 1 to 100 characters without control characters")
	}
	if len(in.ReplyURLs) == 0 || len(in.ReplyURLs) > maxReplyURLs {
		return Input{}, errInvalid("reply_urls must have 1 to 10 entries")
	}
	for i, u := range in.ReplyURLs {
		if err := checkReplyURL(u); err != nil {
			return Input{}, errInvalid("reply_urls: " + err.Error())
		}
		if slices.Contains(in.ReplyURLs[:i], u) {
			return Input{}, errInvalid("reply_urls must not repeat")
		}
	}
	out.ReplyURLs = slices.Clone(in.ReplyURLs)
	switch in.TokenType {
	case "":
		out.TokenType = TokenSAML11
	case TokenSAML11, TokenSAML20:
	default:
		return Input{}, errInvalid("token_type must be saml11 or saml20")
	}
	if in.Claims == nil {
		out.Claims = DefaultClaims()
	} else {
		out.Claims = slices.Clone(in.Claims)
	}
	if len(out.Claims) > maxClaims {
		return Input{}, errInvalid("claims must have at most 32 entries")
	}
	for i, c := range out.Claims {
		if !validSource(c.Source) {
			return Input{}, errInvalid("claims: unknown source " + quoteShort(c.Source))
		}
		if err := checkURI(c.Type, maxClaimTypeLen); err != nil {
			return Input{}, errInvalid("claims: type: " + err.Error())
		}
		if out.TokenType == TokenSAML11 {
			if _, _, ok := splitClaimType(c.Type); !ok {
				return Input{}, errInvalid("claims: a SAML 1.1 claim type must end with /<name>")
			}
		}
		if slices.ContainsFunc(out.Claims[:i], func(x Claim) bool { return x.Type == c.Type }) {
			return Input{}, errInvalid("claims: types must not repeat")
		}
	}
	switch {
	case in.TokenLifetime == 0:
		out.TokenLifetime = DefaultTokenLifetime
	case in.TokenLifetime < MinTokenLifetime || in.TokenLifetime > MaxTokenLifetime:
		return Input{}, errInvalid("token_lifetime must be between 300 and 86400 seconds")
	}
	switch in.SigningAlg {
	case "":
		out.SigningAlg = port.AlgES256
	case port.AlgES256, port.AlgRS256:
	default:
		return Input{}, errInvalid("signing_alg must be ES256 or RS256")
	}
	return out, nil
}

// validate は Validate に、フィーチャー rs256 が止まっていれば RS256 を拒むことを足す。
func (s *Service) validate(in Input) (Input, error) {
	out, err := Validate(in)
	if err != nil {
		return Input{}, err
	}
	if out.SigningAlg == port.AlgRS256 && (s.Keys == nil || !s.Keys.RS256) {
		return Input{}, errInvalid("signing_alg RS256 requires the rs256 feature")
	}
	return out, nil
}

// keptSigningAlg は更新で signing_alg を省いたときの値。今の値を保つ（signing_alg を知らない管理クライアントの更新で
// RS256 が ES256 に戻らないように）。ただしフィーチャー rs256 が止まっていれば ES256（片付けと同じ。ADR 0125）。
func (s *Service) keptSigningAlg(cur string) string {
	if cur == port.AlgRS256 && (s.Keys == nil || !s.Keys.RS256) {
		return port.AlgES256
	}
	return cur
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

// checkReplyURL は wreply の許可リストの1件（https の絶対 URL、フラグメント・利用者情報なし）かを確かめる。
func checkReplyURL(s string) error {
	if len(s) > maxReplyURLLen || strings.ContainsFunc(s, func(r rune) bool { return isControl(r) || r == ' ' }) {
		return errors.New("must be an https URL of at most 2048 bytes")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(s, "#") {
		return errors.New("must be an absolute https URL without a fragment or user info")
	}
	return nil
}

func validSource(s string) bool {
	switch s {
	case SourceUserID, SourceEmail, SourceOrgID, SourceAMR:
		return true
	}
	k, ok := strings.CutPrefix(s, SourceAttributePrefix)
	return ok && attributeKeyRE.MatchString(k)
}

// splitClaimType は SAML 1.1 の AttributeNamespace と AttributeName に分ける（最後の "/" で。どちらも空でないこと）。
func splitClaimType(t string) (ns, name string, ok bool) {
	i := strings.LastIndexByte(t, '/')
	if i <= 0 || i == len(t)-1 {
		return "", "", false
	}
	return t[:i], t[i+1:], true
}

// Service は RP の登録と、トークン・メタデータの組み立て。realm の App ごとに作る。
type Service struct {
	Storage port.Storage
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	Keys    *provider.Keys
	Tokens  *provider.Tokens
	// Issuer は realm の issuer（IdP の Entity ID。エンドポイントはこの下）。
	Issuer string
	// Attributes はフィーチャー custom_attributes が動いているか（attribute:<キー> のクレームを出すか）。
	Attributes bool
	// RequestTTL はログイン画面で待つ間の要求の期限（既定 10 分）。
	RequestTTL time.Duration
	Log        *slog.Logger
}

// Endpoint はパッシブ要求者のエンドポイントの URL。
func (s *Service) Endpoint() string { return s.Issuer + PassivePath }

// Claims は RP のクレームの対応を読む。
func Claims(rp port.WSFedRelyingParty) ([]Claim, error) {
	var cs []Claim
	if len(rp.Claims) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(rp.Claims, &cs); err != nil {
		return nil, err
	}
	return cs, nil
}

func apply(rp port.WSFedRelyingParty, in Input) (port.WSFedRelyingParty, error) {
	claims, err := json.Marshal(in.Claims)
	if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	rp.Realm, rp.Name, rp.ReplyURLs, rp.TokenType, rp.Claims, rp.TokenLifetime = in.Realm, in.Name, in.ReplyURLs, in.TokenType, claims, in.TokenLifetime
	rp.SigningAlg = in.SigningAlg
	return rp, nil
}

func (s *Service) record(ctx context.Context, tx port.Tx, typ, realmID string, actor audit.Actor, requestID string, rp port.WSFedRelyingParty) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"relying_party_id": rp.ID, "realm": rp.Realm, "token_type": rp.TokenType}})
	return err
}

// Create は RP を登録する（監査ログ wsfed.relying_party.created）。wtrealm が重複すれば ErrRealmExists。
func (s *Service) Create(ctx context.Context, tx port.Tx, realmID string, in Input, actor audit.Actor, requestID string) (port.WSFedRelyingParty, error) {
	in, err := s.validate(in)
	if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	now := s.Clock.Now()
	rp, err := apply(port.WSFedRelyingParty{ID: id.NewExternal(id.WSFedRelyingParty), RealmID: realmID, CreatedAt: now, UpdatedAt: now}, in)
	if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	if err := tx.WSFed().CreateRelyingParty(ctx, rp); errors.Is(err, errs.Conflict) {
		return port.WSFedRelyingParty{}, ErrRealmExists
	} else if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	return rp, s.record(ctx, tx, "wsfed.relying_party.created", realmID, actor, requestID, rp)
}

// Update は RP の登録を置き換える（監査ログ wsfed.relying_party.updated）。無ければ errs.NotFound。
func (s *Service) Update(ctx context.Context, tx port.Tx, rp port.WSFedRelyingParty, in Input, actor audit.Actor, requestID string) (port.WSFedRelyingParty, error) {
	if in.SigningAlg == "" {
		in.SigningAlg = s.keptSigningAlg(rp.SigningAlg)
	}
	in, err := s.validate(in)
	if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	rp, err = apply(rp, in)
	if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	rp.UpdatedAt = s.Clock.Now()
	if err := tx.WSFed().UpdateRelyingParty(ctx, rp); errors.Is(err, errs.Conflict) {
		return port.WSFedRelyingParty{}, ErrRealmExists
	} else if err != nil {
		return port.WSFedRelyingParty{}, err
	}
	return rp, s.record(ctx, tx, "wsfed.relying_party.updated", rp.RealmID, actor, requestID, rp)
}

// Delete は RP を消す（監査ログ wsfed.relying_party.deleted）。
func (s *Service) Delete(ctx context.Context, tx port.Tx, rp port.WSFedRelyingParty, actor audit.Actor, requestID string) error {
	if err := tx.WSFed().DeleteRelyingParty(ctx, rp.RealmID, rp.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, "wsfed.relying_party.deleted", rp.RealmID, actor, requestID, rp)
}
