// Package vci は OpenID for Verifiable Credential Issuance 1.0（OpenID4VCI）の発行者（iam が発行者。フィーチャー openid4vci。ADR 0119）。
//
// 発行者の識別子と認可サーバーは realm の issuer。資格情報は SD-JWT VC（dc+sd-jwt）で、realm の ES256 の鍵で署名し、
// proof の鍵に結び付け（cnf.jwk）、Token Status List で失効させる。HTTP とトークン（Authorization Code Flow の分）の確かめは
// server が受け持ち、ここは定義・申し出・Pre-Authorized Code・nonce・proof・発行・status list を持つ。
//
// セキュリティ上重要なコード（13.2）。proof の解析にファジングのテストがある。
package vci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー openid4vci。既定でオフ。
var Feature = feature.Feature{Name: feature.OpenID4VCI, DataVersion: 1}

// エンドポイントのパス（realm の issuer からの相対）。
const (
	// MetadataPath は発行者のメタデータ（OpenID4VCI 12.2）。
	MetadataPath = "/.well-known/openid-credential-issuer"
	// IssuerMetadataPath は JWT VC Issuer Metadata（SD-JWT VC 5）。発行者の公開鍵を配る。
	IssuerMetadataPath = "/.well-known/jwt-vc-issuer"
	// NoncePath は nonce エンドポイント（OpenID4VCI 7）。
	NoncePath = "/oauth2/vci/nonce"
	// CredentialPath は credential エンドポイント（OpenID4VCI 8）。
	CredentialPath = "/oauth2/vci/credential" // #nosec G101 -- パス
	// OfferPath は参照で渡す申し出（credential_offer_uri。OpenID4VCI 4.1.3）の接頭辞。後ろに ID が付く。
	OfferPath = "/oauth2/vci/offers/"
	// StatusListPath は status list token（Token Status List 8）。
	StatusListPath = "/oauth2/vci/status-list"
)

// GrantTypePreAuthorized は Pre-Authorized Code Flow の grant_type（OpenID4VCI 6.1）。
const GrantTypePreAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// 形式と型。
const (
	// FormatSDJWT は SD-JWT VC（OpenID4VCI 付録 A.3）。
	FormatSDJWT = "dc+sd-jwt"
	// ProofType は proof の JWT の typ（OpenID4VCI 付録 F.1）。
	ProofType = "openid4vci-proof+jwt"
	// StatusListType は status list token の typ。
	StatusListType = "statuslist+jwt"
)

// 寿命と上限。
const (
	// OfferTTL は申し出（Pre-Authorized Code）の期限。
	OfferTTL = 10 * time.Minute
	// NonceTTL は c_nonce の期限。
	NonceTTL = 5 * time.Minute
	// ProofMaxAge は proof の iat の古さの上限、Skew は時刻の許容幅（未来の iat）。
	ProofMaxAge = 5 * time.Minute
	Skew        = time.Minute
	// MaxTxCodeAttempts は tx_code の誤りの上限（超えたら申し出を消す）。
	MaxTxCodeAttempts = 5
	// TxCodeLength は tx_code の桁数（数字）。
	TxCodeLength = 6
	// MaxOfferConfigurations は 1 つの申し出に入れられる定義の数。
	MaxOfferConfigurations = 10
)

// Service は発行者。realm ごとに1つ（Issuer が realm の issuer）。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Keys     *provider.Keys
	Sessions *session.Manager
	Accounts *account.Service
	// Attributes はカスタム属性（フィーチャー custom_attributes）。nil なら attribute:<key> の値は無いものとする。
	Attributes *attribute.Service
	// Issuer は発行者の識別子（realm の issuer。server.public_url と realm のパス）。
	Issuer string
	// AccessTokenTTL は Pre-Authorized Code のアクセストークンの期限（oidc.access_token_ttl）。
	AccessTokenTTL time.Duration
	Log            *slog.Logger
}

// URL は issuer からの相対のパスの URL。
func (s *Service) URL(path string) string { return s.Issuer + path }

func (s *Service) accessTTL() time.Duration {
	if s.AccessTokenTTL > 0 {
		return s.AccessTokenTTL
	}
	return provider.DefaultAccessTokenTTL
}

// Error は OpenID4VCI のエラー（credential エンドポイントは 8.3.1.2、token エンドポイントは RFC 6749 5.2）。Code を返し、
// Reason は監査ログにだけ残す（0022）。
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return "vci: " + e.Code + ": " + e.Reason }

// エラーの code。
const (
	CodeInvalidProof                    = "invalid_proof"
	CodeInvalidNonce                    = "invalid_nonce"
	CodeInvalidCredentialRequest        = "invalid_credential_request" // #nosec G101 -- エラーの code
	CodeUnknownCredentialConfiguration  = "unknown_credential_configuration"
	CodeUnknownCredentialIdentifier     = "unknown_credential_identifier"
	CodeCredentialRequestDenied         = "credential_request_denied" // #nosec G101 -- エラーの code
	CodeInvalidEncryptionParameters     = "invalid_encryption_parameters"
	CodeInvalidGrant                    = "invalid_grant"
	CodeInvalidRequest                  = "invalid_request"
	CodeInvalidToken                    = "invalid_token"
	codeInvalidCredentialConfiguration  = "invalid_credential_configuration" // #nosec G101 -- エラーの code
	codeUnsupportedFormat               = "unsupported_format"
	codeConfigurationExists             = "configuration_exists"
	codeScopeExists                     = "scope_exists"
	codeStatusListExhausted             = "status_list_exhausted"
	reasonMissingMandatoryClaim         = "missing_mandatory_claim"
	reasonConfigurationNotAuthorized    = "configuration_not_authorized"
	reasonSessionEnded                  = "session_ended"
	reasonUnsupportedProofType          = "unsupported_proof_type"
	reasonCredentialIdentifierNotIssued = "credential_identifier_not_issued" // #nosec G101 -- エラーの code
)

func vciError(code, reason string) *Error { return &Error{Code: code, Reason: reason} }

// CodeOf は err の OpenID4VCI のエラーの code と理由を返す（Error でなければ空）。
func CodeOf(err error) (code, reason string) {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code, e.Reason
	}
	return "", ""
}

// hashKey は秘密の値（コード・トークン・申し出の ID）を EphemeralStore のキーにする（値そのものはキーに入れない）。
func hashKey(prefix, secret string) string {
	h := sha256.Sum256([]byte(secret))
	return prefix + hex.EncodeToString(h[:])
}

// record は監査ログに残す。
func record(ctx context.Context, tx port.Tx, clk clock.Clock, typ string, result audit.Result, realmID string, actor audit.Actor,
	requestID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: typ, Result: result, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: details})
	return err
}
