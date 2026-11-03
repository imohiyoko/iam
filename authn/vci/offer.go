package vci

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 申し出（Credential Offer）・Pre-Authorized Code・アクセストークン・c_nonce（ADR 0119）。状態は EphemeralStore に封をして置く。

const (
	codePrefix     = "vci:code:v1:"
	offerPrefix    = "vci:offer:v1:"
	attemptPrefix  = "vci:txcode:v1:"
	tokenPrefix    = "vci:token:v1:" // #nosec G101 -- 鍵の接頭辞
	noncePrefix    = "vci:nonce:used:v1:"
	codePurpose    = "flow.vci_pre_authorized_code"
	offerPurpose   = "flow.vci_offer"
	tokenPurpose   = "flow.vci_access_token"
	noncePurpose   = "flow.vci_c_nonce"
	tokenValuePref = "vci_"
	// OfferScheme は申し出の URI の scheme（OpenID4VCI 4.1）。
	OfferScheme = "openid-credential-offer://"
)

// preAuth は Pre-Authorized Code の中身。
type preAuth struct {
	RealmID          string    `json:"realm_id"`
	UserID           string    `json:"user_id"`
	SID              string    `json:"sid"`
	ConfigurationIDs []string  `json:"configuration_ids"`
	TxCode           string    `json:"tx_code,omitempty"`
	OfferID          string    `json:"offer_id"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// Grant はアクセストークンで credential エンドポイントに許したこと。
type Grant struct {
	RealmID string
	UserID  string
	// SID はログインの系列。Pre-Authorized Code では発行のときに系列がまだ使えるかを確かめる（Authorization Code Flow は呼び出し側が確かめる）。
	SID string
	// ConfigurationIDs は許した定義（Pre-Authorized Code）。Scopes は認可のスコープ（Authorization Code Flow）。どちらかで許す。
	ConfigurationIDs []string
	Scopes           []string
	// ClientID はトークンの連携先（匿名なら空）。proof の iss と比べる。
	ClientID string
	// Flow は監査ログに残すフロー（pre-authorized_code・authorization_code）。
	Flow string
	// checkLineage は発行のときに系列を確かめるか（Pre-Authorized Code）。
	checkLineage bool
}

// フロー。
const (
	FlowPreAuthorized = "pre-authorized_code"
	FlowAuthorization = "authorization_code"
)

// AuthorizationGrant は Authorization Code Flow のアクセストークン（server が確かめたもの）の Grant。
func AuthorizationGrant(realmID, userID, clientID string, scopes []string) Grant {
	return Grant{RealmID: realmID, UserID: userID, Scopes: scopes, ClientID: clientID, Flow: FlowAuthorization}
}

type accessToken struct {
	RealmID          string    `json:"realm_id"`
	UserID           string    `json:"user_id"`
	SID              string    `json:"sid"`
	ConfigurationIDs []string  `json:"configuration_ids"`
	ClientID         string    `json:"client_id,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newTxCode() (string, error) {
	var b strings.Builder
	for range TxCodeLength {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte("0123456789"[n.Int64()])
	}
	return b.String(), nil
}

func (s *Service) put(ctx context.Context, key, purpose string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := s.Crypter.Seal(ctx, purpose, b)
	if err != nil {
		return err
	}
	return s.Cache.Set(ctx, key, sealed, ttl)
}

func (s *Service) open(ctx context.Context, purpose string, sealed []byte, v any) error {
	b, err := s.Crypter.Open(ctx, purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// OfferRequest は本人の申し出の要求。
type OfferRequest struct {
	RealmID          string
	UserID           string
	SID              string
	ConfigurationIDs []string
	// TxCode は tx_code を求めるか（定義の require_tx_code があれば偽でも求める）。
	TxCode bool
}

// Offer は作った申し出。
type Offer struct {
	ID string
	// Object は申し出（credential_offer の JSON の値）。
	Object map[string]any
	// TxCode は本人に見せる tx_code（求めなければ空）。ほかには残さない。
	TxCode    string
	ExpiresAt time.Time
}

// ByValueURI は値で渡す申し出の URI。
func (o Offer) ByValueURI() (string, error) {
	b, err := json.Marshal(o.Object)
	if err != nil {
		return "", err
	}
	return OfferScheme + "?" + url.Values{"credential_offer": {string(b)}}.Encode(), nil
}

// ReferenceURL は参照で渡す申し出の URL（credential_offer_uri）。
func (s *Service) ReferenceURL(offerID string) string { return s.URL(OfferPath + offerID) }

// ByReferenceURI は参照で渡す申し出の URI。
func (s *Service) ByReferenceURI(offerID string) string {
	return OfferScheme + "?" + url.Values{"credential_offer_uri": {s.ReferenceURL(offerID)}}.Encode()
}

// ErrUnknownConfiguration は申し出の定義が realm に無いこと。
var ErrUnknownConfiguration = errs.WithCode(errs.KindInvalid, CodeUnknownCredentialConfiguration, "unknown credential configuration")

// CreateOffer は本人の申し出を作る（Pre-Authorized Code Flow。OpenID4VCI 4.1.1）。
func (s *Service) CreateOffer(ctx context.Context, tx port.Tx, r OfferRequest, actor audit.Actor, requestID string) (Offer, error) {
	if len(r.ConfigurationIDs) == 0 || len(r.ConfigurationIDs) > MaxOfferConfigurations {
		return Offer{}, errs.WithCode(errs.KindInvalid, "invalid_request", "credential_configuration_ids must have 1-10 entries")
	}
	ids := []string{}
	txCode := r.TxCode
	for _, cid := range r.ConfigurationIDs {
		if slices.Contains(ids, cid) {
			continue
		}
		c, err := tx.VCI().GetConfigurationByConfigurationID(ctx, r.RealmID, cid)
		if errors.Is(err, errs.NotFound) {
			return Offer{}, ErrUnknownConfiguration
		}
		if err != nil {
			return Offer{}, err
		}
		cfg, err := Parse(c)
		if err != nil {
			return Offer{}, err
		}
		txCode = txCode || cfg.RequireTxCode
		ids = append(ids, cid)
	}
	code, err := randomToken()
	if err != nil {
		return Offer{}, err
	}
	offerID, err := randomToken()
	if err != nil {
		return Offer{}, err
	}
	o := Offer{ID: offerID, ExpiresAt: s.Clock.Now().Add(OfferTTL)}
	grant := map[string]any{"pre-authorized_code": code}
	if txCode {
		if o.TxCode, err = newTxCode(); err != nil {
			return Offer{}, err
		}
		grant["tx_code"] = map[string]any{"input_mode": "numeric", "length": TxCodeLength}
	}
	o.Object = map[string]any{"credential_issuer": s.Issuer, "credential_configuration_ids": ids,
		"grants": map[string]any{GrantTypePreAuthorized: grant}}
	p := preAuth{RealmID: r.RealmID, UserID: r.UserID, SID: r.SID, ConfigurationIDs: ids, TxCode: o.TxCode, OfferID: offerID, ExpiresAt: o.ExpiresAt}
	if err := s.put(ctx, hashKey(codePrefix, code), codePurpose, p, OfferTTL); err != nil {
		return Offer{}, err
	}
	if err := s.put(ctx, hashKey(offerPrefix, offerID), offerPurpose, o.Object, OfferTTL); err != nil {
		return Offer{}, err
	}
	return o, record(ctx, tx, s.Clock, "vci.offer_created", audit.ResultSuccess, r.RealmID, actor, requestID,
		map[string]any{"configuration_ids": ids, "tx_code": txCode})
}

// LookupOffer は参照で渡した申し出を返す（期限まで何度でも。引き換えた後は無い）。無ければ errs.NotFound。
func (s *Service) LookupOffer(ctx context.Context, offerID string) (map[string]any, error) {
	if offerID == "" || len(offerID) > 64 {
		return nil, errs.New(errs.KindNotFound, "offer")
	}
	b, ok, err := s.Cache.Get(ctx, hashKey(offerPrefix, offerID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errs.New(errs.KindNotFound, "offer")
	}
	var m map[string]any
	if err := s.open(ctx, offerPurpose, b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// TokenRequest は Pre-Authorized Code の token 要求（OpenID4VCI 6.1）。
type TokenRequest struct {
	RealmID string
	Code    string
	// TxCode は tx_code。HasTxCode は要求に tx_code の項目があったか。
	TxCode    string
	HasTxCode bool
	// ClientID は要求の client_id（任意。匿名なら空）。
	ClientID  string
	RequestID string
}

// Token は発行したアクセストークン。
type Token struct {
	AccessToken string
	ExpiresIn   time.Duration
}

func (s *Service) tokenRejected(ctx context.Context, realmID, userID, reason, requestID string) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		actor := audit.Actor{Type: "anonymous"}
		if userID != "" {
			if u, err := tx.Users().Get(ctx, realmID, userID); err == nil {
				actor = audit.Actor{Type: "user", ID: u.PublicID}
			}
		}
		return record(ctx, tx, s.Clock, "vci.token_rejected", audit.ResultFailure, realmID, actor, requestID, map[string]any{"reason": reason})
	})
	if err != nil && s.Log != nil {
		s.Log.WarnContext(ctx, "vci: audit token rejection", "error", err)
	}
}

// Redeem は Pre-Authorized Code を引き換えてアクセストークンを発行する。コードは 1 回だけ使え、tx_code の誤りは
// MaxTxCodeAttempts 回で申し出を消す。誤りは *Error（invalid_grant・invalid_request）。
func (s *Service) Redeem(ctx context.Context, r TokenRequest) (Token, error) {
	if r.Code == "" || len(r.Code) > 128 {
		return Token{}, vciError(CodeInvalidRequest, "pre-authorized_code is required")
	}
	key := hashKey(codePrefix, r.Code)
	b, ok, err := s.Cache.Get(ctx, key)
	if err != nil {
		return Token{}, err
	}
	if !ok {
		s.tokenRejected(ctx, r.RealmID, "", "unknown_code", r.RequestID)
		return Token{}, vciError(CodeInvalidGrant, "unknown code")
	}
	var p preAuth
	if err := s.open(ctx, codePurpose, b, &p); err != nil {
		return Token{}, err
	}
	now := s.Clock.Now()
	if p.RealmID != r.RealmID || !now.Before(p.ExpiresAt) {
		s.tokenRejected(ctx, r.RealmID, "", "unknown_code", r.RequestID)
		return Token{}, vciError(CodeInvalidGrant, "unknown code")
	}
	switch {
	case p.TxCode == "" && r.HasTxCode:
		s.tokenRejected(ctx, r.RealmID, p.UserID, "unexpected_tx_code", r.RequestID)
		return Token{}, vciError(CodeInvalidRequest, "tx_code was not expected")
	case p.TxCode != "" && !r.HasTxCode:
		s.tokenRejected(ctx, r.RealmID, p.UserID, "missing_tx_code", r.RequestID)
		return Token{}, vciError(CodeInvalidRequest, "tx_code is required")
	case p.TxCode != "" && subtle.ConstantTimeCompare([]byte(p.TxCode), []byte(r.TxCode)) != 1:
		n, err := s.Cache.Incr(ctx, hashKey(attemptPrefix, r.Code), OfferTTL)
		if err != nil {
			return Token{}, err
		}
		if n >= MaxTxCodeAttempts {
			// 上限に達したら申し出を消す（コードを総当たりの対象にしない）。
			if _, _, err := s.Cache.Take(ctx, key); err != nil {
				return Token{}, err
			}
			if err := s.Cache.Delete(ctx, hashKey(offerPrefix, p.OfferID)); err != nil {
				return Token{}, err
			}
		}
		s.tokenRejected(ctx, r.RealmID, p.UserID, "wrong_tx_code", r.RequestID)
		return Token{}, vciError(CodeInvalidGrant, "wrong tx_code")
	}
	// 1 回だけ：取り出せなければ、ほかの要求が先に引き換えた。
	if _, ok, err := s.Cache.Take(ctx, key); err != nil {
		return Token{}, err
	} else if !ok {
		s.tokenRejected(ctx, r.RealmID, p.UserID, "code_reused", r.RequestID)
		return Token{}, vciError(CodeInvalidGrant, "code already used")
	}
	if err := s.Cache.Delete(ctx, hashKey(offerPrefix, p.OfferID)); err != nil {
		return Token{}, err
	}
	secret, err := randomToken()
	if err != nil {
		return Token{}, err
	}
	token := tokenValuePref + secret
	ttl := s.accessTTL()
	at := accessToken{RealmID: p.RealmID, UserID: p.UserID, SID: p.SID, ConfigurationIDs: p.ConfigurationIDs, ClientID: r.ClientID,
		ExpiresAt: now.Add(ttl)}
	if err := s.put(ctx, hashKey(tokenPrefix, token), tokenPurpose, at, ttl); err != nil {
		return Token{}, err
	}
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().Get(ctx, p.RealmID, p.UserID)
		if err != nil {
			return err
		}
		d := map[string]any{"configuration_ids": p.ConfigurationIDs, "grant_type": GrantTypePreAuthorized}
		if r.ClientID != "" {
			d["client_id"] = r.ClientID
		}
		return record(ctx, tx, s.Clock, "vci.token_issued", audit.ResultSuccess, p.RealmID, audit.Actor{Type: "user", ID: u.PublicID}, r.RequestID, d)
	})
	if err != nil {
		return Token{}, err
	}
	return Token{AccessToken: token, ExpiresIn: ttl}, nil
}

// IsAccessToken は Pre-Authorized Code のアクセストークンの形か（OIDC のアクセストークンと見分ける）。
func IsAccessToken(token string) bool { return strings.HasPrefix(token, tokenValuePref) }

// Bearer は Pre-Authorized Code のアクセストークンを確かめる。使えなければ invalid_token の *Error。
func (s *Service) Bearer(ctx context.Context, realmID, token string) (Grant, error) {
	if !IsAccessToken(token) || len(token) > 128 {
		return Grant{}, vciError(CodeInvalidToken, "malformed")
	}
	b, ok, err := s.Cache.Get(ctx, hashKey(tokenPrefix, token))
	if err != nil {
		return Grant{}, err
	}
	if !ok {
		return Grant{}, vciError(CodeInvalidToken, "unknown")
	}
	var at accessToken
	if err := s.open(ctx, tokenPurpose, b, &at); err != nil {
		return Grant{}, err
	}
	if at.RealmID != realmID || !s.Clock.Now().Before(at.ExpiresAt) {
		return Grant{}, vciError(CodeInvalidToken, "expired")
	}
	return Grant{RealmID: at.RealmID, UserID: at.UserID, SID: at.SID, ConfigurationIDs: at.ConfigurationIDs, ClientID: at.ClientID,
		Flow: FlowPreAuthorized, checkLineage: true}, nil
}

type nonceValue struct {
	RealmID   string `json:"r"`
	ExpiresAt int64  `json:"e"`
}

// Nonce は c_nonce を作る（OpenID4VCI 7）。状態を持たない：realm と期限を封をした値。使うときに印を付ける（useNonce）。
func (s *Service) Nonce(ctx context.Context, realmID string) (string, error) {
	b, err := json.Marshal(nonceValue{RealmID: realmID, ExpiresAt: s.Clock.Now().Add(NonceTTL).Unix()})
	if err != nil {
		return "", err
	}
	sealed, err := s.Crypter.Seal(ctx, noncePurpose, b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// maxNonce は c_nonce の文字数の上限（封の大きさに余裕を見たもの）。
const maxNonce = 512

// useNonce は c_nonce が realm の期限内のもので、まだ使われていないことを確かめ、使用済みにする。
func (s *Service) useNonce(ctx context.Context, realmID, nonce string) error {
	if len(nonce) > maxNonce {
		return vciError(CodeInvalidNonce, "malformed")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return vciError(CodeInvalidNonce, "malformed")
	}
	b, err := s.Crypter.Open(ctx, noncePurpose, sealed)
	if err != nil {
		return vciError(CodeInvalidNonce, "not issued here")
	}
	var v nonceValue
	if err := json.Unmarshal(b, &v); err != nil {
		return vciError(CodeInvalidNonce, "malformed")
	}
	now := s.Clock.Now()
	if v.RealmID != realmID || now.Unix() >= v.ExpiresAt {
		return vciError(CodeInvalidNonce, "expired")
	}
	n, err := s.Cache.Incr(ctx, hashKey(noncePrefix, nonce), time.Unix(v.ExpiresAt, 0).Sub(now)+time.Minute)
	if err != nil {
		return err
	}
	if n != 1 {
		return vciError(CodeInvalidNonce, "reused")
	}
	return nil
}
