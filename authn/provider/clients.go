package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 連携先（クライアント）の登録（design.md 5.5、ADR 0026）。ホスト先が管理 API で登録したファーストパーティだけ。

// 上限。
const (
	MaxClientNameLength = 100
	MaxRedirectURIs     = 20
	maxURILength        = 2000
	maxJWKSBytes        = 16 << 10
)

var (
	// ErrInvalidClient は登録の内容が正しくない（理由はメッセージ）。
	ErrInvalidClient = errs.WithCode(errs.KindInvalid, "invalid_client_metadata", "invalid client metadata")
	// ErrClientAuth はクライアントの認証の失敗（理由は返さない）。
	ErrClientAuth = errs.WithCode(errs.KindUnauthenticated, "invalid_client", "client authentication failed")
)

func invalidClient(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_client_metadata", msg)
}

// Clients は連携先を管理する。
type Clients struct {
	Clock clock.Clock
	// DeviceFlow は Device Authorization Grant を許せるか（フィーチャー device_flow。ADR 0095）。
	DeviceFlow bool
	// FrontChannel はフィーチャー oidc_logout が動いているか（Front-Channel Logout の登録を受け付けるか。ADR 0094）。
	FrontChannel bool
	// DPoP と MTLS はフィーチャー dpop・mtls_client_auth が動いているか（ADR 0113）。
	DPoP, MTLS bool
	// CIBA は CIBA の登録を受け付けるか（フィーチャー ciba。ADR 0114）。
	CIBA bool
}

// ClientInput は登録・変更の内容。
type ClientInput struct {
	Name                   string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AuthMethod             string
	// JWKS は private_key_jwt の公開鍵（JWKS の JSON）。
	JWKS                 []byte
	IDTokenAlg           string
	BackchannelLogoutURI string
	// DeviceGrant は Device Authorization Grant を許す（フィーチャー device_flow。ADR 0095）。
	DeviceGrant bool
	// FrontchannelLogoutURI と FrontchannelLogoutSessionRequired は Front-Channel Logout（フィーチャー oidc_logout）。
	FrontchannelLogoutURI             string
	FrontchannelLogoutSessionRequired bool
	// DPoPBoundAccessTokens・TLSBoundAccessTokens・TLSAuthField・TLSAuthValue は送信者制約トークンと mTLS の認証（ADR 0113）。
	DPoPBoundAccessTokens bool
	TLSBoundAccessTokens  bool
	TLSAuthField          string
	TLSAuthValue          string
	// CIBAMode は CIBA のトークンの受け取り方（backchannel_token_delivery_mode。空・poll・ping）、CIBANotificationEndpoint は
	// ping の通知先（フィーチャー ciba。ADR 0114）。
	CIBAMode                 string
	CIBANotificationEndpoint string
}

// ValidRedirectURI は連携先の URI に使えるか（絶対 URL、https か loopback の http、フラグメントと userinfo なし）を返す。
func ValidRedirectURI(s string) bool {
	if len(s) > maxURILength {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil || strings.Contains(s, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// validFrontChannelURI は Front-Channel Logout の送り先に使えるかを返す。連携先の URI の条件に加え、scheme・ホスト・ポートが
// 登録した戻り先のどれかと同じであること（OIDC Front-Channel Logout 2）。オリジンは完了画面の CSP（frame-src）に書くので、
// CSP の区切りになる文字を含まないこと。
func validFrontChannelURI(s string, redirectURIs []string) bool {
	if !ValidRedirectURI(s) {
		return false
	}
	o, ok := Origin(s)
	if !ok {
		return false
	}
	return slices.ContainsFunc(redirectURIs, func(r string) bool { ro, ok := Origin(r); return ok && ro == o })
}

// Origin は URI のオリジン（scheme://host[:port]）を返す。CSP のソースに書けない文字を含めば false。
func Origin(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false
	}
	o := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, r := range u.Host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':' || r == '[' || r == ']') {
			return "", false
		}
	}
	return o, true
}

func (in ClientInput) normalize(deviceFlow, ciba bool) (ClientInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > MaxClientNameLength {
		return in, invalidClient("name")
	}
	if in.DeviceGrant && !deviceFlow {
		return in, invalidClient("device_authorization_grant")
	}
	if err := in.checkCIBA(ciba); err != nil {
		return in, err
	}
	// Device Authorization Grant・CIBA だけを使う連携先（CLI・コールセンターなど）は戻り先を持たなくてよい。
	if (len(in.RedirectURIs) == 0 && !in.DeviceGrant && in.CIBAMode == "") || len(in.RedirectURIs) > MaxRedirectURIs || len(in.PostLogoutRedirectURIs) > MaxRedirectURIs {
		return in, invalidClient("redirect_uris")
	}
	for _, u := range append(slices.Clone(in.RedirectURIs), in.PostLogoutRedirectURIs...) {
		if !ValidRedirectURI(u) {
			return in, invalidClient("redirect uri " + u)
		}
	}
	in.RedirectURIs = slices.Compact(slices.Clone(in.RedirectURIs))
	if in.RedirectURIs == nil {
		in.RedirectURIs = []string{}
	}
	if in.PostLogoutRedirectURIs == nil {
		in.PostLogoutRedirectURIs = []string{}
	}
	if in.BackchannelLogoutURI != "" && !ValidRedirectURI(in.BackchannelLogoutURI) {
		return in, invalidClient("backchannel_logout_uri")
	}
	if in.FrontchannelLogoutURI == "" {
		in.FrontchannelLogoutSessionRequired = false
	} else if !validFrontChannelURI(in.FrontchannelLogoutURI, in.RedirectURIs) {
		return in, invalidClient("frontchannel_logout_uri")
	}
	if in.IDTokenAlg == "" {
		// 既定は ES256（ML-DSA-65 を検証できる RP がまだ少ないため。9.3）。
		in.IDTokenAlg = port.AlgES256
	}
	if !slices.Contains(Algs, in.IDTokenAlg) {
		return in, invalidClient("id_token_signed_response_alg")
	}
	if in.AuthMethod == port.ClientAuthTLS {
		if !validTLSAuth(in.TLSAuthField, in.TLSAuthValue) {
			return in, invalidClient("tls_client_auth needs exactly one of tls_client_auth_subject_dn, _san_dns, _san_uri, _san_ip, _san_email")
		}
	} else if in.TLSAuthField != "" || in.TLSAuthValue != "" {
		return in, invalidClient("tls_client_auth_* is only for tls_client_auth")
	}
	switch in.AuthMethod {
	case port.ClientAuthSecret, port.ClientAuthNone, port.ClientAuthTLS:
		if len(in.JWKS) > 0 {
			return in, invalidClient("jwks is only for private_key_jwt and self_signed_tls_client_auth")
		}
		in.JWKS = nil
	case port.ClientAuthPrivateKeyJWT, port.ClientAuthSelfSignedTLS:
		if len(in.JWKS) == 0 || len(in.JWKS) > maxJWKSBytes {
			return in, invalidClient("jwks")
		}
		set, err := jwk.Parse(in.JWKS)
		if err != nil || set.Len() == 0 {
			return in, invalidClient("jwks")
		}
		for i := range set.Len() {
			k, _ := set.Key(i)
			if !publicOnly(k) {
				return in, invalidClient("jwks must contain public keys only")
			}
		}
	default:
		return in, invalidClient("token_endpoint_auth_method")
	}
	return in, nil
}

// checkCIBA は CIBA の登録を確かめる（ADR 0114）。フィーチャーが動いていなければ登録できない。機密の連携先だけで、push モードは
// 持たない。ping は通知先（連携先の URI の条件。https かループバックの http）が要り、poll では通知先を持たない。
func (in ClientInput) checkCIBA(enabled bool) error {
	switch in.CIBAMode {
	case "":
		if in.CIBANotificationEndpoint != "" {
			return invalidClient("backchannel_client_notification_endpoint requires backchannel_token_delivery_mode ping")
		}
		return nil
	case port.CIBAPoll, port.CIBAPing:
	default:
		return invalidClient("backchannel_token_delivery_mode")
	}
	if !enabled {
		return invalidClient("backchannel_token_delivery_mode: the ciba feature is not enabled")
	}
	if in.AuthMethod == port.ClientAuthNone {
		return invalidClient("backchannel_token_delivery_mode requires a confidential client")
	}
	if in.CIBAMode == port.CIBAPoll && in.CIBANotificationEndpoint != "" {
		return invalidClient("backchannel_client_notification_endpoint is only for ping")
	}
	if in.CIBAMode == port.CIBAPing && !ValidRedirectURI(in.CIBANotificationEndpoint) {
		return invalidClient("backchannel_client_notification_endpoint")
	}
	return nil
}

// publicOnly は JWK が秘密の項目（RFC 7518 の d・p・q など、対称鍵の k、AKP の priv）を持たないかを返す。
func publicOnly(k jwk.Key) bool {
	b, err := json.Marshal(k)
	if err != nil {
		return false
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	for _, f := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"} {
		if _, ok := m[f]; ok {
			return false
		}
	}
	return true
}

func newSecret() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(s))
	return s, h[:], nil
}

func (c *Clients) record(ctx context.Context, tx port.Tx, realmID string, actor audit.Actor, requestID, typ string, cl port.Client) error {
	details := map[string]any{"client_id": cl.PublicID, "name": cl.Name, "auth_method": cl.AuthMethod,
		"id_token_alg": cl.IDTokenAlg, "redirect_uris": cl.RedirectURIs}
	if cl.DeviceGrant {
		details["device_authorization_grant"] = true
	}
	if cl.DPoPBoundAccessTokens {
		details["dpop_bound_access_tokens"] = true
	}
	if cl.TLSBoundAccessTokens {
		details["tls_client_certificate_bound_access_tokens"] = true
	}
	if cl.TLSAuthField != "" {
		details["tls_client_auth_"+cl.TLSAuthField] = cl.TLSAuthValue
	}
	if cl.CIBAMode != "" {
		details["backchannel_token_delivery_mode"] = cl.CIBAMode
	}
	_, err := eventlog.Record(ctx, tx, c.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor,
		RequestID: requestID, Details: details})
	return err
}

// checkFrontChannel は、フィーチャー oidc_logout が動いていないときに Front-Channel Logout の登録を拒む。無効化の途中で
// 残っている値は、変えなければそのまま受け付ける（ほかの項目を変えられるように）。外すのは受け付ける。
func (c *Clients) checkFrontChannel(in ClientInput, prev port.Client) error {
	if c.FrontChannel || in.FrontchannelLogoutURI == "" ||
		(in.FrontchannelLogoutURI == prev.FrontchannelLogoutURI && in.FrontchannelLogoutSessionRequired == prev.FrontchannelLogoutSessionRequired) {
		return nil
	}
	return invalidClient("frontchannel_logout_uri: the oidc_logout feature is not enabled")
}

// checkSenderConstraint は、フィーチャー dpop・mtls_client_auth が動いていないときに、その設定を新しく入れるのを拒む
// （ADR 0113）。今の値から変えないもの・外すものは受け付ける。
func (c *Clients) checkSenderConstraint(in ClientInput, prev port.Client) error {
	if !c.DPoP && in.DPoPBoundAccessTokens && !prev.DPoPBoundAccessTokens {
		return invalidClient("dpop_bound_access_tokens: the dpop feature is not enabled")
	}
	if c.MTLS {
		return nil
	}
	if in.TLSBoundAccessTokens && !prev.TLSBoundAccessTokens {
		return invalidClient("tls_client_certificate_bound_access_tokens: the mtls_client_auth feature is not enabled")
	}
	tlsMethod := in.AuthMethod == port.ClientAuthTLS || in.AuthMethod == port.ClientAuthSelfSignedTLS
	if tlsMethod && (in.AuthMethod != prev.AuthMethod || in.TLSAuthField != prev.TLSAuthField || in.TLSAuthValue != prev.TLSAuthValue) {
		return invalidClient("token_endpoint_auth_method: the mtls_client_auth feature is not enabled")
	}
	return nil
}

// Create は連携先を登録する。client_secret なら秘密を1度だけ返す（保存するのはハッシュだけ）。
func (c *Clients) Create(ctx context.Context, tx port.Tx, realmID string, in ClientInput, actor audit.Actor, requestID string) (port.Client, string, error) {
	in, err := in.normalize(c.DeviceFlow, c.CIBA)
	if err != nil {
		return port.Client{}, "", err
	}
	if err := c.checkFrontChannel(in, port.Client{}); err != nil {
		return port.Client{}, "", err
	}
	if err := c.checkSenderConstraint(in, port.Client{}); err != nil {
		return port.Client{}, "", err
	}
	now := c.Clock.Now()
	cl := port.Client{ID: id.New(id.Client), PublicID: id.NewExternal(id.Client), RealmID: realmID, Name: in.Name, TrustLevel: port.TrustFirstParty,
		RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs, AuthMethod: in.AuthMethod, JWKS: in.JWKS,
		IDTokenAlg: in.IDTokenAlg, BackchannelLogoutURI: in.BackchannelLogoutURI, DeviceGrant: in.DeviceGrant,
		FrontchannelLogoutURI: in.FrontchannelLogoutURI, FrontchannelLogoutSessionRequired: in.FrontchannelLogoutSessionRequired,
		DPoPBoundAccessTokens: in.DPoPBoundAccessTokens, TLSBoundAccessTokens: in.TLSBoundAccessTokens, TLSAuthField: in.TLSAuthField,
		TLSAuthValue: in.TLSAuthValue, CIBAMode: in.CIBAMode, CIBANotificationEndpoint: in.CIBANotificationEndpoint,
		CreatedAt: now, UpdatedAt: now}
	var secret string
	if cl.AuthMethod == port.ClientAuthSecret {
		if secret, cl.SecretHash, err = newSecret(); err != nil {
			return port.Client{}, "", err
		}
	}
	if err := tx.Clients().Create(ctx, cl); err != nil {
		return port.Client{}, "", err
	}
	return cl, secret, c.record(ctx, tx, realmID, actor, requestID, "client.created", cl)
}

// Update は連携先の内容を置き換える。認証方式を client_secret に変えたときは新しい秘密を返す。
func (c *Clients) Update(ctx context.Context, tx port.Tx, cl port.Client, in ClientInput, actor audit.Actor, requestID string) (port.Client, string, error) {
	in, err := in.normalize(c.DeviceFlow, c.CIBA)
	if err != nil {
		return port.Client{}, "", err
	}
	if err := c.checkFrontChannel(in, cl); err != nil {
		return port.Client{}, "", err
	}
	if err := c.checkSenderConstraint(in, cl); err != nil {
		return port.Client{}, "", err
	}
	var secret string
	if in.AuthMethod != port.ClientAuthSecret {
		cl.SecretHash = nil
	} else if cl.AuthMethod != port.ClientAuthSecret {
		if secret, cl.SecretHash, err = newSecret(); err != nil {
			return port.Client{}, "", err
		}
	}
	cl.Name, cl.RedirectURIs, cl.PostLogoutRedirectURIs, cl.AuthMethod = in.Name, in.RedirectURIs, in.PostLogoutRedirectURIs, in.AuthMethod
	cl.JWKS, cl.IDTokenAlg, cl.BackchannelLogoutURI, cl.UpdatedAt = in.JWKS, in.IDTokenAlg, in.BackchannelLogoutURI, c.Clock.Now()
	cl.DeviceGrant = in.DeviceGrant
	cl.CIBAMode, cl.CIBANotificationEndpoint = in.CIBAMode, in.CIBANotificationEndpoint
	cl.FrontchannelLogoutURI, cl.FrontchannelLogoutSessionRequired = in.FrontchannelLogoutURI, in.FrontchannelLogoutSessionRequired
	cl.DPoPBoundAccessTokens, cl.TLSBoundAccessTokens = in.DPoPBoundAccessTokens, in.TLSBoundAccessTokens
	cl.TLSAuthField, cl.TLSAuthValue = in.TLSAuthField, in.TLSAuthValue
	if cl.AuthMethod == port.ClientAuthNone {
		// 公開クライアントには交換を許さない（ADR 0099）。
		cl.TokenExchange = nil
	}
	if err := tx.Clients().Update(ctx, cl); err != nil {
		return port.Client{}, "", err
	}
	return cl, secret, c.record(ctx, tx, cl.RealmID, actor, requestID, "client.updated", cl)
}

// RotateSecret は client_secret を新しくする（古い秘密はすぐ使えなくなる）。
func (c *Clients) RotateSecret(ctx context.Context, tx port.Tx, cl port.Client, actor audit.Actor, requestID string) (string, error) {
	if cl.AuthMethod != port.ClientAuthSecret {
		return "", errs.WithCode(errs.KindFailedPrecondition, "no_client_secret", "client does not use a secret")
	}
	secret, h, err := newSecret()
	if err != nil {
		return "", err
	}
	cl.SecretHash, cl.UpdatedAt = h, c.Clock.Now()
	if err := tx.Clients().Update(ctx, cl); err != nil {
		return "", err
	}
	return secret, c.record(ctx, tx, cl.RealmID, actor, requestID, "client.secret_rotated", cl)
}

// Delete は連携先を消す。
func (c *Clients) Delete(ctx context.Context, tx port.Tx, cl port.Client, actor audit.Actor, requestID string) error {
	if err := tx.Clients().Delete(ctx, cl.RealmID, cl.ID); err != nil {
		return err
	}
	return c.record(ctx, tx, cl.RealmID, actor, requestID, "client.deleted", cl)
}

// AuthenticateSecret は client_secret で連携先を認証する。無い連携先・方式の違い・秘密の誤りは区別しない。
func AuthenticateSecret(ctx context.Context, tx port.Tx, realmID, clientID, secret string) (port.Client, error) {
	cl, err := tx.Clients().GetByPublicID(ctx, realmID, clientID)
	if errors.Is(err, errs.NotFound) {
		return port.Client{}, ErrClientAuth
	}
	if err != nil {
		return port.Client{}, err
	}
	h := sha256.Sum256([]byte(secret))
	if cl.AuthMethod != port.ClientAuthSecret || subtle.ConstantTimeCompare(h[:], cl.SecretHash) != 1 {
		return port.Client{}, ErrClientAuth
	}
	return cl, nil
}

// MaxAssertionLifetime は client_assertion の exp の上限（今からの長さ）。jti の再利用の検知はこの間だけ覚える。
const MaxAssertionLifetime = 5 * time.Minute

// AssertionReplay は client_assertion の jti を覚える（1回だけ使える。RFC 7523 3）。
type AssertionReplay interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// AuthenticateAssertion は private_key_jwt の client_assertion で連携先を認証する（OIDC Core 9、RFC 7523）。
// iss と sub は client_id、aud は audiences（token エンドポイントの URL か issuer）のどれか、exp は今から
// MaxAssertionLifetime 以内、jti は未使用であること。理由は返さない。
func AuthenticateAssertion(ctx context.Context, tx port.Tx, replay AssertionReplay, clk clock.Clock, realmID, clientID, assertion string,
	audiences []string) (port.Client, error) {
	if clientID == "" {
		// client_id を省いたときは、署名の検証の前に iss を読む（検証の後で sub・iss と照合する）。
		t, err := jwt.ParseInsecure([]byte(assertion))
		if err != nil {
			return port.Client{}, ErrClientAuth
		}
		if clientID, _ = t.Issuer(); clientID == "" {
			return port.Client{}, ErrClientAuth
		}
	}
	cl, err := tx.Clients().GetByPublicID(ctx, realmID, clientID)
	if errors.Is(err, errs.NotFound) {
		return port.Client{}, ErrClientAuth
	}
	if err != nil {
		return port.Client{}, err
	}
	if cl.AuthMethod != port.ClientAuthPrivateKeyJWT {
		return port.Client{}, ErrClientAuth
	}
	set, err := jwk.Parse(cl.JWKS)
	if err != nil {
		return port.Client{}, ErrClientAuth
	}
	now := clk.Now()
	t, err := jwt.Parse([]byte(assertion), jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)), jwt.WithValidate(true),
		jwt.WithClock(jwt.ClockFunc(clk.Now)), jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithIssuer(cl.PublicID), jwt.WithSubject(cl.PublicID), jwt.WithRequiredClaim(jwt.ExpirationKey), jwt.WithRequiredClaim(jwt.JwtIDKey))
	if err != nil {
		return port.Client{}, ErrClientAuth
	}
	aud, _ := t.Audience()
	if !slices.ContainsFunc(aud, func(a string) bool { return slices.Contains(audiences, a) }) {
		return port.Client{}, ErrClientAuth
	}
	exp, _ := t.Expiration()
	if exp.Sub(now) > MaxAssertionLifetime {
		return port.Client{}, ErrClientAuth
	}
	jti, _ := t.JwtID()
	h := sha256.Sum256([]byte(cl.PublicID + "\x00" + jti))
	n, err := replay.Incr(ctx, "oidc:assertion:v1:"+base64.RawURLEncoding.EncodeToString(h[:]), MaxAssertionLifetime+time.Minute)
	if err != nil {
		return port.Client{}, err
	}
	if n != 1 {
		return port.Client{}, ErrClientAuth
	}
	return cl, nil
}
