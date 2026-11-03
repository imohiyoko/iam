// Package saml は外部 IdP としての SAML 2.0 による登録とログインを行う（iam が SP になる。ADR 0098）。
//
// セキュリティ上重要なコード（design.md 13.2）。不変条件：
//   - 署名を確かめた Assertion だけを受ける（verify.go）。署名は SHA-256 以上、暗号化された Assertion は受けない
//   - 応答は要求したフローに結び付け、1 回限り：RelayState で取り出すフローの状態（EphemeralStore に封をして置く）は
//     Take で 1 回だけ取り出せ、要求したブラウザのフロー ID（Cookie か API の応答）と AuthnRequest の ID（InResponseTo）に結び付ける。
//     IdP からの一方的な応答（IdP-initiated）は受けない
//   - Assertion の ID は connection ごとに 1 回だけ受ける
//   - ログイン・登録・連携は OIDC と同じ扱い（oauth.LoginFederated）。Org 専用 SSO の connection では、その Org の管理ユーザーだけが
//     ログイン・連携でき、登録は Org が証明したドメインのアドレスに限る（ADR 0077）
//   - ACS の URL と SP の Entity ID はサーバーが決める（Org は選べない）
package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー saml の宣言（既定オフ。ADR 0089、0098）。Org 専用 SSO で使うには org_managed_users も要る。
var Feature = feature.Feature{Name: feature.SAML, DataVersion: 1}

// Type は connections.type。
const Type = "saml"

// methodSAML は監査ログの method。
const methodSAML = "saml"

// Config は connections.config（JSON）。
type Config struct {
	IdPEntityID string `json:"idp_entity_id"`
	SSOURL      string `json:"sso_url"`
	// IdPCerts は IdP の署名の証明書（DER）。
	IdPCerts [][]byte `json:"idp_certs"`
	// MetadataURL はメタデータを取得した URL（登録のときに一度だけ取得する）。XML で登録したなら空。
	MetadataURL string `json:"metadata_url,omitempty"`
	SPEntityID  string `json:"sp_entity_id"`
	ACSURL      string `json:"acs_url"`
	// SPKey は SP の署名鍵（ECDSA P-256 の PKCS#8）を pii.Crypter.Seal で封をしたもの。SPCert はその自己署名の証明書（DER）。
	SPKey        []byte `json:"sp_key_sealed"`
	SPCert       []byte `json:"sp_cert"`
	SignRequests bool   `json:"sign_requests"`
	// NameIDFormat は AuthnRequest で求める NameID の形式（空なら IdP に任せる）。
	NameIDFormat string `json:"name_id_format,omitempty"`
	// EmailAttribute はメールの属性の名前（空なら既定の名前を順に見て、無ければ emailAddress 形式の NameID）。
	EmailAttribute string `json:"email_attribute,omitempty"`
	// TrustEmail は IdP が返すメールを確認済みとみなすか（realm 共通の connection だけ。運営者が決める）。
	// Org 専用の connection では、Org が証明したドメインのアドレスに限って確認済みとみなす（ADR 0077）。
	TrustEmail bool `json:"trust_email,omitempty"`
}

// 既定のメールの属性の名前（よく使われるもの）。
var defaultEmailAttributes = []string{
	"email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
}

const (
	keyPurpose  = "connection.saml_sp_key"
	sealPurpose = "flow.saml"
)

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = oauth.ErrAuthFailed

// ErrPublicURLRequired は server.public_url が無く、ACS の URL が決まらないこと。
var ErrPublicURLRequired = errs.WithCode(errs.KindInvalid, "public_url_required", "saml: the ACS URL is not configured (server.public_url)")

// Service は SAML のフローを扱う。
type Service struct {
	Storage port.Storage
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
	// OAuth はログイン・登録・連携（OIDC と同じ扱い）と、外部の URL への問い合わせに使う。
	OAuth *oauth.Service
	// BaseURL は realm の公開の URL（OIDC の issuer と同じ）。ACS と SP の Entity ID はこれから作る。空なら使えない。
	BaseURL string
	Dev     bool
	TTL     time.Duration // フローの期限。既定 10 分
	Log     *slog.Logger
}

// ACSPath は ACS（HTTP-POST）のパス。MetadataPath は SP のメタデータのパスの接頭辞（後ろに slug）。
const (
	ACSPath      = "/login/saml/acs"
	MetadataPath = "/login/saml/metadata/"
)

// ConnectionInput は connection の登録の入力。MetadataXML と MetadataURL のどちらか 1 つ。
type ConnectionInput struct {
	MetadataXML []byte
	MetadataURL string
	// EntityID はメタデータに IdP が複数あるときに選ぶ。
	EntityID       string
	SignRequests   bool
	NameIDFormat   string
	EmailAttribute string
	TrustEmail     bool
}

// NewConnection は connection を作る（保存はしない）。slug が空なら connection の ID を slug にする（Org 専用。ADR 0077）。
// ownerOrgID が空なら realm 共通。メタデータの URL は公開のアドレスに限って取得する（SSRF を防ぐ）。
func (s *Service) NewConnection(ctx context.Context, realmID, slug, ownerOrgID string, in ConnectionInput) (port.Connection, error) {
	if !okURL(s.BaseURL, s.Dev) {
		return port.Connection{}, ErrPublicURLRequired
	}
	if (len(in.MetadataXML) == 0) == (in.MetadataURL == "") {
		return port.Connection{}, invalid("specify one of metadata_xml and metadata_url")
	}
	if len(in.EntityID) > 1024 || len(in.NameIDFormat) > 256 || len(in.EmailAttribute) > 256 {
		return port.Connection{}, invalid("value too long")
	}
	if in.NameIDFormat == nameIDTransient {
		return port.Connection{}, invalid("transient NameID cannot identify a user")
	}
	if ownerOrgID != "" && in.TrustEmail {
		return port.Connection{}, invalid("trust_email is for realm connections")
	}
	raw := in.MetadataXML
	if in.MetadataURL != "" {
		if !okURL(in.MetadataURL, s.Dev) {
			return port.Connection{}, invalid("metadata_url must be an https URL")
		}
		var err error
		if raw, err = s.fetch(ctx, in.MetadataURL); err != nil {
			// 誤りには解決したアドレスや接続の結果が入るので、呼び出し側には返さずログにだけ残す（内部のネットワークを探らせない）。
			if s.Log != nil {
				s.Log.WarnContext(ctx, "saml: fetch the IdP metadata", "url", in.MetadataURL, "error", err)
			}
			return port.Connection{}, invalid("could not fetch the metadata")
		}
	}
	md, err := ParseIdPMetadata(raw, in.EntityID, s.Dev)
	if err != nil {
		return port.Connection{}, invalid("%v", err)
	}
	now := s.Clock.Now()
	for _, c := range md.Certs {
		if !now.Before(c.NotAfter) {
			return port.Connection{}, invalid("the IdP signing certificate has expired")
		}
	}
	cid := id.NewExternal(id.Connection)
	if slug == "" {
		slug = cid
	}
	base := strings.TrimSuffix(s.BaseURL, "/")
	cfg := Config{IdPEntityID: md.EntityID, SSOURL: md.SSOURL, MetadataURL: in.MetadataURL, SPEntityID: base + MetadataPath + slug,
		ACSURL: base + ACSPath, SignRequests: in.SignRequests, NameIDFormat: in.NameIDFormat, EmailAttribute: in.EmailAttribute, TrustEmail: in.TrustEmail}
	for _, c := range md.Certs {
		cfg.IdPCerts = append(cfg.IdPCerts, c.Raw)
	}
	key, cert, err := newSPKey(cfg.SPEntityID, now)
	if err != nil {
		return port.Connection{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return port.Connection{}, err
	}
	if cfg.SPKey, err = s.Crypter.Seal(ctx, keyPurpose, der); err != nil {
		return port.Connection{}, err
	}
	cfg.SPCert = cert
	b, err := json.Marshal(cfg)
	if err != nil {
		return port.Connection{}, err
	}
	return port.Connection{ID: cid, RealmID: realmID, Slug: slug, Type: Type, Config: b, CreatedAt: now, OwnerOrgID: ownerOrgID}, nil
}

func invalid(format string, args ...any) error {
	return errs.WithCode(errs.KindInvalid, "invalid_connection", "saml connection: "+fmt.Sprintf(format, args...))
}

// fetch は IdP のメタデータを取得する。Org の connection と同じく、公開のアドレスに限ってつなぐ（ADR 0077）。
func (s *Service) fetch(ctx context.Context, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	client, err := s.OAuth.GuardedClient(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) // #nosec G704 -- https に限り、公開のアドレスに限ってつなぐ（GuardedClient）
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetadataBytes {
		return nil, errors.New("metadata too large")
	}
	return b, nil
}

// ConfigOf は connection の設定を読む。
func ConfigOf(c port.Connection) (Config, error) {
	if c.Type != Type {
		return Config{}, fmt.Errorf("saml: connection %s is not a saml connection", c.ID)
	}
	var cfg Config
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return Config{}, fmt.Errorf("saml: connection %s: %w", c.ID, err)
	}
	return cfg, nil
}

// Info は connection の設定のうち、公開してよいもの（鍵は返さない）。
type Info struct {
	IdPEntityID, SSOURL, MetadataURL, SPEntityID, ACSURL, NameIDFormat, EmailAttribute string
	SignRequests, TrustEmail                                                           bool
	// IdPCertExpiresAt は IdP の署名の証明書のうち、最も遅い期限（切り替えの目安）。
	IdPCertExpiresAt time.Time
}

// InfoOf は connection の公開してよい設定を返す。
func InfoOf(c port.Connection) (Info, error) {
	cfg, err := ConfigOf(c)
	if err != nil {
		return Info{}, err
	}
	out := Info{IdPEntityID: cfg.IdPEntityID, SSOURL: cfg.SSOURL, MetadataURL: cfg.MetadataURL, SPEntityID: cfg.SPEntityID, ACSURL: cfg.ACSURL,
		NameIDFormat: cfg.NameIDFormat, EmailAttribute: cfg.EmailAttribute, SignRequests: cfg.SignRequests, TrustEmail: cfg.TrustEmail}
	for _, der := range cfg.IdPCerts {
		if c, err := x509.ParseCertificate(der); err == nil && c.NotAfter.After(out.IdPCertExpiresAt) {
			out.IdPCertExpiresAt = c.NotAfter
		}
	}
	return out, nil
}

// connection は slug の SAML の connection を返す。Org 専用のものは、Org 専用 SSO が使えるときだけ。
func (s *Service) connection(ctx context.Context, realmID, slug string) (port.Connection, Config, error) {
	var c port.Connection
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		c, err = tx.Connections().GetBySlug(ctx, realmID, slug)
		return err
	})
	if err != nil {
		return port.Connection{}, Config{}, err
	}
	if c.Type != Type || (c.OwnerOrgID != "" && !s.OAuth.OrgSSOEnabled()) {
		return port.Connection{}, Config{}, errs.New(errs.KindNotFound, "connection %s is not a saml connection", slug)
	}
	cfg, err := ConfigOf(c)
	return c, cfg, err
}

// Metadata は SP のメタデータ（XML）を返す。
func (s *Service) Metadata(ctx context.Context, realmID, slug string) ([]byte, error) {
	_, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return nil, err
	}
	return SPMetadata(cfg)
}

// state はフローの状態。EphemeralStore に封をして置く。
type state struct {
	RealmID      string    `json:"realm_id"`
	ConnectionID string    `json:"connection_id"`
	RequestID    string    `json:"request_id"`
	FlowHash     []byte    `json:"flow_hash"`
	ExpiresAt    time.Time `json:"expires_at"`
	// LinkUserID は連携のフローで、連携先のユーザー（内部 ID）。空ならログイン・登録のフロー（4.2）。
	LinkUserID string `json:"link_user_id,omitempty"`
}

// LinkRelayPrefix は連携のフローの RelayState の接頭辞（ホスト型の画面が完了の API を選ぶのに使う。秘密ではない）。
const LinkRelayPrefix = "link."

func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func stateKey(relayState string) string {
	return "flow:saml:v1:" + base64.RawURLEncoding.EncodeToString(digest(relayState))
}

func (s *Service) ttl() time.Duration {
	if s.TTL <= 0 {
		return 10 * time.Minute
	}
	return s.TTL
}

// Started は開始したフロー。FlowID は要求した側にだけ渡す秘密。RedirectURL へブラウザを移す。
type Started struct {
	FlowID      string
	RedirectURL string
	ExpiresAt   time.Time
}

// Start はログイン・登録のフローを始める。
func (s *Service) Start(ctx context.Context, realmID, slug string) (Started, error) {
	return s.start(ctx, realmID, slug, "")
}

// StartLink は、ログイン済みのユーザー（内部 ID）に外部 ID を連携するフローを始める（4.2）。
func (s *Service) StartLink(ctx context.Context, realmID, slug, userID string) (Started, error) {
	if userID == "" {
		return Started{}, errors.New("saml: link requires a user")
	}
	return s.start(ctx, realmID, slug, userID)
}

func (s *Service) start(ctx context.Context, realmID, slug, linkUserID string) (Started, error) {
	c, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return Started{}, err
	}
	if linkUserID != "" && c.OwnerOrgID != "" {
		// Org 専用の connection は、その Org の管理ユーザーだけが使える（ADR 0077）。
		if err := s.OAuth.ManagedByOwner(ctx, realmID, c, linkUserID); err != nil {
			return Started{}, err
		}
	}
	flowID, err := randomToken()
	if err != nil {
		return Started{}, err
	}
	relay, err := randomToken()
	if err != nil {
		return Started{}, err
	}
	if linkUserID != "" {
		relay = LinkRelayPrefix + relay
	}
	requestID, err := newRequestID()
	if err != nil {
		return Started{}, err
	}
	now := s.Clock.Now()
	st := state{RealmID: realmID, ConnectionID: c.ID, RequestID: requestID, FlowHash: digest(flowID), ExpiresAt: now.Add(s.ttl()), LinkUserID: linkUserID}
	b, err := json.Marshal(st)
	if err != nil {
		return Started{}, err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, b)
	if err != nil {
		return Started{}, err
	}
	if err := s.Cache.Set(ctx, stateKey(relay), sealed, s.ttl()); err != nil {
		return Started{}, err
	}
	req, err := authnRequest(cfg, requestID, now)
	if err != nil {
		return Started{}, err
	}
	var key *ecdsa.PrivateKey
	if cfg.SignRequests {
		if key, err = s.spKey(ctx, cfg); err != nil {
			return Started{}, err
		}
	}
	u, err := redirectURL(cfg.SSOURL, req, relay, key)
	if err != nil {
		return Started{}, err
	}
	return Started{FlowID: flowID, RedirectURL: u, ExpiresAt: st.ExpiresAt}, nil
}

func (s *Service) spKey(ctx context.Context, cfg Config) (*ecdsa.PrivateKey, error) {
	if len(cfg.SPKey) == 0 {
		return nil, errNoKey
	}
	der, err := s.Crypter.Open(ctx, keyPurpose, cfg.SPKey)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errNoKey
	}
	return key, nil
}

// Complete は ACS に届いた応答。SAMLResponse は HTTP-POST の値（base64）のまま渡す。
type Complete struct {
	FlowID, RelayState, SAMLResponse string
	Client                           oauth.Client
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン（session.Issue を参照）。
	ReplaceToken string
}

// Complete はフローを完了し、ログインさせる（未登録で、メールの条件を満たせば登録する）。失敗は ErrAuthFailed
// （本人確認の後の理由は oauth.DiscloseLogin のとおり返す）。
func (s *Service) Complete(ctx context.Context, realmID string, in Complete) (oauth.Result, error) {
	conn, f, err := s.finish(ctx, realmID, in, "")
	if err == nil {
		var out oauth.Result
		if out, err = s.OAuth.LoginFederated(ctx, realmID, conn, f, in.Client, in.ReplaceToken); err == nil {
			return out, nil
		}
	}
	s.OAuth.RecordFailure(ctx, realmID, methodSAML, in.Client, err)
	return oauth.Result{}, oauth.DiscloseLogin(err)
}

// CompleteLink は応答で、ログイン済みのユーザー（内部 ID）に外部 ID を紐付ける。フローを始めたユーザーと違えば ErrAuthFailed。
func (s *Service) CompleteLink(ctx context.Context, realmID, userID string, in Complete) (port.Identity, error) {
	if userID == "" {
		return port.Identity{}, ErrAuthFailed
	}
	conn, f, err := s.finish(ctx, realmID, in, userID)
	if err == nil {
		var ident port.Identity
		if ident, err = s.OAuth.LinkFederated(ctx, realmID, userID, conn, f, in.Client); err == nil {
			return ident, nil
		}
	}
	out := oauth.DiscloseLink(err)
	if out == oauth.ErrAuthFailed {
		s.OAuth.RecordFailure(ctx, realmID, methodSAML, in.Client, err)
	}
	return port.Identity{}, out
}

// maxEncodedResponse は SAMLResponse（base64）の上限。
const maxEncodedResponse = (maxResponseBytes + 2) / 3 * 4

// finish はフローの状態を取り出して確かめ、応答を確かめて本人の属性を返す。
// linkUserID が空ならログイン・登録のフローだけ、空でなければそのユーザーの連携のフローだけを受け付ける。
func (s *Service) finish(ctx context.Context, realmID string, in Complete, linkUserID string) (port.Connection, oauth.Federated, error) {
	if in.FlowID == "" || in.RelayState == "" || in.SAMLResponse == "" || len(in.RelayState) > 80 {
		return port.Connection{}, oauth.Federated{}, errors.New("flow id, relay state and response are required")
	}
	if len(in.SAMLResponse) > maxEncodedResponse {
		return port.Connection{}, oauth.Federated{}, errors.New("response too large")
	}
	// 1 回限り：取り出せた要求だけが続ける。
	b, ok, err := s.Cache.Take(ctx, stateKey(in.RelayState))
	if err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	if !ok {
		return port.Connection{}, oauth.Federated{}, errors.New("unknown or used relay state")
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	now := s.Clock.Now()
	switch {
	case st.RealmID != realmID || !now.Before(st.ExpiresAt):
		return port.Connection{}, oauth.Federated{}, errors.New("flow expired or in another realm")
	case subtle.ConstantTimeCompare(st.FlowHash, digest(in.FlowID)) != 1:
		return port.Connection{}, oauth.Federated{}, errors.New("relay state is bound to another flow")
	case st.LinkUserID != linkUserID:
		return port.Connection{}, oauth.Federated{}, errors.New("flow is for another purpose or user")
	}
	var conn port.Connection
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		conn, err = tx.Connections().Get(ctx, realmID, st.ConnectionID)
		return err
	}); err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	cfg, err := ConfigOf(conn)
	if err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	certs := make([]*x509.Certificate, 0, len(cfg.IdPCerts))
	for _, der := range cfg.IdPCerts {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return port.Connection{}, oauth.Federated{}, err
		}
		certs = append(certs, c)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(in.SAMLResponse), ""))
	if err != nil {
		return port.Connection{}, oauth.Federated{}, errors.New("response is not base64")
	}
	a, err := Verify(raw, Expect{IdPEntityID: cfg.IdPEntityID, Certs: certs, SPEntityID: cfg.SPEntityID, ACSURL: cfg.ACSURL,
		RequestID: st.RequestID, Now: now})
	if err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	// Assertion の ID の再利用を拒む（InResponseTo を 1 回限りの状態に結び付けているので、重ねての防御）。
	ttl := min(max(a.Expires.Sub(now), time.Second), 24*time.Hour)
	n, err := s.Cache.Incr(ctx, "saml:assertion:v1:"+base64.RawURLEncoding.EncodeToString(digest(conn.ID+"\x00"+a.ID)), ttl)
	if err != nil {
		return port.Connection{}, oauth.Federated{}, err
	}
	if n != 1 {
		return port.Connection{}, oauth.Federated{}, errors.New("assertion replayed")
	}
	return conn, federated(cfg, conn, a), nil
}

// federated は Assertion をログインの属性にする。Subject は NameID。メールは設定の属性（無ければ既定の名前、
// それも無ければ emailAddress 形式の NameID）。確認済みとみなすのは、Org 専用の connection（Org が証明したドメインに
// 限る。oauth.LoginFederated が確かめる）か、運営者が trust_email にした realm 共通の connection だけ。
func federated(cfg Config, conn port.Connection, a Assertion) oauth.Federated {
	f := oauth.Federated{Subject: a.NameID, Method: methodSAML, EmailVerified: conn.OwnerOrgID != "" || cfg.TrustEmail}
	names := defaultEmailAttributes
	if cfg.EmailAttribute != "" {
		names = []string{cfg.EmailAttribute}
	}
	// 名前は大文字と小文字を区別しない。同じ名前の属性が複数あるか、値が複数あるものは使わない（どれを使うかが決まらない）。
	for _, n := range names {
		var found []string
		for k, vs := range a.Attributes {
			if strings.EqualFold(k, n) {
				found = append(found, vs...)
			}
		}
		if len(found) == 1 && found[0] != "" {
			f.Email = found[0]
			break
		}
	}
	if f.Email == "" && cfg.EmailAttribute == "" && a.NameIDFormat == nameIDEmail {
		f.Email = a.NameID
	}
	if f.Email == "" {
		f.EmailVerified = false
	}
	return f
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
