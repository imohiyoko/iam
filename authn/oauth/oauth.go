// Package oauth は外部の OAuth / OIDC プロバイダによる登録とログインを行う（design.md 4.1、9.4）。
//
// セキュリティ上重要なコード（13.2）。不変条件（13.5）：
//   - 認可コード + PKCE（S256）。state と nonce は毎回の乱数で、要求したフロー（Cookie か API の応答で渡す
//     フロー ID）に結び付け、1回限り
//   - ID トークンはトークンエンドポイントから TLS で直接受け取り、署名の検証は TLS で代替する
//     （OIDC Core 3.1.3.7）。iss、aud、azp、exp、iat、nonce は必ず確かめる
//   - 識別は (connection, provider_subject)。未ログインでメールが一致しても自動リンクしない（4.2）
//   - プロバイダが確認済みとしたメールだけを、確認済み（oauth_provider）として登録に使う
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "oauth flow failed")

// ErrAccountExists は、プロバイダが確認済みとしたメールが別のユーザーで登録済みであること。
// 自動リンクはしない（4.2）。本人はプロバイダでメールの所有を示したので、理由を返してよい（ADR 0046）。
var ErrAccountExists = errs.New(errs.KindConflict, "an account with this email already exists; log in and link the provider")

// ErrEmailUnverified は、未登録で、プロバイダがメールを確認済みとしていないこと（登録に使えない）。
var ErrEmailUnverified = errs.New(errs.KindInvalid, "the provider has not verified the email address")

// Type は connections.type。
const Type = "oidc"

// Config は connections.config（JSON）。
type Config struct {
	// Issuers は ID トークンの iss として受け入れる値。
	Issuers      []string `json:"issuers"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"` // 戻り先の許可リスト。先頭が既定
	// ClientSecret は pii.Crypter.Seal で封をしたクライアントシークレット（平文を DB に置かない）。
	ClientSecret []byte `json:"client_secret_sealed"`
	// Extra は認可リクエストに足すパラメータ（Google の prompt など）。
	Extra map[string]string `json:"extra,omitempty"`
}

// Presets はよく使うプロバイダの既定値。
var Presets = map[string]Config{
	"google": { // #nosec G101 -- 公開のエンドポイントで、秘密は含まない
		Issuers:  []string{"https://accounts.google.com", "accounts.google.com"},
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		Scopes:   []string{"openid", "email"},
	},
}

const secretPurpose = "connection.client_secret"

// Validate は設定を確かめる。dev でなければ URL は https に限る。
func (c Config) Validate(dev bool) error {
	var problems []string
	for name, u := range map[string]string{"auth_url": c.AuthURL, "token_url": c.TokenURL} {
		if !okURL(u, dev) {
			problems = append(problems, name+" must be an https URL")
		}
	}
	if len(c.RedirectURIs) == 0 {
		problems = append(problems, "redirect_uris is required")
	}
	for _, u := range c.RedirectURIs {
		if !okURL(u, dev) {
			problems = append(problems, fmt.Sprintf("redirect_uri %q must be an https URL", u))
		}
	}
	if len(c.Issuers) == 0 || c.ClientID == "" || len(c.ClientSecret) == 0 {
		problems = append(problems, "issuers, client_id and client secret are required")
	}
	if !slices.Contains(c.Scopes, "openid") {
		problems = append(problems, "scopes must include openid")
	}
	if len(problems) > 0 {
		return errs.New(errs.KindInvalid, "oauth connection: %s", strings.Join(problems, "; "))
	}
	return nil
}

func okURL(s string, dev bool) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && u.Fragment == "" && (u.Scheme == "https" || (dev && u.Scheme == "http"))
}

// Service は OAuth のフローを扱う。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	// HTTP はトークンエンドポイントへの接続。nil なら既定（リダイレクトを追わない、10 秒で打ち切る）。
	HTTP *http.Client
	Dev  bool
	TTL  time.Duration // フローの期限。既定 10 分
	Log  *slog.Logger
}

// Client は要求の接続元（監査ログとセッションに残す）。
type Client struct {
	IP, UserAgent, RequestID string
}

// NewConnection はプリセットから connection を作る（運営者の操作。クライアントシークレットは封をして置く）。
func (s *Service) NewConnection(ctx context.Context, realmID, slug, preset, clientID, clientSecret string, redirectURIs []string) (port.Connection, error) {
	cfg, ok := Presets[preset]
	if !ok {
		return port.Connection{}, errs.New(errs.KindInvalid, "unknown oauth preset %q", preset)
	}
	cfg.ClientID, cfg.RedirectURIs = clientID, redirectURIs
	sealed, err := s.Crypter.Seal(ctx, secretPurpose, []byte(clientSecret))
	if err != nil {
		return port.Connection{}, err
	}
	cfg.ClientSecret = sealed
	if err := cfg.Validate(s.Dev); err != nil {
		return port.Connection{}, err
	}
	b, err := json.Marshal(cfg) // #nosec G117 -- シークレットは Seal で封をしたもの
	if err != nil {
		return port.Connection{}, err
	}
	return port.Connection{ID: id.NewExternal(id.Connection), RealmID: realmID, Slug: slug, Type: Type, Config: b, CreatedAt: s.Clock.Now()}, nil
}

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
	if c.Type != Type {
		return port.Connection{}, Config{}, errs.New(errs.KindNotFound, "connection %s is not an oauth connection", slug)
	}
	var cfg Config
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return port.Connection{}, Config{}, fmt.Errorf("oauth: connection %s: %w", slug, err)
	}
	return c, cfg, cfg.Validate(s.Dev)
}

// state はフローの状態。EphemeralStore に封をして置く。
type state struct {
	RealmID      string    `json:"realm_id"`
	ConnectionID string    `json:"connection_id"`
	FlowHash     []byte    `json:"flow_hash"`
	Verifier     string    `json:"verifier"`
	Nonce        string    `json:"nonce"`
	RedirectURI  string    `json:"redirect_uri"`
	ExpiresAt    time.Time `json:"expires_at"`
}

const sealPurpose = "flow.oauth"

func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func stateKey(st string) string {
	return "flow:oauth:v1:" + base64.RawURLEncoding.EncodeToString(digest(st))
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) ttl() time.Duration {
	if s.TTL <= 0 {
		return 10 * time.Minute
	}
	return s.TTL
}

// Started は開始したフロー。FlowID は要求した側にだけ渡す秘密。
type Started struct {
	FlowID           string
	AuthorizationURL string
	ExpiresAt        time.Time
}

// Start はフローを始め、プロバイダの認可 URL を返す。redirectURI が空なら既定の戻り先。
func (s *Service) Start(ctx context.Context, realmID, slug, redirectURI string) (Started, error) {
	c, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return Started{}, err
	}
	if redirectURI == "" {
		redirectURI = cfg.RedirectURIs[0]
	} else if !slices.Contains(cfg.RedirectURIs, redirectURI) {
		return Started{}, errs.New(errs.KindInvalid, "redirect_uri is not allowed for this connection")
	}
	var tokens [4]string // flow ID、state、PKCE の verifier、nonce
	for i := range tokens {
		if tokens[i], err = randomToken(); err != nil {
			return Started{}, err
		}
	}
	flowID, st, verifier, nonce := tokens[0], tokens[1], tokens[2], tokens[3]
	now := s.Clock.Now()
	data := state{RealmID: realmID, ConnectionID: c.ID, FlowHash: digest(flowID), Verifier: verifier, Nonce: nonce,
		RedirectURI: redirectURI, ExpiresAt: now.Add(s.ttl())}
	b, err := json.Marshal(data)
	if err != nil {
		return Started{}, err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, b)
	if err != nil {
		return Started{}, err
	}
	if err := s.Cache.Set(ctx, stateKey(st), sealed, s.ttl()); err != nil {
		return Started{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(cfg.Scopes, " ")},
		"state":                 {st},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range cfg.Extra {
		if q.Get(k) == "" {
			q.Set(k, v)
		}
	}
	u, _ := url.Parse(cfg.AuthURL) // Validate で確かめ済み
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += q.Encode()
	return Started{FlowID: flowID, AuthorizationURL: u.String(), ExpiresAt: data.ExpiresAt}, nil
}

// Complete はプロバイダからの戻り（state、code）を受ける。
type Complete struct {
	FlowID, State, Code string
	Client              Client
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン（session.Issue を参照）。
	ReplaceToken string
}

// Result はログイン（または登録）の結果。
type Result struct {
	Session session.Issued
	UserID  string // 公開 ID
	Created bool
}

// Complete はフローを完了し、ログインさせる（未登録で、確認済みのメールがあれば登録する）。
// 失敗は ErrAuthFailed。ErrAccountExists と ErrEmailUnverified は本人確認の後なので理由を返す。
func (s *Service) Complete(ctx context.Context, realmID string, in Complete) (Result, error) {
	out, err := s.complete(ctx, realmID, in)
	if err != nil {
		s.recordFailure(ctx, realmID, in.Client, err)
		if errors.Is(err, ErrAccountExists) || errors.Is(err, ErrEmailUnverified) {
			return Result{}, err
		}
		if denied, ok := errors.AsType[*warning.DeniedError](err); ok {
			return Result{}, denied
		}
		return Result{}, ErrAuthFailed
	}
	return out, nil
}

func (s *Service) complete(ctx context.Context, realmID string, in Complete) (Result, error) {
	if in.FlowID == "" || in.State == "" || in.Code == "" {
		return Result{}, errors.New("flow id, state and code are required")
	}
	// 1回限り：取り出せた要求だけが続ける。
	b, ok, err := s.Cache.Take(ctx, stateKey(in.State))
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, errors.New("unknown or used state")
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return Result{}, err
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil {
		return Result{}, err
	}
	now := s.Clock.Now()
	if st.RealmID != realmID || !now.Before(st.ExpiresAt) {
		return Result{}, errors.New("flow expired or in another realm")
	}
	if subtle.ConstantTimeCompare(st.FlowHash, digest(in.FlowID)) != 1 {
		return Result{}, errors.New("state is bound to another flow")
	}

	var conn port.Connection
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		conn, err = tx.Connections().Get(ctx, realmID, st.ConnectionID)
		return err
	}); err != nil {
		return Result{}, err
	}
	var cfg Config
	if err := json.Unmarshal(conn.Config, &cfg); err != nil {
		return Result{}, err
	}
	if err := cfg.Validate(s.Dev); err != nil {
		return Result{}, err
	}
	claims, err := s.exchange(ctx, cfg, st, in.Code, now)
	if err != nil {
		return Result{}, err
	}
	return s.login(ctx, realmID, conn, claims, in, now)
}

// claims は ID トークンのうち使うもの。
type claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      audience `json:"aud"`
	AuthorizedBy  string   `json:"azp"`
	Expiry        int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Nonce         string   `json:"nonce"`
	Email         string   `json:"email"`
	EmailVerified flexBool `json:"email_verified"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// flexBool は true と "true" の両方を読む（プロバイダによって文字列で返す）。
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*f = true
	case "false", `"false"`, "null":
		*f = false
	default:
		return fmt.Errorf("invalid boolean %s", b)
	}
	return nil
}

// maxSkew は iat に許す時刻のずれ。
const maxSkew = 5 * time.Minute

const maxResponse = 1 << 20

func (s *Service) httpClient() *http.Client {
	c := &http.Client{Timeout: exchangeTimeout}
	if s.HTTP != nil {
		// 注入されたクライアント（テストの TLS など）の設定は保ちつつ、リダイレクトは必ず追わない
		// （client_secret を含むフォームを 307/308 で別の URL に送り直さないため）。
		cp := *s.HTTP
		c = &cp
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// exchangeTimeout はトークンエンドポイントへの問い合わせの上限。
const exchangeTimeout = 10 * time.Second

// exchange は認可コードをトークンエンドポイントで ID トークンに替え、クレームを確かめる。
func (s *Service) exchange(ctx context.Context, cfg Config, st state, code string, now time.Time) (claims, error) {
	secret, err := s.Crypter.Open(ctx, secretPurpose, cfg.ClientSecret)
	if err != nil {
		return claims{}, fmt.Errorf("client secret: %w", err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {st.RedirectURI},
		"client_id":     {cfg.ClientID},
		"client_secret": {string(secret)},
		"code_verifier": {st.Verifier},
	}
	// 注入されたクライアントにタイムアウトが無くても、プロバイダが応答しないまま待ち続けないようにする。
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return claims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req) // #nosec G704 -- token_url は運営者が設定し、Validate で https に限る
	if err != nil {
		return claims{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return claims{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return claims{}, fmt.Errorf("token endpoint: status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return claims{}, errors.New("token endpoint: no id_token")
	}
	// 署名の検証は TLS で代替する（トークンエンドポイントから直接受け取ったため。OIDC Core 3.1.3.7）。
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("id_token: malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errors.New("id_token: malformed payload")
	}
	var c claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&c); err != nil {
		return claims{}, fmt.Errorf("id_token: %w", err)
	}
	switch {
	case !slices.Contains(cfg.Issuers, c.Issuer):
		return claims{}, errors.New("id_token: unexpected iss")
	case !slices.Contains(c.Audience, cfg.ClientID):
		return claims{}, errors.New("id_token: aud does not include client_id")
	case (len(c.Audience) > 1 || c.AuthorizedBy != "") && c.AuthorizedBy != cfg.ClientID:
		return claims{}, errors.New("id_token: azp mismatch")
	case !now.Before(time.Unix(c.Expiry, 0)):
		return claims{}, errors.New("id_token: expired")
	case c.IssuedAt == 0 || time.Unix(c.IssuedAt, 0).After(now.Add(maxSkew)):
		return claims{}, errors.New("id_token: invalid iat")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(st.Nonce)) != 1:
		return claims{}, errors.New("id_token: nonce mismatch")
	case c.Subject == "" || len(c.Subject) > 255:
		return claims{}, errors.New("id_token: invalid sub")
	}
	return c, nil
}

// login は (connection, sub) でユーザーを探し、無ければ登録する。
func (s *Service) login(ctx context.Context, realmID string, conn port.Connection, c claims, in Complete, now time.Time) (Result, error) {
	var out Result
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ident, err := tx.Identities().GetBySubject(ctx, realmID, conn.ID, c.Subject)
		switch {
		case err == nil:
			if ident.RevokedAt != nil {
				return errors.New("identity revoked")
			}
		case errors.Is(err, errs.NotFound):
			if ident, err = s.signup(ctx, tx, realmID, conn, c, in.Client, now); err != nil {
				return err
			}
			out.Created = true
		default:
			return err
		}
		u, err := tx.Users().Get(ctx, realmID, ident.UserID)
		if err != nil {
			return err
		}
		if !account.CanLogin(u, now) {
			return errors.New("user cannot log in")
		}
		is, err := s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: []string{"fed"}, Credentials: []string{ident.ID},
			Evidence: warning.Evidence{OAuthEmailVerified: new(bool(c.EmailVerified))},
			IP:       in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, ReplaceToken: in.ReplaceToken,
		})
		if err != nil {
			return err
		}
		out.Session, out.UserID = is, u.PublicID
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: is.Session.ID, IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID,
			Details: map[string]any{"method": "oauth", "connection_id": conn.ID, "signup": out.Created},
		})
		return err
	})
	return out, err
}

// signup はプロバイダが確認済みとしたメールでユーザーを作り、外部 ID を紐付ける。
// メールが登録済みなら ErrAccountExists（自動リンクしない）。
func (s *Service) signup(ctx context.Context, tx port.Tx, realmID string, conn port.Connection, c claims, cl Client, now time.Time) (port.Identity, error) {
	if c.Email == "" || !c.EmailVerified {
		return port.Identity{}, ErrEmailUnverified
	}
	created, err := s.Accounts.CreateWithEmail(ctx, tx, realmID, c.Email, port.VerifiedViaOAuthProvider, audit.Actor{}, cl.RequestID)
	if errors.Is(err, errs.Conflict) {
		return port.Identity{}, ErrAccountExists
	}
	if err != nil {
		return port.Identity{}, err
	}
	ident := port.Identity{ID: id.New(id.Identity), RealmID: realmID, UserID: created.User.ID, ConnectionID: conn.ID,
		ProviderSubject: c.Subject, CreatedAt: now}
	if err := tx.Identities().Create(ctx, ident); err != nil {
		return port.Identity{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "identity.linked", Result: audit.ResultSuccess, RealmID: realmID,
		Actor: audit.Actor{Type: "user", ID: created.User.PublicID}, RequestID: cl.RequestID,
		Details: map[string]any{"connection_id": conn.ID, "user_id": created.User.PublicID},
	})
	return ident, err
}

// recordFailure は失敗を監査ログに残す（理由は内部向け。6.1）。
func (s *Service) recordFailure(ctx context.Context, realmID string, c Client, cause error) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.failed", Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
			Details: map[string]any{"method": "oauth", "reason": cause.Error()},
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record login failure", "error", err)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
