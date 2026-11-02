package ldap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = oauth.ErrAuthFailed

// Service は LDAP のログイン・連携・同期を扱う。
type Service struct {
	Storage port.Storage
	Crypter *pii.Crypter
	Clock   clock.Clock
	// OAuth はログイン・登録・連携（OIDC・SAML と同じ扱い）に使う。Org 専用の connection の可否と、宛先の確かめ
	// （AllowPrivateNetworks）もこれに従う。
	OAuth *oauth.Service
	// Accounts は同期での停止と解除、Sessions は停止したユーザーのログインの系列を終えるのに使う。
	Accounts *account.Service
	Sessions *session.Manager
	// PerAccount は名前ごとの照合の回数の上限（ディレクトリのアカウントのロックアウトも防ぐ）。nil なら制限しない。
	PerAccount *ratelimit.Limiter
	// GroupsChanged は同期で Group の所属を変えた後に呼ぶ（認可の判定のキャッシュを消す）。nil なら呼ばない。
	GroupsChanged func(realmID string)
	Log           *slog.Logger
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// guarded は connection の宛先を公開のアドレスに限るか（Org 専用の connection。開発・テストの AllowPrivateNetworks を除く）。
func (s *Service) guarded(c port.Connection) bool {
	return c.OwnerOrgID != "" && !s.OAuth.AllowPrivateNetworks
}

// connection は slug の LDAP の connection を返す。Org 専用のものは、Org 専用 SSO が使えるときだけ。
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
		return port.Connection{}, Config{}, errs.New(errs.KindNotFound, "connection %s is not an ldap connection", slug)
	}
	cfg, err := ConfigOf(c)
	if err == nil {
		err = cfg.Validate()
	}
	return c, cfg, err
}

// Credentials はログインの名前とパスワード。
type Credentials struct {
	Username, Password string
	Client             oauth.Client
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン（session.Issue を参照）。
	ReplaceToken string
}

// errBadCredentials はディレクトリが名前かパスワードを拒んだこと（内部向け）。
var errBadCredentials = errors.New("invalid credentials")

// authenticate はサービスアカウントで本人の DN を 1 件だけ探し、本人の DN とパスワードで bind する。
func (s *Service) authenticate(ctx context.Context, c port.Connection, cfg Config, username, password string) (entry, error) {
	// 空のパスワードは認証しない bind として通ってしまうので、ディレクトリに送らない（RFC 4513 5.1.2、6.3.1）。
	if password == "" || len(password) > maxPassword || !ValidUsername(username) {
		return entry{}, errBadCredentials
	}
	sess, err := s.open(ctx, cfg, s.guarded(c))
	if err != nil {
		return entry{}, err
	}
	defer sess.close()
	res, err := sess.conn.Search(ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(opTimeout/time.Second), false,
		loginFilter(cfg, username), attributes(cfg), nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return entry{}, errors.New("more than one entry matches the username")
	case err != nil:
		return entry{}, fmt.Errorf("%w: search: %v", ErrUnavailable, err)
	case len(res.Entries) == 0:
		return entry{}, fmt.Errorf("%w: no entry", errBadCredentials)
	case len(res.Entries) > 1:
		return entry{}, errors.New("more than one entry matches the username")
	}
	e, err := entryOf(cfg, res.Entries[0])
	if err != nil {
		return entry{}, err
	}
	if e.DN == "" {
		return entry{}, errors.New("entry without a DN")
	}
	if err := sess.conn.Bind(e.DN, password); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && rejected(le.ResultCode) {
			// 資格情報を拒んだ（49 など。AD はロック・期限切れも 49）。
			return entry{}, fmt.Errorf("%w: bind: %d", errBadCredentials, le.ResultCode)
		}
		return entry{}, fmt.Errorf("%w: bind: %v", ErrUnavailable, err)
	}
	if e.Disabled {
		return entry{}, errors.New("account disabled in the directory")
	}
	return e, nil
}

// rejected は bind の結果のコードが本人の資格情報を拒んだものか。それ以外（busy・unavailable・ネットワークの誤りなど）はディレクトリの障害。
func rejected(code uint16) bool {
	switch code {
	case ldap.LDAPResultInvalidCredentials, ldap.LDAPResultInappropriateAuthentication, ldap.LDAPResultInsufficientAccessRights,
		ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultInvalidDNSyntax, ldap.LDAPResultNoSuchObject, ldap.LDAPResultConstraintViolation:
		return true
	}
	return false
}

// federated はディレクトリの項目をログインの属性にする。確認済みとみなすメールは、Org 専用の connection（Org が証明したドメインに
// 限る。oauth が確かめる）か、運営者が trust_email にした realm 共通の connection だけ。amr は pwd（iam がパスワードを確かめた）。
func federated(cfg Config, c port.Connection, e entry) oauth.Federated {
	return oauth.Federated{Subject: e.Subject, Email: e.Email, EmailVerified: e.Email != "" && (c.OwnerOrgID != "" || cfg.TrustEmail),
		Method: Method, AMR: []string{"pwd"}}
}

func (s *Service) limit(ctx context.Context, realmID string, c port.Connection, username, ip string) error {
	if s.PerAccount == nil {
		return nil
	}
	h := sha256.Sum256([]byte(c.ID + "\x00" + strings.ToLower(username)))
	return s.PerAccount.AllowFrom(ctx, "ldap:"+realmID+":"+base64.RawURLEncoding.EncodeToString(h[:]), ip)
}

// disclose は外に返してよい誤りを返す（それ以外は ErrAuthFailed）。
func disclose(err error, fallback func(error) error) error {
	if _, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return err
	}
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return fallback(err)
}

// Login は名前とパスワードでログインさせる（未登録で、メールの条件を満たせば登録する）。失敗は ErrAuthFailed、ディレクトリの障害は
// ErrUnavailable、回数の上限は *ratelimit.ExceededError（本人確認の後の理由は oauth.DiscloseLogin のとおり返す）。
func (s *Service) Login(ctx context.Context, realmID, slug string, in Credentials) (oauth.Result, error) {
	c, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return oauth.Result{}, err
	}
	err = s.limit(ctx, realmID, c, in.Username, in.Client.IP)
	var e entry
	if err == nil {
		e, err = s.authenticate(ctx, c, cfg, in.Username, in.Password)
	}
	if err == nil {
		var out oauth.Result
		if out, err = s.OAuth.LoginFederated(ctx, realmID, c, federated(cfg, c, e), in.Client, in.ReplaceToken); err == nil {
			return out, nil
		}
	}
	s.OAuth.RecordFailure(ctx, realmID, Method, in.Client, err)
	if errors.Is(err, ErrUnavailable) {
		s.logger().WarnContext(ctx, "ldap login", "connection_id", c.ID, "error", err)
	}
	return oauth.Result{}, disclose(err, oauth.DiscloseLogin)
}

// Link は名前とパスワードで確かめたディレクトリの本人を、ログイン済みのユーザー（内部 ID）に紐付ける。
func (s *Service) Link(ctx context.Context, realmID, slug, userID string, in Credentials) (port.Identity, error) {
	if userID == "" {
		return port.Identity{}, ErrAuthFailed
	}
	c, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return port.Identity{}, err
	}
	if c.OwnerOrgID != "" {
		// Org 専用の connection は、その Org の管理ユーザーだけが使える（ADR 0077）。ディレクトリに問い合わせる前に断る。
		if err := s.OAuth.ManagedByOwner(ctx, realmID, c, userID); err != nil {
			return port.Identity{}, err
		}
	}
	err = s.limit(ctx, realmID, c, in.Username, in.Client.IP)
	var e entry
	if err == nil {
		e, err = s.authenticate(ctx, c, cfg, in.Username, in.Password)
	}
	if err == nil {
		var ident port.Identity
		if ident, err = s.OAuth.LinkFederated(ctx, realmID, userID, c, federated(cfg, c, e), in.Client); err == nil {
			return ident, nil
		}
	}
	out := disclose(err, oauth.DiscloseLink)
	if out == oauth.ErrAuthFailed {
		s.OAuth.RecordFailure(ctx, realmID, Method, in.Client, err)
	}
	return port.Identity{}, out
}

// UserBy は realm 共通の connection（slug）で、属性 attribute が value の項目をサービスアカウントでちょうど 1 件探し、その外部 ID を
// 紐付けたユーザーの内部 ID を返す（Kerberos のプリンシパルの結び付け。ADR 0107）。本人の bind はしない（本人の確認は呼び出し側が
// 済ませている）。Org 専用の connection は使わない（Org の owner が書いたディレクトリで realm の本人を決めさせない）。
// 見つからない・複数・AD で無効・紐付けが無ければ errs.NotFound、ディレクトリに届かなければ ErrUnavailable。
func (s *Service) UserBy(ctx context.Context, realmID, slug, attribute, value string) (string, error) {
	c, cfg, err := s.connection(ctx, realmID, slug)
	if err != nil {
		return "", err
	}
	if c.OwnerOrgID != "" {
		return "", errs.New(errs.KindNotFound, "connection %s is not a realm connection", slug)
	}
	if !attrRE.MatchString(attribute) || !ValidUsername(value) {
		return "", errs.New(errs.KindNotFound, "user")
	}
	sess, err := s.open(ctx, cfg, false)
	if err != nil {
		return "", err
	}
	defer sess.close()
	filter := "(&" + cfg.UserFilter + "(" + attribute + "=" + ldap.EscapeFilter(value) + "))"
	res, err := sess.conn.Search(ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(opTimeout/time.Second), false,
		filter, attributes(cfg), nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return "", errs.New(errs.KindNotFound, "more than one entry matches")
	case err != nil:
		return "", fmt.Errorf("%w: search: %v", ErrUnavailable, err)
	case len(res.Entries) != 1:
		return "", errs.New(errs.KindNotFound, "%d entries match", len(res.Entries))
	}
	e, err := entryOf(cfg, res.Entries[0])
	if err != nil {
		return "", errs.Wrap(errs.KindNotFound, err, "directory entry")
	}
	if e.Disabled {
		return "", errs.New(errs.KindNotFound, "account disabled in the directory")
	}
	var userID string
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		i, err := tx.Identities().GetBySubject(ctx, realmID, c.ID, e.Subject)
		userID = i.UserID
		return err
	})
	return userID, err
}
