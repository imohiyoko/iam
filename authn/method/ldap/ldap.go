// Package ldap は LDAP / Active Directory のバインド認証と、ユーザーと Group の所属の同期を行う（ADR 0102）。
//
// セキュリティ上重要なコード（design.md 13.2）。不変条件：
//   - 平文の LDAP は使わない。ldaps:// か、ldap:// に StartTLS を必ず掛ける（StartTLS に失敗すれば何も送らずに切る）。
//     サーバーの証明書はホスト名と信頼の起点（設定の CA か OS の既定）で確かめ、ピン（SPKI の SHA-256）があれば連なりの中に一致を求める
//   - サービスアカウントのパスワードは封をして connections.config に置く（平文を DB に置かない）
//   - ログインは、サービスアカウントで本人の DN を 1 件だけ探し、本人の DN とパスワードで bind し直す。入力は絞り込みに
//     エスケープして入れる。空のパスワードは bind の前に拒む（認証しない bind（RFC 4513 5.1.2）が成功してしまうため）
//   - 外部 ID は (connection, 変わらない識別子（entryUUID・objectGUID）)。DN は名前の変更で変わるので使わない
//   - ログイン・登録・連携は OIDC・SAML と同じ扱い（oauth.LoginFederated）。Org 専用の connection では、その Org の管理ユーザーだけが
//     ログイン・連携でき、登録は Org が証明したドメインのアドレスに限る（ADR 0077）。Org の connection の宛先は公開のアドレスに限る
//   - 同期は自分が作った Group（directory_groups）の所属だけを変え、手で作った Group を引き取らない。全件を読み切れなかった回は、
//     停止・所属の削除をしない。停止は一度に有効な外部 ID の一定の割合までに限る
package ldap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー ldap の宣言（既定オフ。ADR 0089、0102）。Org 専用の connection には org_managed_users も要る。
var Feature = feature.Feature{Name: feature.LDAP, DataVersion: 1}

// Type は connections.type。
const Type = "ldap"

// Method は監査ログの method。
const Method = "ldap"

// passwordPurpose はサービスアカウントのパスワードの封の用途。
const passwordPurpose = "connection.ldap_bind_password"

// 同期の未登録・消えた本人の扱い。
const (
	OnMissingSuspend = "suspend"
	OnMissingNone    = "none"
)

// 同期の間隔の範囲。
const (
	DefaultSyncInterval = time.Hour
	MinSyncInterval     = 15 * time.Minute
	MaxSyncInterval     = 7 * 24 * time.Hour
)

// Sync は同期の設定。
type Sync struct {
	Enabled bool `json:"enabled"`
	// IntervalSeconds は同期の間隔（秒）。0 なら既定。
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`
	// Provision は、まだ紐付いていない本人を、ログインと同じ規則で事前に登録する。
	Provision bool `json:"provision,omitempty"`
	// OnMissing はディレクトリから消えた・無効にされた本人の扱い（suspend か none）。
	OnMissing string `json:"on_missing"`
}

// Interval は同期の間隔。
func (s Sync) Interval() time.Duration {
	if s.IntervalSeconds <= 0 {
		return DefaultSyncInterval
	}
	return time.Duration(s.IntervalSeconds) * time.Second
}

// Config は connections.config（JSON）。
type Config struct {
	// URL は ldaps://host[:port] か ldap://host[:port]（StartTLS を必ず掛ける）。
	URL string `json:"url"`
	// CAPEM はサーバーの証明書の信頼の起点（PEM）。空なら OS の既定。
	CAPEM string `json:"ca_pem,omitempty"`
	// Pins はサーバーの証明書の連なりのどれかの SPKI の SHA-256（base64）。空なら確かめない。
	Pins []string `json:"pins,omitempty"`
	// BindDN はサービスアカウント。BindPassword はそのパスワードを pii.Crypter.Seal で封をしたもの。
	BindDN       string `json:"bind_dn"`
	BindPassword []byte `json:"bind_password_sealed"`
	UserBaseDN   string `json:"user_base_dn"`
	UserFilter   string `json:"user_filter"`
	// LoginAttribute はログインの名前の属性、IDAttribute は変わらない識別子の属性、EmailAttribute はメールの属性。
	LoginAttribute string `json:"login_attribute"`
	IDAttribute    string `json:"id_attribute"`
	EmailAttribute string `json:"email_attribute"`
	// GroupAttribute は本人の項目の所属の属性（memberOf）。GroupBaseDN の下の Group だけを同期する（空なら所属を同期しない）。
	GroupAttribute string `json:"group_attribute,omitempty"`
	GroupBaseDN    string `json:"group_base_dn,omitempty"`
	// ActiveDirectory なら userAccountControl の無効のビットを見る。
	ActiveDirectory bool `json:"active_directory,omitempty"`
	// TrustEmail はディレクトリのメールを確認済みとみなすか（realm 共通の connection だけ。運営者が決める）。
	TrustEmail bool `json:"trust_email,omitempty"`
	Sync       Sync `json:"sync"`
}

// ConnectionInput は connection の登録の入力。空の項目は既定（ActiveDirectory で変わる）。
type ConnectionInput struct {
	URL, CAPEM                                                          string
	Pins                                                                []string
	BindDN, BindPassword                                                string
	UserBaseDN, UserFilter, LoginAttribute, IDAttribute, EmailAttribute string
	GroupBaseDN, GroupAttribute                                         string
	ActiveDirectory, TrustEmail                                         bool
	Sync                                                                Sync
}

// 上限。
const (
	maxDN         = 1024
	maxFilter     = 1024
	maxPins       = 10
	maxCAPEM      = 64 << 10
	maxPassword   = 1024
	maxUsername   = 256
	maxAttrValues = 256
)

var attrRE = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]{0,63}|[0-9]+(?:\.[0-9]+){1,31})$`)

func invalid(format string, args ...any) error {
	return errs.WithCode(errs.KindInvalid, "invalid_connection", "ldap connection: "+fmt.Sprintf(format, args...))
}

// defaults は空の項目に既定を入れる。
func (in *ConnectionInput) defaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	if in.ActiveDirectory {
		set(&in.UserFilter, "(&(objectCategory=person)(objectClass=user))")
		set(&in.LoginAttribute, "sAMAccountName")
		set(&in.IDAttribute, "objectGUID")
	} else {
		set(&in.UserFilter, "(objectClass=inetOrgPerson)")
		set(&in.LoginAttribute, "uid")
		set(&in.IDAttribute, "entryUUID")
	}
	set(&in.EmailAttribute, "mail")
	if in.GroupBaseDN != "" {
		set(&in.GroupAttribute, "memberOf")
	}
	set(&in.Sync.OnMissing, OnMissingSuspend)
}

// Validate は設定を確かめる（封をしたパスワードの中身は見ない）。
func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	switch {
	case err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return invalid("url must be ldaps://host[:port] or ldap://host[:port]")
	case u.Scheme != "ldaps" && u.Scheme != "ldap":
		// 平文の LDAP は無い：ldap:// は StartTLS を必ず掛ける。
		return invalid("url scheme must be ldaps or ldap (StartTLS)")
	}
	if len(c.CAPEM) > maxCAPEM {
		return invalid("ca_pem too large")
	}
	if c.CAPEM != "" {
		if _, err := certPool(c.CAPEM); err != nil {
			return invalid("%v", err)
		}
	}
	if len(c.Pins) > maxPins {
		return invalid("too many pins")
	}
	for _, p := range c.Pins {
		if b, err := base64.StdEncoding.DecodeString(p); err != nil || len(b) != sha256.Size {
			return invalid("pins must be base64 SHA-256 of the SubjectPublicKeyInfo")
		}
	}
	for name, dn := range map[string]string{"bind_dn": c.BindDN, "user_base_dn": c.UserBaseDN} {
		if err := checkDN(dn); err != nil {
			return invalid("%s: %v", name, err)
		}
	}
	if c.GroupBaseDN != "" {
		if err := checkDN(c.GroupBaseDN); err != nil {
			return invalid("group_base_dn: %v", err)
		}
	}
	if len(c.BindPassword) == 0 {
		return invalid("bind_password is required")
	}
	if len(c.UserFilter) > maxFilter {
		return invalid("user_filter too long")
	}
	if _, err := ldap.CompileFilter(c.UserFilter); err != nil {
		return invalid("user_filter: %v", err)
	}
	attrs := map[string]string{"login_attribute": c.LoginAttribute, "id_attribute": c.IDAttribute, "email_attribute": c.EmailAttribute}
	if c.GroupBaseDN != "" {
		attrs["group_attribute"] = c.GroupAttribute
	}
	for name, a := range attrs {
		if !attrRE.MatchString(a) {
			return invalid("%s must be an attribute name", name)
		}
	}
	switch c.Sync.OnMissing {
	case OnMissingSuspend, OnMissingNone:
	default:
		return invalid("sync.on_missing must be suspend or none")
	}
	if c.Sync.IntervalSeconds != 0 {
		if d := c.Sync.Interval(); d < MinSyncInterval || d > MaxSyncInterval {
			return invalid("sync interval must be between %s and %s", MinSyncInterval, MaxSyncInterval)
		}
	}
	return nil
}

func checkDN(dn string) error {
	if dn == "" || len(dn) > maxDN {
		return fmt.Errorf("a DN of at most %d bytes is required", maxDN)
	}
	_, err := ldap.ParseDN(dn)
	return err
}

func certPool(p string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest, n := []byte(p), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca_pem: unexpected %s block", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca_pem: %w", err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("ca_pem must contain only PEM certificates")
	}
	return pool, nil
}

// NewConnection は connection を作る（保存はしない）。slug が空なら connection の ID を slug にする（Org 専用。ADR 0077）。
// ownerOrgID が空なら realm 共通。
func NewConnection(ctx context.Context, crypter *pii.Crypter, now time.Time, realmID, slug, ownerOrgID string, in ConnectionInput) (port.Connection, error) {
	in.defaults()
	if ownerOrgID != "" && in.TrustEmail {
		return port.Connection{}, invalid("trust_email is for realm connections")
	}
	if in.BindPassword == "" || len(in.BindPassword) > maxPassword {
		return port.Connection{}, invalid("bind_password is required (at most %d bytes)", maxPassword)
	}
	cfg := Config{URL: in.URL, CAPEM: in.CAPEM, Pins: in.Pins, BindDN: in.BindDN, UserBaseDN: in.UserBaseDN, UserFilter: in.UserFilter,
		LoginAttribute: in.LoginAttribute, IDAttribute: in.IDAttribute, EmailAttribute: in.EmailAttribute, GroupAttribute: in.GroupAttribute,
		GroupBaseDN: in.GroupBaseDN, ActiveDirectory: in.ActiveDirectory, TrustEmail: in.TrustEmail, Sync: in.Sync}
	cfg.BindPassword = []byte("x") // 形の確認のため。下で封をしたものに替える
	if err := cfg.Validate(); err != nil {
		return port.Connection{}, err
	}
	sealed, err := crypter.Seal(ctx, passwordPurpose, []byte(in.BindPassword))
	if err != nil {
		return port.Connection{}, err
	}
	cfg.BindPassword = sealed
	b, err := json.Marshal(cfg)
	if err != nil {
		return port.Connection{}, err
	}
	cid := id.NewExternal(id.Connection)
	if slug == "" {
		slug = cid
	}
	return port.Connection{ID: cid, RealmID: realmID, Slug: slug, Type: Type, Config: b, CreatedAt: now, OwnerOrgID: ownerOrgID}, nil
}

// Update は運営者・Org の owner による変更（サービスアカウントのパスワードの入れ替え、同期の設定）。nil の項目は変えない。
type Update struct {
	BindPassword *string
	Sync         *Sync
	CAPEM        *string
	Pins         *[]string
}

// UpdateConnection は変更を当てた connection と、変えた項目の名前（監査ログ用。値は残さない）を返す。
func UpdateConnection(ctx context.Context, crypter *pii.Crypter, c port.Connection, u Update) (port.Connection, []string, error) {
	cfg, err := ConfigOf(c)
	if err != nil {
		return port.Connection{}, nil, err
	}
	var changed []string
	if u.BindPassword != nil {
		if *u.BindPassword == "" || len(*u.BindPassword) > maxPassword {
			return port.Connection{}, nil, invalid("bind_password must not be empty (at most %d bytes)", maxPassword)
		}
		if cfg.BindPassword, err = crypter.Seal(ctx, passwordPurpose, []byte(*u.BindPassword)); err != nil {
			return port.Connection{}, nil, err
		}
		changed = append(changed, "bind_password")
	}
	if u.Sync != nil {
		s := *u.Sync
		if s.OnMissing == "" {
			s.OnMissing = OnMissingSuspend
		}
		cfg.Sync = s
		changed = append(changed, "sync")
	}
	if u.CAPEM != nil {
		cfg.CAPEM = *u.CAPEM
		changed = append(changed, "ca_pem")
	}
	if u.Pins != nil {
		cfg.Pins = *u.Pins
		changed = append(changed, "pins")
	}
	if err := cfg.Validate(); err != nil {
		return port.Connection{}, nil, err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return port.Connection{}, nil, err
	}
	c.Config = b
	return c, changed, nil
}

// ConfigOf は connection の設定を読む。
func ConfigOf(c port.Connection) (Config, error) {
	if c.Type != Type {
		return Config{}, fmt.Errorf("ldap: connection %s is not an ldap connection", c.ID)
	}
	var cfg Config
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return Config{}, fmt.Errorf("ldap: connection %s: %w", c.ID, err)
	}
	return cfg, nil
}

// Info は connection の設定のうち、公開してよいもの（パスワードは返さない）。
type Info struct {
	URL, BindDN, UserBaseDN, UserFilter, LoginAttribute, IDAttribute, EmailAttribute, GroupBaseDN, GroupAttribute string
	ActiveDirectory, TrustEmail, CAConfigured                                                                     bool
	Pins                                                                                                          []string
	Sync                                                                                                          Sync
}

// InfoOf は connection の公開してよい設定を返す。
func InfoOf(c port.Connection) (Info, error) {
	cfg, err := ConfigOf(c)
	if err != nil {
		return Info{}, err
	}
	return Info{URL: cfg.URL, BindDN: cfg.BindDN, UserBaseDN: cfg.UserBaseDN, UserFilter: cfg.UserFilter, LoginAttribute: cfg.LoginAttribute,
		IDAttribute: cfg.IDAttribute, EmailAttribute: cfg.EmailAttribute, GroupBaseDN: cfg.GroupBaseDN, GroupAttribute: cfg.GroupAttribute,
		ActiveDirectory: cfg.ActiveDirectory, TrustEmail: cfg.TrustEmail, CAConfigured: cfg.CAPEM != "", Pins: append([]string{}, cfg.Pins...),
		Sync: cfg.Sync}, nil
}
