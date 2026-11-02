package kerberos

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Config は設定ファイルの `methods.kerberos`（ADR 0107）。realm の slug ごとに持つ。設定の無い realm では方式を動かさない。
//
//	methods:
//	  kerberos:
//	    realms:
//	      default:
//	        keytab: /etc/iam/http.keytab
//	        service_principal: HTTP/login.example.com@CORP.EXAMPLE.COM
//	        accepted_realms: [CORP.EXAMPLE.COM]
//	        mapping: {rule: ldap, ldap: {connection: corp-ad, attribute: userPrincipalName}}
type Config struct {
	Realms map[string]RealmConfig `yaml:"realms"`
}

// RealmConfig は realm ごとの方針。
type RealmConfig struct {
	// Keytab はサービスの鍵（keytab）のファイルのパス。起動時に読む（入れ替えたら再起動する）。
	Keytab string `yaml:"keytab"`
	// ServicePrincipal はチケットの宛先のサービスのプリンシパル（`HTTP/<ホスト名>@<Kerberos の realm>`）。realm を省けば
	// keytab にあるそのプリンシパルの realm（1 つだけのとき）。
	ServicePrincipal string `yaml:"service_principal"`
	// AcceptedRealms は受け付ける本人の Kerberos の realm（信頼関係の先の realm を含める）。既定はサービスのプリンシパルの realm。
	AcceptedRealms []string `yaml:"accepted_realms"`
	// MaxClockSkew は時刻のずれの上限（既定 5m。RFC 4120 の推奨）。最大 10m。
	MaxClockSkew string `yaml:"max_clock_skew"`
	// CaseInsensitiveNames は本人の名前を小文字にそろえて比べるか（Active Directory は大文字と小文字を区別しない）。既定は区別する。
	CaseInsensitiveNames bool `yaml:"case_insensitive_names"`
	// AllowRC4 は RC4-HMAC（etype 23）のチケットとセッション鍵を受け付けるか。既定は拒む（AES だけ）。
	AllowRC4 bool    `yaml:"allow_rc4"`
	Mapping  Mapping `yaml:"mapping"`
	// MaxCredentials は 1 人が登録できるプリンシパルの数（規則 enrollment。既定 5）。
	MaxCredentials int `yaml:"max_credentials"`
}

// Mapping はプリンシパルを iam のユーザーに結び付ける規則。
type Mapping struct {
	// Rule は enrollment（既定。本人が登録したプリンシパル）・email（確認済みのメールアドレス）・ldap（LDAP の connection の外部 ID）。
	Rule string `yaml:"rule"`
	// EmailDomains は規則 email で、Kerberos の realm をメールのドメインに読み替える（無ければ realm を小文字にしたもの）。
	EmailDomains map[string]string `yaml:"email_domains"`
	LDAP         LDAPMapping       `yaml:"ldap"`
}

// LDAPMapping は規則 ldap の検索。
type LDAPMapping struct {
	// Connection は realm 共通の LDAP の connection の slug（ADR 0102。フィーチャー ldap）。
	Connection string `yaml:"connection"`
	// Attribute はディレクトリで探す属性（既定 userPrincipalName）。
	Attribute string `yaml:"attribute"`
	// Value は探す値：principal（既定。`名前@REALM`）・name（`名前`。sAMAccountName・uid）。
	Value string `yaml:"value"`
}

// 結び付けの規則。
const (
	RuleEnrollment = "enrollment"
	RuleEmail      = "email"
	RuleLDAP       = "ldap"
)

// 規則 ldap で探す値。
const (
	ValuePrincipal = "principal"
	ValueName      = "name"
)

// 既定値と上限。
const (
	DefaultMaxCredentials = 5
	defaultClockSkew      = 5 * time.Minute
	maxClockSkew          = 10 * time.Minute
	maxNameLen            = 256
	maxRealmLen           = 255
	// maxToken は受け付ける SPNEGO のトークンの大きさ。AD の PAC を含むチケットでも 48 KiB 程度。
	maxToken = 48 << 10
)

var attrRE = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]{0,63}|[0-9]+(?:\.[0-9]+){1,31})$`)

// policy は確かめた設定（realm ごと）。
type policy struct {
	kt *keytab.Keytab
	// sname と srealm はサービスのプリンシパル。
	sname  types.PrincipalName
	srealm string
	// realms は受け付ける本人の realm。
	realms         []string
	skew           time.Duration
	foldCase       bool
	etypes         []int32
	mapping        Mapping
	maxCredentials int
}

// aesTypes は既定で受け付ける暗号の種類（AES）。DES・3DES・RC4 は拒む。
var aesTypes = []int32{etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA256_128,
	etypeID.AES256_CTS_HMAC_SHA384_192}

func newPolicy(rc RealmConfig) (*policy, error) {
	if rc.Keytab == "" {
		return nil, errors.New("keytab is required")
	}
	if rc.ServicePrincipal == "" {
		return nil, errors.New("service_principal is required")
	}
	b, err := os.ReadFile(rc.Keytab)
	if err != nil {
		return nil, fmt.Errorf("keytab: %w", err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("keytab %s: %w", rc.Keytab, err)
	}
	p := &policy{kt: kt, foldCase: rc.CaseInsensitiveNames, etypes: slices.Clone(aesTypes), mapping: rc.Mapping,
		maxCredentials: rc.MaxCredentials}
	if rc.AllowRC4 {
		p.etypes = append(p.etypes, etypeID.RC4_HMAC)
	}
	if err := p.setService(rc.ServicePrincipal); err != nil {
		return nil, err
	}
	p.realms = rc.AcceptedRealms
	if len(p.realms) == 0 {
		p.realms = []string{p.srealm}
	}
	for _, r := range p.realms {
		if !validRealm(r) {
			return nil, fmt.Errorf("accepted_realms: invalid realm %q", r)
		}
	}
	p.skew = defaultClockSkew
	if rc.MaxClockSkew != "" {
		if p.skew, err = time.ParseDuration(rc.MaxClockSkew); err != nil || p.skew <= 0 || p.skew > maxClockSkew {
			return nil, fmt.Errorf("max_clock_skew: must be a duration up to %v", maxClockSkew)
		}
	}
	if p.maxCredentials == 0 {
		p.maxCredentials = DefaultMaxCredentials
	}
	if p.maxCredentials < 0 || p.maxCredentials > 50 {
		return nil, errors.New("max_credentials: must be 1..50")
	}
	if err := p.checkMapping(); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	return p, nil
}

// setService はサービスのプリンシパルを読み、keytab に AES（AllowRC4 なら RC4 も）の鍵があることを確かめる。
func (p *policy) setService(spn string) error {
	name, realm, _ := strings.Cut(spn, "@")
	comps := strings.Split(name, "/")
	if len(comps) != 2 || comps[0] == "" || comps[1] == "" || strings.ContainsFunc(name, unicode.IsSpace) {
		return fmt.Errorf("service_principal %q: must be service/host[@REALM]", spn)
	}
	if realm != "" && !validRealm(realm) {
		return fmt.Errorf("service_principal %q: invalid realm", spn)
	}
	var realms []string
	for _, e := range p.kt.Entries {
		if !slices.Equal(e.Principal.Components, comps) || (realm != "" && e.Principal.Realm != realm) {
			continue
		}
		if !slices.Contains(p.etypes, e.Key.KeyType) {
			continue
		}
		if !slices.Contains(realms, e.Principal.Realm) {
			realms = append(realms, e.Principal.Realm)
		}
	}
	switch {
	case len(realms) == 0:
		return fmt.Errorf("keytab has no usable key (AES, or RC4 with allow_rc4) for %s", spn)
	case len(realms) > 1:
		return fmt.Errorf("keytab has keys for %s in several realms; write service_principal with @REALM", name)
	}
	p.sname = types.PrincipalName{NameType: 2 /* KRB_NT_SRV_INST */, NameString: comps}
	p.srealm = realms[0]
	if !validRealm(p.srealm) {
		return fmt.Errorf("keytab: invalid realm %q", p.srealm)
	}
	return nil
}

func (p *policy) checkMapping() error {
	m := &p.mapping
	if m.Rule == "" {
		m.Rule = RuleEnrollment
	}
	switch m.Rule {
	case RuleEnrollment:
		if len(m.EmailDomains) > 0 || m.LDAP != (LDAPMapping{}) {
			return errors.New("email_domains and ldap are not used with rule enrollment")
		}
	case RuleEmail:
		if m.LDAP != (LDAPMapping{}) {
			return errors.New("ldap is not used with rule email")
		}
		for r, d := range m.EmailDomains {
			if !slices.Contains(p.realms, r) {
				return fmt.Errorf("email_domains: %s is not an accepted realm", r)
			}
			if d == "" || len(d) > 253 || strings.ContainsAny(d, "@ /\\") || !utf8.ValidString(d) || strings.ContainsFunc(d, unicode.IsControl) {
				return fmt.Errorf("email_domains: invalid domain %q", d)
			}
		}
	case RuleLDAP:
		if len(m.EmailDomains) > 0 {
			return errors.New("email_domains is not used with rule ldap")
		}
		l := &m.LDAP
		if l.Connection == "" {
			return errors.New("ldap.connection is required")
		}
		if l.Attribute == "" {
			l.Attribute = "userPrincipalName"
		}
		if !attrRE.MatchString(l.Attribute) {
			return fmt.Errorf("ldap.attribute: invalid attribute %q", l.Attribute)
		}
		if l.Value == "" {
			l.Value = ValuePrincipal
		}
		if l.Value != ValuePrincipal && l.Value != ValueName {
			return fmt.Errorf("ldap.value: must be %s or %s", ValuePrincipal, ValueName)
		}
		// 名前だけで探すと、別の realm の同じ名前を取り違える。
		if l.Value == ValueName && len(p.realms) > 1 {
			return errors.New("ldap.value name needs a single accepted realm")
		}
	default:
		return fmt.Errorf("unknown rule %q", m.Rule)
	}
	return nil
}

// validRealm は Kerberos の realm の名前として受け付けるか（印字できる ASCII で、空白・`@`・`/` を含まない）。
func validRealm(r string) bool {
	if r == "" || len(r) > maxRealmLen {
		return false
	}
	for _, c := range []byte(r) {
		if c <= 0x20 || c >= 0x7f || c == '@' || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}
