package x509

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config は設定ファイルの `methods.x509`（ADR 0103）。realm の slug ごとに持つ。設定の無い realm では方式を動かさない。
//
//	methods:
//	  x509:
//	    realms:
//	      default:
//	        trust_anchors: [/etc/iam/x509/root.pem]
//	        mapping: san_upn
//	        hardware_issuers: [{certificate: /etc/iam/x509/piv-ca.pem, pin_activation: true}]
//	        revocation: {mode: ocsp_crl}
type Config struct {
	Realms map[string]RealmConfig `yaml:"realms"`
}

// RealmConfig は realm ごとの方針。証明書は PEM のファイルのパスか、PEM そのもの（`-----BEGIN` で始まる値）で書く。
type RealmConfig struct {
	// TrustAnchors は信じるルート CA（1つ以上）。どの CA も、利用者との対応付け（mapping）について同じだけ信じる。
	TrustAnchors []string `yaml:"trust_anchors"`
	// Intermediates はクライアントが送らないときに補う中間 CA。
	Intermediates []string `yaml:"intermediates"`
	// ExtKeyUsages は本人の証明書が持つべき拡張鍵用途のどれか。client_auth（既定）・smartcard_logon・ドット区切りの OID。
	ExtKeyUsages []string `yaml:"extended_key_usages"`
	// Mapping は証明書を利用者に結び付ける値：fingerprint（既定。証明書そのもの）・san_upn・san_email・subject_dn。
	Mapping string `yaml:"mapping"`
	// HardwareIssuers は、ハードウェアの鍵（スマートカードなど）にだけ証明書を発行する CA（本人の証明書を直接発行したもの）。
	// これらが発行した証明書だけが AAL3 に届きうる（ADR 0093、0103）。
	HardwareIssuers []HardwareIssuer `yaml:"hardware_issuers"`
	Revocation      Revocation       `yaml:"revocation"`
	// MaxCredentials は1人が登録できる数（既定 5）。
	MaxCredentials int `yaml:"max_credentials"`
}

// HardwareIssuer はハードウェアの鍵にだけ発行する CA。
type HardwareIssuer struct {
	Certificate string `yaml:"certificate"`
	// PINActivation は、鍵を使うのに PIN（か生体）が要る（PIV のように多要素の暗号デバイス）と運営者が保証するか。
	// true なら、証明書のログインだけで知識の要素を含む多要素とみなす（amr に pin・mfa）。
	PINActivation bool `yaml:"pin_activation"`
}

// Revocation は失効の確かめ方。
type Revocation struct {
	// Mode は ocsp_crl（既定。OCSP で分からなければ CRL）・ocsp・crl・none（確かめない。勧めない）。
	Mode string `yaml:"mode"`
	// FailOpen は、失効が分からない（応答が無い・古い・読めない）ときに通すか。既定は false（拒む）。失効していれば常に拒む。
	FailOpen bool `yaml:"fail_open"`
	// OCSPURL は証明書の AIA の代わりに問い合わせる OCSP のレスポンダー。
	OCSPURL string `yaml:"ocsp_url"`
	// CRLURLs は証明書の CRL 配布点に加えて読む CRL。
	CRLURLs []string `yaml:"crl_urls"`
	// LeafOnly は本人の証明書だけを確かめる（中間 CA の失効を確かめない）。
	LeafOnly bool `yaml:"leaf_only"`
	// Timeout は1回の取得の上限（既定 5s）。CacheMax は結果を持つ上限（既定 1h。応答の nextUpdate が先ならそちら）。
	Timeout  string `yaml:"timeout"`
	CacheMax string `yaml:"cache_max"`
	// MaxCRLBytes は CRL の大きさの上限（既定 16 MiB）。
	MaxCRLBytes int64 `yaml:"max_crl_bytes"`
}

// マッピングの規則。
const (
	MappingFingerprint = "fingerprint"
	MappingUPN         = "san_upn"
	MappingEmail       = "san_email"
	MappingSubjectDN   = "subject_dn"
)

// 失効の確かめ方。
const (
	RevocationOCSPCRL = "ocsp_crl"
	RevocationOCSP    = "ocsp"
	RevocationCRL     = "crl"
	RevocationNone    = "none"
)

// 既定値と上限。
const (
	DefaultMaxCredentials = 5
	defaultTimeout        = 5 * time.Second
	defaultCacheMax       = time.Hour
	defaultMaxCRLBytes    = 16 << 20
	maxChainLength        = 8
	maxCertBytes          = 16 << 10
)

var (
	oidSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
)

// policy は確かめた設定（realm ごと）。
type policy struct {
	roots, intermediates *x509.CertPool
	// clientAuthOnly は受け付ける拡張鍵用途が client_auth だけか（連鎖の用途の入れ子も確かめる）。
	clientAuthOnly bool
	clientAuth     bool
	ekuOIDs        []asn1.ObjectIdentifier
	mapping        string
	hardware       []hardwareIssuer
	revocation     revocationPolicy
	maxCredentials int
}

type hardwareIssuer struct {
	subject []byte
	spki    [32]byte
	pin     bool
}

type revocationPolicy struct {
	mode     string
	failOpen bool
	ocspURL  string
	crlURLs  []string
	leafOnly bool
	timeout  time.Duration
	cacheMax time.Duration
	maxCRL   int64
}

// loadCerts は PEM のファイルのパスか PEM そのものから証明書を読む（1つ以上）。
func loadCerts(v string) ([]*x509.Certificate, error) {
	raw := []byte(v)
	if !strings.HasPrefix(strings.TrimSpace(v), "-----BEGIN") {
		b, err := os.ReadFile(v) // #nosec G304 -- 運営者が設定ファイルで指すパス
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

func parseDuration(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}

func validURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// newPolicy は realm の設定を確かめる。誤りがあれば起動を止める（設定の誤りで黙って緩めない）。
func newPolicy(rc RealmConfig) (*policy, error) {
	p := &policy{roots: x509.NewCertPool(), intermediates: x509.NewCertPool(), mapping: rc.Mapping, maxCredentials: rc.MaxCredentials}
	if len(rc.TrustAnchors) == 0 {
		return nil, errors.New("trust_anchors is required")
	}
	for _, v := range rc.TrustAnchors {
		cs, err := loadCerts(v)
		if err != nil {
			return nil, fmt.Errorf("trust_anchors: %w", err)
		}
		for _, c := range cs {
			if !c.IsCA {
				return nil, fmt.Errorf("trust_anchors: %s is not a CA", c.Subject)
			}
			p.roots.AddCert(c)
		}
	}
	for _, v := range rc.Intermediates {
		cs, err := loadCerts(v)
		if err != nil {
			return nil, fmt.Errorf("intermediates: %w", err)
		}
		for _, c := range cs {
			p.intermediates.AddCert(c)
		}
	}
	ekus := rc.ExtKeyUsages
	if len(ekus) == 0 {
		ekus = []string{"client_auth"}
	}
	for _, e := range ekus {
		switch e {
		case "client_auth":
			p.clientAuth = true
		case "smartcard_logon":
			p.ekuOIDs = append(p.ekuOIDs, oidSmartcardLogon)
		default:
			oid, err := parseOID(e)
			if err != nil {
				return nil, fmt.Errorf("extended_key_usages: %q: %w", e, err)
			}
			p.ekuOIDs = append(p.ekuOIDs, oid)
		}
	}
	p.clientAuthOnly = p.clientAuth && len(p.ekuOIDs) == 0
	switch p.mapping {
	case "":
		p.mapping = MappingFingerprint
	case MappingFingerprint, MappingUPN, MappingEmail, MappingSubjectDN:
	default:
		return nil, fmt.Errorf("mapping: unknown rule %q", rc.Mapping)
	}
	for _, h := range rc.HardwareIssuers {
		cs, err := loadCerts(h.Certificate)
		if err != nil {
			return nil, fmt.Errorf("hardware_issuers: %w", err)
		}
		for _, c := range cs {
			p.hardware = append(p.hardware, hardwareIssuer{subject: c.RawSubject, spki: sha256.Sum256(c.RawSubjectPublicKeyInfo), pin: h.PINActivation})
		}
	}
	if p.maxCredentials == 0 {
		p.maxCredentials = DefaultMaxCredentials
	}
	if p.maxCredentials < 0 || p.maxCredentials > 100 {
		return nil, errors.New("max_credentials must be between 1 and 100")
	}
	r := rc.Revocation
	p.revocation = revocationPolicy{mode: r.Mode, failOpen: r.FailOpen, ocspURL: r.OCSPURL, crlURLs: r.CRLURLs, leafOnly: r.LeafOnly, maxCRL: r.MaxCRLBytes}
	switch p.revocation.mode {
	case "":
		p.revocation.mode = RevocationOCSPCRL
	case RevocationOCSPCRL, RevocationOCSP, RevocationCRL, RevocationNone:
	default:
		return nil, fmt.Errorf("revocation.mode: unknown mode %q", r.Mode)
	}
	if r.OCSPURL != "" && !validURL(r.OCSPURL) {
		return nil, errors.New("revocation.ocsp_url must be http or https")
	}
	for _, u := range r.CRLURLs {
		if !validURL(u) {
			return nil, errors.New("revocation.crl_urls must be http or https")
		}
	}
	var err error
	if p.revocation.timeout, err = parseDuration(r.Timeout, defaultTimeout); err != nil {
		return nil, fmt.Errorf("revocation.timeout: %w", err)
	}
	if p.revocation.timeout > 30*time.Second {
		return nil, errors.New("revocation.timeout must be at most 30s")
	}
	if p.revocation.cacheMax, err = parseDuration(r.CacheMax, defaultCacheMax); err != nil {
		return nil, fmt.Errorf("revocation.cache_max: %w", err)
	}
	if p.revocation.maxCRL == 0 {
		p.revocation.maxCRL = defaultMaxCRLBytes
	}
	if p.revocation.maxCRL < 0 {
		return nil, errors.New("revocation.max_crl_bytes must be positive")
	}
	return p, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, errors.New("not an OID")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, x := range parts {
		var n int
		if _, err := fmt.Sscanf(x, "%d", &n); err != nil || n < 0 || fmt.Sprint(n) != x {
			return nil, errors.New("not an OID")
		}
		oid[i] = n
	}
	return oid, nil
}
