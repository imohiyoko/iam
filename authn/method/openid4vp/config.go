package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Config は設定ファイルの `methods.openid4vp`（ADR 0108）。realm の slug ごとに持つ。設定の無い realm では方式を動かさない。
//
//	methods:
//	  openid4vp:
//	    realms:
//	      default:
//	        client_id_prefix: x509_hash
//	        signing_key: /etc/iam/vp/verifier.key
//	        certificate_chain: /etc/iam/vp/verifier.pem
//	        same_device_redirect_uri: https://app.example.com/login/wallet
//	        vct_values: [urn:eudi:pid:1]
//	        subject_claim: [personal_administrative_number]
//	        attributes: {given_name: [given_name], family_name: [family_name]}
//	        issuers:
//	          - {iss: https://pid.example, trust_anchors: [/etc/iam/vp/pid-root.pem]}
type Config struct {
	Realms map[string]RealmConfig `yaml:"realms"`
}

// RealmConfig は realm ごとの方針。
type RealmConfig struct {
	// ClientIDPrefix はクライアント ID の接頭辞：redirect_uri（既定。要求に署名しない）・x509_san_dns・x509_hash（要求に署名する）。
	ClientIDPrefix string `yaml:"client_id_prefix"`
	// SigningKey と CertificateChain は要求に署名する鍵（ECDSA P-256。PEM のファイルのパスか PEM そのもの）と、その証明書の連鎖
	// （先頭が鍵の証明書）。x509_* の接頭辞で要る。
	SigningKey       string `yaml:"signing_key"`
	CertificateChain string `yaml:"certificate_chain"`
	// AuthorizationEndpoint はウォレットを開く URL（既定 openid4vp://）。クエリを持たない。
	AuthorizationEndpoint string `yaml:"authorization_endpoint"`
	// Flows は許す流れ（same_device・cross_device）。既定は両方。先頭が begin の既定。
	Flows []string `yaml:"flows"`
	// SameDeviceRedirectURI は同じ端末の流れで、提示の後にウォレットがブラウザを戻す先（クライアントの画面）。
	// `#response_code=…` を付けて返す。same_device を許すなら要る。
	SameDeviceRedirectURI string `yaml:"same_device_redirect_uri"`
	// VCTValues は受ける資格情報の種類（vct）。1 つ以上。
	VCTValues []string `yaml:"vct_values"`
	// SubjectClaim は本人の結び付けに使う値の path（DCQL の claims path。文字列と 0 以上の数）。
	SubjectClaim []any `yaml:"subject_claim"`
	// Attributes は確かめた属性として持つ値（名前 → path）。
	Attributes map[string][]any `yaml:"attributes"`
	// EmailClaim は link_by_email の発行者で使うメールアドレスの path（既定 [email]）。
	EmailClaim []any `yaml:"email_claim"`
	// Issuers は信じる発行者。1 つ以上。
	Issuers []IssuerConfig `yaml:"issuers"`
	// Status は status（Token Status List）を持つ資格情報の扱い：reject（既定。失効を確かめられないので拒む）・ignore（確かめずに受ける）。
	Status string `yaml:"status"`
	// RequestTTL は要求の期限（既定 5m、10m 以下）。KBMaxAge は KB-JWT の iat の古さの上限（既定 5m、10m 以下）。
	RequestTTL string `yaml:"request_ttl"`
	KBMaxAge   string `yaml:"kb_max_age"`
	// MaxCredentials は 1 人が結び付けられる数（既定 5）。
	MaxCredentials int `yaml:"max_credentials"`
}

// IssuerConfig は信じる発行者。鍵は JWKS か、x5c の連鎖のトラストアンカーで決める（どちらか 1 つ以上）。
type IssuerConfig struct {
	// ISS は発行者の JWT の iss（完全一致）。
	ISS string `yaml:"iss"`
	// JWKS は発行者の公開鍵（JWKS の JSON のファイルのパスか JSON そのもの）。
	JWKS string `yaml:"jwks"`
	// TrustAnchors は x5c の連鎖を確かめるルート CA（PEM のファイルのパスか PEM そのもの）。
	TrustAnchors []string `yaml:"trust_anchors"`
	// VCTValues はこの発行者から受ける vct（空なら realm の vct_values の全部）。
	VCTValues []string `yaml:"vct_values"`
	// LinkByEmail は、結び付けが無いときに、開示されたメールアドレスを確認済みのメールとして持つ本人に結び付けてログインさせるか。
	// 発行者がメールアドレスの持ち主を確かめていると運営者が保証するときだけ true にする。
	LinkByEmail bool `yaml:"link_by_email"`
}

// クライアント ID の接頭辞。
const (
	PrefixRedirectURI = "redirect_uri"
	PrefixX509SANDNS  = "x509_san_dns"
	PrefixX509Hash    = "x509_hash"
)

// 流れ。
const (
	FlowSameDevice  = "same_device"
	FlowCrossDevice = "cross_device"
)

// 既定値と上限。
const (
	DefaultMaxCredentials        = 5
	DefaultAuthorizationEndpoint = "openid4vp://"
	defaultRequestTTL            = 5 * time.Minute
	defaultKBMaxAge              = 5 * time.Minute
	maxTTL                       = 10 * time.Minute
	clockSkew                    = time.Minute
	maxPathLength                = 16
)

// policy は確かめた設定（realm ごと）。
type policy struct {
	prefix         string
	signer         jose.Signer
	leaf           *x509.Certificate
	authzEndpoint  string
	flows          []string
	sameDeviceURI  string
	vcts           []string
	subject        []any
	attributes     map[string][]any
	email          []any
	issuers        map[string]*issuer
	ignoreStatus   bool
	requestTTL     time.Duration
	kbMaxAge       time.Duration
	maxCredentials int
	linkByEmail    bool
}

type issuer struct {
	iss         string
	keys        []jose.JSONWebKey
	roots       *x509.CertPool
	vcts        []string
	linkByEmail bool
}

// readValue は値そのものか、ファイルのパスを読む。isValue が true なら値そのもの。
func readValue(v string, isValue bool) ([]byte, error) {
	if isValue {
		return []byte(v), nil
	}
	b, err := os.ReadFile(v) // #nosec G304 -- 運営者が設定ファイルで指すパス
	if err != nil {
		return nil, err
	}
	return b, nil
}

func isPEM(v string) bool { return strings.HasPrefix(strings.TrimSpace(v), "-----BEGIN") }

// loadCerts は PEM の証明書を読む（1つ以上）。
func loadCerts(v string) ([]*x509.Certificate, error) {
	raw, err := readValue(v, isPEM(v))
	if err != nil {
		return nil, err
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

// loadKey は ECDSA P-256 の秘密鍵を読む（PKCS#8 か SEC 1）。
func loadKey(v string) (*ecdsa.PrivateKey, error) {
	raw, err := readValue(v, isPEM(v))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	var k any
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", blk.Type)
	}
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("signing_key must be an ECDSA P-256 key (ES256)")
	}
	return ec, nil
}

func parseDuration(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > maxTTL {
		return 0, fmt.Errorf("invalid duration %q (must be positive and at most %s)", v, maxTTL)
	}
	return d, nil
}

// parsePath は DCQL の claims path を確かめる（文字列と 0 以上の整数。null は使わない。値は 1 つに決まる）。
func parsePath(p []any) ([]any, error) {
	if len(p) == 0 || len(p) > maxPathLength {
		return nil, errors.New("path must have 1 to 16 elements")
	}
	out := make([]any, len(p))
	for i, e := range p {
		switch e := e.(type) {
		case string:
			if e == "" {
				return nil, errors.New("path element must not be empty")
			}
			out[i] = e
		case int:
			if e < 0 {
				return nil, errors.New("path index must not be negative")
			}
			out[i] = e
		default:
			return nil, fmt.Errorf("path element %v must be a string or a non-negative integer", e)
		}
	}
	if _, ok := out[0].(string); !ok {
		return nil, errors.New("path must start with a claim name")
	}
	return out, nil
}

// webURL は https（dev なら http も）の、フラグメントの無い絶対 URL かを確かめる。
func webURL(v string, dev bool) (*url.URL, error) {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("%q is not an absolute URL without a fragment", v)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !dev) {
		return nil, fmt.Errorf("%q must be https", v)
	}
	return u, nil
}

// newPolicy は realm の設定を確かめる。誤りがあれば起動を止める（設定の誤りで黙って緩めない）。responseURI は応答を受ける URL。
// 空なら URL に関わる確かめ（response_uri の形、x509_san_dns の SAN と response_uri のホストの一致）をしない（他の realm の設定を
// 確かめるとき。realm ごとにホスト名が違いうるので、それは各 realm の Setup で確かめる）。
func newPolicy(rc RealmConfig, responseURI string, dev bool) (*policy, error) {
	p := &policy{prefix: rc.ClientIDPrefix, authzEndpoint: rc.AuthorizationEndpoint, flows: slices.Clone(rc.Flows),
		maxCredentials: rc.MaxCredentials, attributes: map[string][]any{}, issuers: map[string]*issuer{}}
	var ru *url.URL
	if responseURI != "" {
		var err error
		if ru, err = webURL(responseURI, dev); err != nil {
			return nil, fmt.Errorf("response_uri: %w (set server.public_url)", err)
		}
	}
	var err error
	if p.prefix == "" {
		p.prefix = PrefixRedirectURI
	}
	switch p.prefix {
	case PrefixRedirectURI:
		if rc.SigningKey != "" || rc.CertificateChain != "" {
			return nil, errors.New("signing_key and certificate_chain are used only with x509_san_dns or x509_hash")
		}
	case PrefixX509SANDNS, PrefixX509Hash:
		if err := p.loadSigner(rc, ru); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("client_id_prefix: unsupported prefix %q", rc.ClientIDPrefix)
	}
	if p.authzEndpoint == "" {
		p.authzEndpoint = DefaultAuthorizationEndpoint
	}
	if u, err := url.Parse(p.authzEndpoint); err != nil || u.Scheme == "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(p.authzEndpoint, "?") {
		return nil, errors.New("authorization_endpoint must be an absolute URL without a query")
	}
	if len(p.flows) == 0 {
		p.flows = []string{FlowSameDevice, FlowCrossDevice}
	}
	for i, f := range p.flows {
		if (f != FlowSameDevice && f != FlowCrossDevice) || slices.Contains(p.flows[:i], f) {
			return nil, fmt.Errorf("flows: unknown or duplicate flow %q", f)
		}
	}
	if slices.Contains(p.flows, FlowSameDevice) {
		if _, err := webURL(rc.SameDeviceRedirectURI, dev); err != nil {
			return nil, fmt.Errorf("same_device_redirect_uri: %w", err)
		}
		p.sameDeviceURI = rc.SameDeviceRedirectURI
	} else if rc.SameDeviceRedirectURI != "" {
		return nil, errors.New("same_device_redirect_uri is set but same_device is not in flows")
	}
	if len(rc.VCTValues) == 0 {
		return nil, errors.New("vct_values is required")
	}
	for _, v := range rc.VCTValues {
		if v == "" {
			return nil, errors.New("vct_values must not contain an empty value")
		}
	}
	p.vcts = slices.Clone(rc.VCTValues)
	if p.subject, err = parsePath(rc.SubjectClaim); err != nil {
		return nil, fmt.Errorf("subject_claim: %w", err)
	}
	for name, path := range rc.Attributes {
		if name == "" || len(name) > 64 {
			return nil, errors.New("attributes: invalid name")
		}
		if p.attributes[name], err = parsePath(path); err != nil {
			return nil, fmt.Errorf("attributes.%s: %w", name, err)
		}
	}
	email := rc.EmailClaim
	if len(email) == 0 {
		email = []any{"email"}
	}
	if p.email, err = parsePath(email); err != nil {
		return nil, fmt.Errorf("email_claim: %w", err)
	}
	if len(rc.Issuers) == 0 {
		return nil, errors.New("issuers is required")
	}
	for _, ic := range rc.Issuers {
		is, err := newIssuer(ic, p.vcts)
		if err != nil {
			return nil, fmt.Errorf("issuers: %s: %w", ic.ISS, err)
		}
		if _, dup := p.issuers[is.iss]; dup {
			return nil, fmt.Errorf("issuers: duplicate iss %q", is.iss)
		}
		p.issuers[is.iss] = is
		p.linkByEmail = p.linkByEmail || is.linkByEmail
	}
	switch rc.Status {
	case "", "reject":
	case "ignore":
		p.ignoreStatus = true
	default:
		return nil, fmt.Errorf("status: unknown value %q", rc.Status)
	}
	if p.requestTTL, err = parseDuration(rc.RequestTTL, defaultRequestTTL); err != nil {
		return nil, fmt.Errorf("request_ttl: %w", err)
	}
	if p.kbMaxAge, err = parseDuration(rc.KBMaxAge, defaultKBMaxAge); err != nil {
		return nil, fmt.Errorf("kb_max_age: %w", err)
	}
	if p.maxCredentials == 0 {
		p.maxCredentials = DefaultMaxCredentials
	}
	if p.maxCredentials < 0 || p.maxCredentials > 100 {
		return nil, errors.New("max_credentials must be between 1 and 100")
	}
	return p, nil
}

// loadSigner は要求に署名する鍵と証明書を読み、クライアント ID の接頭辞と合うかを確かめる。responseURI が nil なら SAN と
// ホストの一致は確かめない。
func (p *policy) loadSigner(rc RealmConfig, responseURI *url.URL) error {
	if rc.SigningKey == "" || rc.CertificateChain == "" {
		return fmt.Errorf("%s needs signing_key and certificate_chain", p.prefix)
	}
	key, err := loadKey(rc.SigningKey)
	if err != nil {
		return fmt.Errorf("signing_key: %w", err)
	}
	chain, err := loadCerts(rc.CertificateChain)
	if err != nil {
		return fmt.Errorf("certificate_chain: %w", err)
	}
	leaf := chain[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return errors.New("certificate_chain: the first certificate does not match signing_key")
	}
	if p.prefix == PrefixX509SANDNS && responseURI != nil && !slices.Contains(leaf.DNSNames, responseURI.Hostname()) {
		return fmt.Errorf("certificate_chain: x509_san_dns needs a DNS SAN equal to the response_uri host %q", responseURI.Hostname())
	}
	x5c := make([]string, len(chain))
	for i, c := range chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	opts := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", x5c)
	if p.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts); err != nil {
		return fmt.Errorf("signing_key: %w", err)
	}
	p.leaf = leaf
	return nil
}

// clientID は要求のクライアント ID（接頭辞を含む。KB-JWT の aud）。
func (p *policy) clientID(responseURI string) string {
	switch p.prefix {
	case PrefixX509SANDNS:
		u, _ := url.Parse(responseURI)
		return PrefixX509SANDNS + ":" + u.Hostname()
	case PrefixX509Hash:
		h := sha256.Sum256(p.leaf.Raw)
		return PrefixX509Hash + ":" + base64.RawURLEncoding.EncodeToString(h[:])
	}
	return PrefixRedirectURI + ":" + responseURI
}

func newIssuer(ic IssuerConfig, realmVCTs []string) (*issuer, error) {
	u, err := url.Parse(ic.ISS)
	if ic.ISS == "" || err != nil || u.Scheme == "" {
		return nil, errors.New("iss must be a URI")
	}
	is := &issuer{iss: ic.ISS, vcts: slices.Clone(ic.VCTValues), linkByEmail: ic.LinkByEmail}
	for _, v := range is.vcts {
		if !slices.Contains(realmVCTs, v) {
			return nil, fmt.Errorf("vct_values: %q is not in the realm's vct_values", v)
		}
	}
	if ic.JWKS == "" && len(ic.TrustAnchors) == 0 {
		return nil, errors.New("jwks or trust_anchors is required")
	}
	if ic.JWKS != "" {
		raw, err := readValue(ic.JWKS, strings.HasPrefix(strings.TrimSpace(ic.JWKS), "{"))
		if err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		if len(set.Keys) == 0 {
			return nil, errors.New("jwks: no keys")
		}
		for _, k := range set.Keys {
			if !k.Valid() || !k.IsPublic() {
				return nil, errors.New("jwks: keys must be valid public keys")
			}
			if _, sym := k.Key.([]byte); sym {
				return nil, errors.New("jwks: symmetric keys are not allowed")
			}
			if len(set.Keys) > 1 && k.KeyID == "" {
				return nil, errors.New("jwks: every key needs a kid when there are several")
			}
		}
		is.keys = set.Keys
	}
	if len(ic.TrustAnchors) > 0 {
		is.roots = x509.NewCertPool()
		for _, v := range ic.TrustAnchors {
			cs, err := loadCerts(v)
			if err != nil {
				return nil, fmt.Errorf("trust_anchors: %w", err)
			}
			for _, c := range cs {
				if !c.IsCA {
					return nil, fmt.Errorf("trust_anchors: %s is not a CA", c.Subject)
				}
				is.roots.AddCert(c)
			}
		}
	}
	return is, nil
}

// key は発行者の JWT のヘッダーに合う鍵を返す。kid が JWKS にあればその鍵、無ければ x5c をトランザクションの時刻で
// トラストアンカーまで確かめた証明書の鍵。どちらも無ければ拒む。
func (is *issuer) key(h jose.Header, now time.Time) (any, error) {
	if len(is.keys) > 0 {
		for _, k := range is.keys {
			if (h.KeyID == "" && len(is.keys) == 1) || (h.KeyID != "" && k.KeyID == h.KeyID) {
				if k.Algorithm != "" && k.Algorithm != h.Algorithm {
					return nil, errors.New("key algorithm mismatch")
				}
				return k.Key, nil
			}
		}
	}
	if is.roots != nil {
		chains, err := h.Certificates(x509.VerifyOptions{Roots: is.roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			return nil, fmt.Errorf("x5c: %w", err)
		}
		return chains[0][0].PublicKey, nil
	}
	return nil, errors.New("no matching issuer key")
}
