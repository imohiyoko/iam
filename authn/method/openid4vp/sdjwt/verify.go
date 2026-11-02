package sdjwt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Algorithms は受ける署名の alg（発行者の JWT と KB-JWT）。none・HMAC・RSA は受けない。
var Algorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}

// AlgorithmNames は Algorithms の名前（client_metadata の vp_formats_supported に載せる）。
func AlgorithmNames() []string {
	out := make([]string, len(Algorithms))
	for i, a := range Algorithms {
		out[i] = string(a)
	}
	return out
}

// 型（typ）。
const (
	TypeVC       = "dc+sd-jwt"
	TypeVCLegacy = "vc+sd-jwt"
	TypeKB       = "kb+jwt"
)

// Reserved は SD-JWT VC で選択的に開示してはならない名前。
var Reserved = []string{"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"}

// ErrVerification は署名・時刻・key binding などの確かめの失敗。
var ErrVerification = errors.New("sdjwt: verification failed")

func failed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerification, fmt.Sprintf(format, a...))
}

// IssuerKeyFunc は発行者（iss）の、ヘッダーに合う署名の鍵を返す。信じない発行者・鍵が無ければエラー。
type IssuerKeyFunc func(iss string, h jose.Header) (any, error)

// Options は確かめの条件。
type Options struct {
	Now time.Time
	// Skew は時刻の許容幅。
	Skew time.Duration
	// KBMaxAge は KB-JWT の iat の古さの上限。
	KBMaxAge time.Duration
	// Audience は KB-JWT の aud（検証者のクライアント ID）。Nonce は要求の nonce。
	Audience, Nonce string
	IssuerKey       IssuerKeyFunc
}

// Credential は確かめた SD-JWT VC。
type Credential struct {
	Issuer string
	VCT    string
	// Claims は開示を戻した値（_sd・_sd_alg を除く）。数は json.Number。
	Claims map[string]any
	// HasStatus は status（失効の参照）を持つか。
	HasStatus bool
}

// Verify は key binding 付きの SD-JWT VC の提示を確かめる。発行者の署名・型・時刻、開示、key binding（cnf.jwk の鍵の署名、aud、
// nonce、sd_hash、iat）を確かめ、どれかが外れれば拒む。
func Verify(raw string, o Options) (*Credential, error) {
	if o.IssuerKey == nil || o.Audience == "" || o.Nonce == "" || o.KBMaxAge <= 0 {
		return nil, errors.New("sdjwt: incomplete verification options")
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if p.KBJWT == "" {
		return nil, failed("key binding JWT is required")
	}
	jws, err := jose.ParseSignedCompact(p.IssuerJWT, Algorithms)
	if err != nil {
		return nil, failed("issuer-signed JWT: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, failed("issuer-signed JWT must have one signature")
	}
	h := jws.Signatures[0].Protected
	if typ := headerType(h); typ != TypeVC && typ != TypeVCLegacy {
		return nil, failed("unexpected typ %q", typ)
	}
	unverified, err := decodeObject(jws.UnsafePayloadWithoutVerification())
	if err != nil {
		return nil, failed("issuer-signed JWT payload: %v", err)
	}
	iss, ok := unverified["iss"].(string)
	if !ok || iss == "" {
		return nil, failed("iss is missing")
	}
	key, err := o.IssuerKey(iss, h)
	if err != nil {
		return nil, fmt.Errorf("%w: issuer key: %w", ErrVerification, err)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, failed("issuer signature: %v", err)
	}
	claims, err := decodeObject(payload)
	if err != nil {
		return nil, failed("issuer-signed JWT payload: %v", err)
	}
	if claims["iss"] != iss {
		return nil, failed("iss changed")
	}
	if alg, ok := claims["_sd_alg"]; ok && alg != "sha-256" {
		return nil, failed("unsupported _sd_alg")
	}
	vct, ok := claims["vct"].(string)
	if !ok || vct == "" {
		return nil, failed("vct is missing")
	}
	if err := checkTimes(claims, o.Now, o.Skew); err != nil {
		return nil, err
	}
	holder, err := holderKey(claims)
	if err != nil {
		return nil, err
	}
	disclosed, err := Disclose(claims, p.Disclosures, Reserved)
	if err != nil {
		return nil, err
	}
	if err := verifyKB(p, holder, o); err != nil {
		return nil, err
	}
	_, status := claims["status"]
	return &Credential{Issuer: iss, VCT: vct, Claims: disclosed, HasStatus: status}, nil
}

func headerType(h jose.Header) string {
	s, _ := h.ExtraHeaders[jose.HeaderType].(string)
	return s
}

// numericDate は JWT の時刻（秒。小数を許す）を読む。
func numericDate(v any) (time.Time, error) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, errors.New("not a number")
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}, errors.New("out of range")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}

// checkTimes は exp・nbf・iat を確かめる（あれば）。
func checkTimes(claims map[string]any, now time.Time, skew time.Duration) error {
	for _, name := range []string{"exp", "nbf", "iat"} {
		v, ok := claims[name]
		if !ok {
			continue
		}
		t, err := numericDate(v)
		if err != nil {
			return failed("%s: %v", name, err)
		}
		switch name {
		case "exp":
			if !now.Before(t.Add(skew)) {
				return failed("credential expired")
			}
		default:
			if t.After(now.Add(skew)) {
				return failed("credential %s is in the future", name)
			}
		}
	}
	return nil
}

// holderKey は cnf.jwk の公開鍵を返す。非対称の公開鍵だけを受ける。
func holderKey(claims map[string]any) (*jose.JSONWebKey, error) {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, failed("cnf is missing")
	}
	raw, ok := cnf["jwk"]
	if !ok {
		return nil, failed("cnf.jwk is missing")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, failed("cnf.jwk: %v", err)
	}
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(b); err != nil {
		return nil, failed("cnf.jwk: %v", err)
	}
	if !k.Valid() || !k.IsPublic() {
		return nil, failed("cnf.jwk is not a public key")
	}
	if _, sym := k.Key.([]byte); sym {
		return nil, failed("cnf.jwk is a symmetric key")
	}
	return &k, nil
}

// SDHash は KB-JWT の sd_hash（最後の ~ までの SHA-256）。
func SDHash(signed string) string {
	h := sha256.Sum256([]byte(signed))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// verifyKB は KB-JWT を確かめる。
func verifyKB(p *Presentation, holder *jose.JSONWebKey, o Options) error {
	jws, err := jose.ParseSignedCompact(p.KBJWT, Algorithms)
	if err != nil {
		return failed("key binding JWT: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return failed("key binding JWT must have one signature")
	}
	if typ := headerType(jws.Signatures[0].Protected); typ != TypeKB {
		return failed("unexpected key binding typ %q", typ)
	}
	payload, err := jws.Verify(holder.Key)
	if err != nil {
		return failed("key binding signature: %v", err)
	}
	c, err := decodeObject(payload)
	if err != nil {
		return failed("key binding payload: %v", err)
	}
	aud, _ := c["aud"].(string)
	nonce, _ := c["nonce"].(string)
	sdHash, _ := c["sd_hash"].(string)
	switch {
	case !equal(aud, o.Audience):
		return failed("key binding aud mismatch")
	case !equal(nonce, o.Nonce):
		return failed("key binding nonce mismatch")
	case !equal(sdHash, SDHash(p.Signed)):
		return failed("key binding sd_hash mismatch")
	}
	iat, err := numericDate(c["iat"])
	if err != nil {
		return failed("key binding iat: %v", err)
	}
	if iat.After(o.Now.Add(o.Skew)) || iat.Before(o.Now.Add(-o.KBMaxAge-o.Skew)) {
		return failed("key binding iat out of range")
	}
	return nil
}
