package vci

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
)

// 鍵の所持の証明（proof の JWT。OpenID4VCI 8.2.1.1・付録 F.1）。攻撃者の入力として扱い、少しでも外れたものは拒む。

// MaxProofSize は proof の JWT の文字数の上限。
const MaxProofSize = 8 << 10

// ProofOptions は proof の確かめの条件。
type ProofOptions struct {
	// Audience は発行者の識別子（aud）。
	Audience string
	Now      time.Time
	// ClientID はアクセストークンの連携先（空なら匿名の Pre-Authorized Code。iss は比べない）。
	ClientID string
}

// Proof は確かめた proof。
type Proof struct {
	// Key はウォレットの公開鍵（ヘッダーの jwk）。資格情報の cnf.jwk にする。
	Key jose.JSONWebKey
	// Nonce は c_nonce（発行者が封をした値。呼び出し側が確かめて使用済みにする）。
	Nonce string
	// Thumbprint は鍵の JWK Thumbprint（RFC 7638、SHA-256、base64url）。
	Thumbprint string
}

func invalidProof(reason string) *Error { return vciError(CodeInvalidProof, reason) }

// allowedProofHeaders は proof のヘッダーで受ける項目。kid（DID）・x5c・key_attestation・trust_chain は受けない。
var allowedProofHeaders = map[string]bool{"alg": true, "typ": true, "jwk": true}

// VerifyProof は proof の JWT を確かめる（nonce の使用済みの確かめは呼び出し側）。
func VerifyProof(raw string, o ProofOptions) (Proof, error) {
	if raw == "" || len(raw) > MaxProofSize {
		return Proof{}, invalidProof("proof size")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Proof{}, invalidProof("not a compact jws")
	}
	// ヘッダーは go-jose より先に厳しく読む（重複した名前・知らない項目を拒む）。
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Proof{}, invalidProof("header encoding")
	}
	header, err := sdjwt.DecodeObject(hb)
	if err != nil {
		return Proof{}, invalidProof("header json")
	}
	for k := range header {
		if !allowedProofHeaders[k] {
			return Proof{}, invalidProof("header member " + k + " is not supported")
		}
	}
	if typ, _ := header["typ"].(string); typ != ProofType {
		return Proof{}, invalidProof("typ")
	}
	jws, err := jose.ParseSignedCompact(raw, sdjwt.Algorithms)
	if err != nil {
		return Proof{}, invalidProof("jws")
	}
	if len(jws.Signatures) != 1 {
		return Proof{}, invalidProof("signatures")
	}
	h := jws.Signatures[0].Protected
	jwk := h.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return Proof{}, invalidProof("jwk must be a public key")
	}
	if _, sym := jwk.Key.([]byte); sym {
		return Proof{}, invalidProof("jwk is symmetric")
	}
	if rawJWK, ok := header["jwk"].(map[string]any); !ok || hasPrivateMembers(rawJWK) {
		return Proof{}, invalidProof("jwk has private members")
	}
	if !algMatchesKey(jose.SignatureAlgorithm(h.Algorithm), jwk) {
		return Proof{}, invalidProof("alg does not match the key")
	}
	payload, err := jws.Verify(jwk.Key)
	if err != nil {
		return Proof{}, invalidProof("signature")
	}
	claims, err := sdjwt.DecodeObject(payload)
	if err != nil {
		return Proof{}, invalidProof("payload json")
	}
	if !audienceContains(claims["aud"], o.Audience) {
		return Proof{}, invalidProof("aud")
	}
	if iss, ok := claims["iss"]; ok {
		s, isStr := iss.(string)
		if !isStr || (o.ClientID != "" && s != o.ClientID) {
			return Proof{}, invalidProof("iss")
		}
	}
	iat, ok := numericDate(claims["iat"])
	if !ok || iat.After(o.Now.Add(Skew)) || iat.Before(o.Now.Add(-ProofMaxAge-Skew)) {
		return Proof{}, invalidProof("iat")
	}
	nonce, _ := claims["nonce"].(string)
	if nonce == "" {
		return Proof{}, vciError(CodeInvalidNonce, "nonce missing")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return Proof{}, invalidProof("thumbprint")
	}
	pub := jose.JSONWebKey{Key: jwk.Key}
	return Proof{Key: pub, Nonce: nonce, Thumbprint: base64.RawURLEncoding.EncodeToString(tp)}, nil
}

// hasPrivateMembers は JWK に秘密の項目（EC・OKP の d、RSA の d・p・q など、対称鍵の k）があるかを返す。
func hasPrivateMembers(m map[string]any) bool {
	for _, k := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// algMatchesKey は alg が鍵の種類と曲線に合うかを返す（ES256 に P-384 の鍵などを拒む）。
func algMatchesKey(alg jose.SignatureAlgorithm, k *jose.JSONWebKey) bool {
	b, err := k.MarshalJSON()
	if err != nil {
		return false
	}
	var m struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
	}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	switch alg {
	case jose.ES256:
		return m.Kty == "EC" && m.Crv == "P-256"
	case jose.ES384:
		return m.Kty == "EC" && m.Crv == "P-384"
	case jose.ES512:
		return m.Kty == "EC" && m.Crv == "P-521"
	case jose.EdDSA:
		return m.Kty == "OKP" && m.Crv == "Ed25519"
	}
	return false
}

func audienceContains(v any, want string) bool {
	switch a := v.(type) {
	case string:
		return want != "" && a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && want != "" && s == want {
				return true
			}
		}
	}
	return false
}

// numericDate は JWT の時刻（秒）を読む。
func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}
