package ssf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Subject は Subject Identifier（RFC 9493）。送信側は iss_sub を出し、受信側は email・iss_sub・opaque と、
// それらを user・device・session に持つ complex を読む。
type Subject struct {
	Format  string   `json:"format"`
	Email   string   `json:"email,omitempty"`
	Iss     string   `json:"iss,omitempty"`
	Sub     string   `json:"sub,omitempty"`
	ID      string   `json:"id,omitempty"`
	User    *Subject `json:"user,omitempty"`
	Device  *Subject `json:"device,omitempty"`
	Session *Subject `json:"session,omitempty"`
}

// 書式（RFC 9493）。
const (
	FormatEmail   = "email"
	FormatIssSub  = "iss_sub"
	FormatOpaque  = "opaque"
	FormatComplex = "complex"
)

const maxSubjectField = 512

// Valid は書式と必須の項目を確かめる。complex の中に complex は置けない。
func (s *Subject) Valid() bool { return s != nil && s.valid(true) }

func (s *Subject) valid(top bool) bool {
	for _, v := range []string{s.Format, s.Email, s.Iss, s.Sub, s.ID} {
		if len(v) > maxSubjectField {
			return false
		}
	}
	nested := s.User != nil || s.Device != nil || s.Session != nil
	switch s.Format {
	case FormatEmail:
		return s.Email != "" && !nested
	case FormatIssSub:
		return s.Iss != "" && s.Sub != "" && !nested
	case FormatOpaque:
		return s.ID != "" && !nested
	case FormatComplex:
		if !top || !nested {
			return false
		}
		for _, m := range []*Subject{s.User, s.Device, s.Session} {
			if m != nil && !m.valid(false) {
				return false
			}
		}
		return true
	}
	// 知らない書式は、complex の中でなければ受けない（読めない対象に動作しない）。
	return !top && s.Format != "" && !nested
}

// UserPart は利用者を表す部分（complex なら user）を返す。無ければ nil。
func (s *Subject) UserPart() *Subject {
	if s == nil {
		return nil
	}
	if s.Format == FormatComplex {
		return s.User
	}
	return s
}

// SET は Security Event Token（RFC 8417）の、確かめた後の中身。
type SET struct {
	Issuer   string
	Audience []string
	IssuedAt time.Time
	JTI      string
	TxN      string
	// Subject は sub_id（SSF 1.0）。無ければイベントの中の subject（古い RISC の形）。
	Subject *Subject
	// Event と Payload は1つだけのイベント（SSF 1.0 は1つの SET に1つのイベント）。
	Event   string
	Payload map[string]any
}

// EventTime はイベントの event_timestamp（無ければ iat）。
func (s SET) EventTime() time.Time {
	if v, ok := s.Payload["event_timestamp"].(json.Number); ok {
		if n, err := v.Int64(); err == nil && n > 0 {
			return time.Unix(n, 0).UTC()
		}
	}
	return s.IssuedAt
}

// String は Payload の文字列の項目（無ければ空）。
func (s SET) String(key string) string {
	v, _ := s.Payload[key].(string)
	return v
}

// 受け付けない SET の理由（RFC 8935 2.3 の err）。
var (
	ErrInvalidRequest  = errors.New("invalid_request")
	ErrInvalidKey      = errors.New("invalid_key")
	ErrInvalidIssuer   = errors.New("invalid_issuer")
	ErrInvalidAudience = errors.New("invalid_audience")
)

const (
	// MaxSETBytes は受け付ける SET の大きさの上限。
	MaxSETBytes = 64 << 10
	maxJTI      = 256
	setSkew     = time.Minute
)

// acceptedAlgs は受け付ける署名の方式（非対称のものだけ。none と HMAC は受けない）。
var acceptedAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// Header は SET の JWS の保護ヘッダーのうち、検証の前に読むもの。
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// ParseHeader は compact の JWS の保護ヘッダーを読み、alg と typ を確かめる（署名はまだ確かめない）。
func ParseHeader(compact []byte) (Header, error) {
	if len(compact) == 0 || len(compact) > MaxSETBytes || bytes.Count(compact, []byte(".")) != 2 {
		return Header{}, ErrInvalidRequest
	}
	seg, _, _ := bytes.Cut(compact, []byte("."))
	raw, err := base64.RawURLEncoding.DecodeString(string(seg))
	if err != nil {
		return Header{}, ErrInvalidRequest
	}
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, ErrInvalidRequest
	}
	if !slices.Contains(acceptedAlgs, h.Alg) {
		return Header{}, ErrInvalidKey
	}
	if t := strings.ToLower(h.Typ); t != SETType && t != "application/"+SETType {
		return Header{}, ErrInvalidRequest
	}
	return h, nil
}

// VerifySignature は SET の署名を keys（公開鍵だけ）で確かめ、ペイロードを返す。kid があれば同じ kid の鍵だけを使う。
func VerifySignature(compact []byte, h Header, keys jwk.Set) ([]byte, error) {
	if keys == nil || keys.Len() == 0 {
		return nil, ErrInvalidKey
	}
	payload, err := jws.Verify(compact, jws.WithKeySet(keys, jws.WithRequireKid(h.Kid != ""), jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, ErrInvalidKey
	}
	return payload, nil
}

// rawClaims は SET の JSON の形。
type rawClaims struct {
	Iss    string                     `json:"iss"`
	Aud    json.RawMessage            `json:"aud"`
	Iat    json.Number                `json:"iat"`
	Exp    json.Number                `json:"exp"`
	Jti    string                     `json:"jti"`
	Txn    string                     `json:"txn"`
	SubID  *Subject                   `json:"sub_id"`
	Events map[string]json.RawMessage `json:"events"`
	// sub は SET には使わない（RFC 8417 では events の対象を表さない）。
}

// ParseClaims は確かめた署名のペイロードを読み、SET の形（iss・iat・jti・1つのイベント・対象）を確かめる。
// aud・iss の値の照合と再送の判定は呼び出し側が行う。
func ParseClaims(payload []byte, now time.Time, maxAge time.Duration) (SET, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var c rawClaims
	if err := dec.Decode(&c); err != nil || dec.More() {
		return SET{}, ErrInvalidRequest
	}
	if c.Iss == "" || c.Jti == "" || len(c.Jti) > maxJTI || len(c.Iss) > maxSubjectField || len(c.Txn) > maxJTI {
		return SET{}, ErrInvalidRequest
	}
	iat, err := c.Iat.Int64()
	if err != nil || iat <= 0 {
		return SET{}, ErrInvalidRequest
	}
	at := time.Unix(iat, 0).UTC()
	if at.After(now.Add(setSkew)) || now.Sub(at) > maxAge {
		return SET{}, ErrInvalidRequest
	}
	if c.Exp != "" {
		exp, err := c.Exp.Int64()
		if err != nil || !now.Before(time.Unix(exp, 0).Add(setSkew)) {
			return SET{}, ErrInvalidRequest
		}
	}
	aud, err := audience(c.Aud)
	if err != nil {
		return SET{}, err
	}
	if len(c.Events) != 1 {
		return SET{}, ErrInvalidRequest
	}
	out := SET{Issuer: c.Iss, Audience: aud, IssuedAt: at, JTI: c.Jti, TxN: c.Txn, Subject: c.SubID}
	for uri, raw := range c.Events {
		if uri == "" || len(uri) > maxSubjectField {
			return SET{}, ErrInvalidRequest
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var p map[string]any
		if err := d.Decode(&p); err != nil || p == nil {
			return SET{}, ErrInvalidRequest
		}
		out.Event, out.Payload = uri, p
	}
	if out.Subject == nil {
		// 古い RISC の形（イベントの中の subject）。
		if raw, ok := out.Payload["subject"]; ok {
			b, err := json.Marshal(raw)
			if err != nil {
				return SET{}, ErrInvalidRequest
			}
			var s Subject
			if err := json.Unmarshal(b, &s); err != nil {
				return SET{}, ErrInvalidRequest
			}
			out.Subject = &s
		}
	}
	if !out.Subject.Valid() {
		return SET{}, ErrInvalidRequest
	}
	return out, nil
}

// audience は aud（文字列か文字列の配列）を読む。無いのは誤り（受信側は aud で自分宛てかを確かめる）。
func audience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidAudience
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil, ErrInvalidAudience
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 || len(many) > 20 {
		return nil, ErrInvalidAudience
	}
	return many, nil
}

// PublicKeys は JWKS を読み、公開鍵（RSA・EC・OKP）だけの集合にする。秘密鍵・共通鍵を含む集合は受けない。
func PublicKeys(raw []byte) (jwk.Set, error) {
	if len(raw) == 0 || len(raw) > maxJWKSBytes {
		return nil, ErrInvalidKey
	}
	set, err := jwk.Parse(raw)
	if err != nil || set.Len() == 0 {
		return nil, ErrInvalidKey
	}
	for i := range set.Len() {
		k, _ := set.Key(i)
		switch k.(type) {
		case jwk.RSAPublicKey, jwk.ECDSAPublicKey, jwk.OKPPublicKey:
		default:
			return nil, ErrInvalidKey
		}
		if hasPrivate(k) {
			return nil, ErrInvalidKey
		}
	}
	return set, nil
}

const maxJWKSBytes = 64 << 10

// hasPrivate は鍵が秘密の項目を持つかを返す（秘密鍵の型が公開鍵のインターフェースも満たす場合に備え、JSON で確かめる）。
func hasPrivate(k jwk.Key) bool {
	b, err := json.Marshal(k)
	if err != nil {
		return true
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return true
	}
	for _, f := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"} {
		if _, ok := m[f]; ok {
			return true
		}
	}
	return false
}
