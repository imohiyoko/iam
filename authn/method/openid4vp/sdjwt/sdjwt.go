// Package sdjwt は SD-JWT（RFC 9901）と SD-JWT VC の提示（key binding 付き）を確かめ（ADR 0108）、発行のために組み立てる（ADR 0119）。
//
// JWS の署名の確認は go-jose に任せ、受ける alg を非対称の署名に限る。開示（disclosure）の処理は RFC 9901 7.1 のとおりに自前で行い、
// 少しでも形が外れたものは拒む（fail-closed）。入力は攻撃者のものとして扱い、大きさと入れ子に上限を置く。
//
// セキュリティ上重要なコード（13.2）。解析と開示の処理にファジングのテストがある。
package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// 大きさの上限。
const (
	// MaxSize は提示（SD-JWT と KB-JWT）の文字数の上限。
	MaxSize = 64 << 10
	// MaxDisclosures は開示の数の上限。
	MaxDisclosures = 256
)

// Presentation は区切り（~）で分けた提示。
type Presentation struct {
	// IssuerJWT は発行者が署名した JWT（compact）。
	IssuerJWT string
	// Disclosures は開示（base64url のまま）。
	Disclosures []string
	// KBJWT は key binding の JWT（無ければ空）。
	KBJWT string
	// Signed は KB-JWT の sd_hash の対象（最後の ~ まで）。
	Signed string
}

// ErrMalformed は提示の形の誤り。
var ErrMalformed = errors.New("sdjwt: malformed presentation")

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// isB64URL は s が空でない base64url（パディング無し）の文字だけかを返す。
func isB64URL(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// isCompactJWS は s が JWS の compact の形（base64url の 3 つの区切り）かを返す。
func isCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && isB64URL(parts[0]) && isB64URL(parts[1]) && isB64URL(parts[2])
}

// Parse は提示を区切りで分ける。形（JWS の compact、開示の文字、数と大きさの上限）だけを確かめ、署名は確かめない。
func Parse(s string) (*Presentation, error) {
	if len(s) > MaxSize {
		return nil, malformed("presentation too large")
	}
	last := strings.LastIndexByte(s, '~')
	if last < 0 {
		return nil, malformed("no disclosure separator")
	}
	parts := strings.Split(s[:last], "~")
	if len(parts)-1 > MaxDisclosures {
		return nil, malformed("too many disclosures")
	}
	p := &Presentation{IssuerJWT: parts[0], Disclosures: parts[1:], KBJWT: s[last+1:], Signed: s[:last+1]}
	if !isCompactJWS(p.IssuerJWT) {
		return nil, malformed("issuer-signed JWT is not a compact JWS")
	}
	for _, d := range p.Disclosures {
		if !isB64URL(d) {
			return nil, malformed("disclosure is not base64url")
		}
	}
	if p.KBJWT != "" && !isCompactJWS(p.KBJWT) {
		return nil, malformed("key binding JWT is not a compact JWS")
	}
	return p, nil
}

// Digest は開示のダイジェスト（sha-256。base64url の文字列のハッシュ）。
func Digest(disclosure string) string {
	h := sha256.Sum256([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// disclosure は解析した開示。
type disclosure struct {
	name    string
	hasName bool
	value   any
	used    bool
}

// parseDisclosure は開示（base64url の JSON の配列）を読む。オブジェクトの値は [salt, 名前, 値]、配列の要素は [salt, 値]。
func parseDisclosure(raw string) (*disclosure, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, malformed("disclosure is not base64url")
	}
	v, err := decodeJSON(b)
	if err != nil {
		return nil, fmt.Errorf("%w: disclosure: %w", ErrMalformed, err)
	}
	a, ok := v.([]any)
	if !ok || (len(a) != 2 && len(a) != 3) {
		return nil, malformed("disclosure is not a 2 or 3 element array")
	}
	if _, ok := a[0].(string); !ok {
		return nil, malformed("disclosure salt is not a string")
	}
	if len(a) == 2 {
		return &disclosure{value: a[1]}, nil
	}
	name, ok := a[1].(string)
	if !ok {
		return nil, malformed("disclosure claim name is not a string")
	}
	if name == "_sd" || name == "..." {
		return nil, malformed("disclosure uses a reserved claim name")
	}
	return &disclosure{name: name, hasName: true, value: a[2]}, nil
}

// discloser は開示を payload に戻す処理の状態。
type discloser struct {
	byDigest map[string]*disclosure
	seen     map[string]bool // payload と開示の中で見たダイジェスト（重複を拒む）
	reserved map[string]bool // 最上位で開示してはならない名前
}

// Disclose は発行者の JWT の payload（claims）に開示を戻した結果を返す（RFC 9901 7.1）。claims は書き換えない。
// reserved は最上位で選択的に開示してはならない名前（SD-JWT VC の iss・cnf など）。
//
// 拒むもの：同じ開示が 2 つ、同じダイジェストが 2 回現れる、どこからも指されない開示、名前の無い開示を _sd から指す・名前のある開示を
// 配列から指す、既にある名前を開示で上書きする、`...` に別の項目がある配列の要素、_sd が文字列の配列でない、入れ子の _sd_alg。
// 指す開示の無いダイジェスト（デコイ）は捨てる。
func Disclose(claims map[string]any, disclosures []string, reserved []string) (map[string]any, error) {
	if len(disclosures) > MaxDisclosures {
		return nil, malformed("too many disclosures")
	}
	d := &discloser{byDigest: map[string]*disclosure{}, seen: map[string]bool{}, reserved: map[string]bool{}}
	for _, r := range reserved {
		d.reserved[r] = true
	}
	for _, raw := range disclosures {
		dg := Digest(raw)
		if _, dup := d.byDigest[dg]; dup {
			return nil, malformed("duplicate disclosure")
		}
		x, err := parseDisclosure(raw)
		if err != nil {
			return nil, err
		}
		d.byDigest[dg] = x
	}
	out, err := d.object(claims, 0, true)
	if err != nil {
		return nil, err
	}
	for _, x := range d.byDigest {
		if !x.used {
			return nil, malformed("disclosure is not referenced")
		}
	}
	return out, nil
}

func (d *discloser) value(v any, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, malformed("claims nested too deeply")
	}
	switch v := v.(type) {
	case map[string]any:
		return d.object(v, depth, false)
	case []any:
		return d.array(v, depth)
	}
	return v, nil
}

func (d *discloser) take(digest string) (*disclosure, error) {
	if d.seen[digest] {
		return nil, malformed("digest appears more than once")
	}
	d.seen[digest] = true
	x, ok := d.byDigest[digest]
	if !ok {
		return nil, nil // デコイか、提示しなかった開示
	}
	x.used = true
	return x, nil
}

func (d *discloser) object(in map[string]any, depth int, top bool) (map[string]any, error) {
	if depth > MaxDepth {
		return nil, malformed("claims nested too deeply")
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "_sd":
			continue
		case "_sd_alg":
			if !top {
				return nil, malformed("_sd_alg below the top level")
			}
			continue
		}
		x, err := d.value(v, depth+1)
		if err != nil {
			return nil, err
		}
		out[k] = x
	}
	raw, ok := in["_sd"]
	if !ok {
		return out, nil
	}
	digests, ok := raw.([]any)
	if !ok {
		return nil, malformed("_sd is not an array")
	}
	for _, x := range digests {
		dg, ok := x.(string)
		if !ok {
			return nil, malformed("_sd contains a non-string digest")
		}
		disc, err := d.take(dg)
		if err != nil {
			return nil, err
		}
		if disc == nil {
			continue
		}
		if !disc.hasName {
			return nil, malformed("array element disclosure referenced from _sd")
		}
		if _, exists := out[disc.name]; exists {
			return nil, malformed("disclosure overwrites an existing claim")
		}
		if _, exists := in[disc.name]; exists {
			return nil, malformed("disclosure overwrites an existing claim")
		}
		if top && d.reserved[disc.name] {
			return nil, malformed("claim %q must not be selectively disclosed", disc.name)
		}
		val, err := d.value(disc.value, depth+1)
		if err != nil {
			return nil, err
		}
		out[disc.name] = val
	}
	return out, nil
}

func (d *discloser) array(in []any, depth int) ([]any, error) {
	out := make([]any, 0, len(in))
	for _, e := range in {
		if m, ok := e.(map[string]any); ok {
			if raw, ok := m["..."]; ok {
				if len(m) != 1 {
					return nil, malformed("array element digest object has other members")
				}
				dg, ok := raw.(string)
				if !ok {
					return nil, malformed("array element digest is not a string")
				}
				disc, err := d.take(dg)
				if err != nil {
					return nil, err
				}
				if disc == nil {
					continue // デコイか、提示しなかった要素
				}
				if disc.hasName {
					return nil, malformed("object property disclosure referenced from an array")
				}
				val, err := d.value(disc.value, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, val)
				continue
			}
		}
		val, err := d.value(e, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
	return out, nil
}
