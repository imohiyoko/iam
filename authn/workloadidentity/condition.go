package workloadidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/shared/errs"
)

// 結び付けの条件（ADR 0116）。クレームの値（文字列だけ）を完全一致・一覧・前方一致で比べる。式の評価はしない。

// 条件の上限。
const (
	MaxConditions    = 20
	MaxInValues      = 50
	MaxConditionText = 1024 // equals・in・prefix の 1 つの値のバイト数
	MaxPointerLength = 256
	MaxPointerDepth  = 8
	// maxConditionsJSON は条件の JSON 全体のバイト数の上限。
	maxConditionsJSON = 64 << 10
)

// ErrInvalidConditions は条件の誤り（400 invalid_conditions）。
var ErrInvalidConditions = errs.WithCode(errs.KindInvalid, "invalid_conditions", "invalid conditions")

// Condition は 1 つの条件。Claim は JSON Pointer（RFC 6901）で、Equals・In・Prefix のちょうど 1 つを持つ。
type Condition struct {
	Claim  string   `json:"claim"`
	Equals *string  `json:"equals,omitempty"`
	In     []string `json:"in,omitempty"`
	Prefix *string  `json:"prefix,omitempty"`

	path []string
}

func invalidConditions(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_conditions", "invalid conditions: "+msg)
}

// ParseConditions は条件の JSON（配列）を読み、確かめる。不明な項目・演算子が 0 個か 2 個以上・空の値・不正な Pointer・
// 上限の超過は ErrInvalidConditions。条件は 1 個以上（空の条件で、共有の issuer の誰でも通るようにはしない）。
func ParseConditions(b []byte) ([]Condition, error) {
	if len(b) > maxConditionsJSON {
		return nil, invalidConditions("too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cs []Condition
	if err := dec.Decode(&cs); err != nil {
		return nil, invalidConditions("malformed")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalidConditions("trailing data")
	}
	if len(cs) == 0 || len(cs) > MaxConditions {
		return nil, invalidConditions("1 to 20 conditions are required")
	}
	for i := range cs {
		if err := cs[i].validate(); err != nil {
			return nil, err
		}
	}
	return cs, nil
}

// MarshalConditions は確かめた条件を保存の形（JSON）にする。
func MarshalConditions(cs []Condition) ([]byte, error) { return json.Marshal(cs) }

func (c *Condition) validate() error {
	p, err := parsePointer(c.Claim)
	if err != nil {
		return err
	}
	c.path = p
	ops := 0
	if c.Equals != nil {
		ops++
		if !validText(*c.Equals) {
			return invalidConditions("equals must be a non-empty string of at most 1024 bytes")
		}
	}
	if c.In != nil {
		ops++
		if len(c.In) == 0 || len(c.In) > MaxInValues {
			return invalidConditions("in must have 1 to 50 values")
		}
		for _, v := range c.In {
			if !validText(v) {
				return invalidConditions("in values must be non-empty strings of at most 1024 bytes")
			}
		}
	}
	if c.Prefix != nil {
		ops++
		if !validText(*c.Prefix) {
			return invalidConditions("prefix must be a non-empty string of at most 1024 bytes")
		}
	}
	if ops != 1 {
		return invalidConditions("exactly one of equals, in, prefix is required")
	}
	return nil
}

func validText(s string) bool { return s != "" && len(s) <= MaxConditionText }

// parsePointer は JSON Pointer（RFC 6901）を区切りに分ける。先頭は "/"、区切りは空でなく、"~" の後は 0 か 1 だけ。深さは 8 まで。
func parsePointer(s string) ([]string, error) {
	if len(s) > MaxPointerLength || !strings.HasPrefix(s, "/") {
		return nil, invalidConditions("claim must be a JSON Pointer such as /sub")
	}
	parts := strings.Split(s[1:], "/")
	if len(parts) > MaxPointerDepth {
		return nil, invalidConditions("claim is nested too deeply")
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, invalidConditions("claim has an empty segment")
		}
		var b strings.Builder
		for i := 0; i < len(p); i++ {
			if p[i] != '~' {
				b.WriteByte(p[i])
				continue
			}
			if i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1') {
				return nil, invalidConditions("claim has an invalid ~ escape")
			}
			if p[i+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			i++
		}
		out = append(out, b.String())
	}
	return out, nil
}

// Match はクレーム（JSON のオブジェクトを読んだもの）が条件を満たすかを返す。値が無い・文字列でないものは満たさない。
func (c Condition) Match(claims map[string]any) bool {
	path := c.path
	if path == nil {
		var err error
		if path, err = parsePointer(c.Claim); err != nil {
			return false
		}
	}
	var v any = claims
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if v, ok = m[k]; !ok {
			return false
		}
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	switch {
	case c.Equals != nil:
		return *c.Equals != "" && s == *c.Equals
	case c.In != nil:
		return slices.Contains(c.In, s)
	case c.Prefix != nil:
		return *c.Prefix != "" && strings.HasPrefix(s, *c.Prefix)
	}
	return false
}

// MatchAll は条件をすべて満たすかを返す。条件が無ければ満たさない（fail closed）。
func MatchAll(cs []Condition, claims map[string]any) bool {
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		if !c.Match(claims) {
			return false
		}
	}
	return true
}
