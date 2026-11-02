package sdjwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxDepth は JSON の入れ子の上限。
const MaxDepth = 32

// errDuplicate は同じ名前の項目が 2 つあること（どちらを信じるかが実装で違うので拒む）。
var errDuplicate = errors.New("sdjwt: duplicate member name")

// decodeJSON は JSON を1つ読む。数は json.Number のまま、同じ名前の項目と、入れ子の上限を超えるものと、後ろの余りを拒む。
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("sdjwt: trailing data after JSON value")
	}
	return v, nil
}

// DecodeObject は JSON のオブジェクトを1つ、decodeJSON と同じ厳しさで読む（数は json.Number）。
func DecodeObject(b []byte) (map[string]any, error) { return decodeObject(b) }

// decodeObject は JSON のオブジェクトを1つ読む。
func decodeObject(b []byte) (map[string]any, error) {
	v, err := decodeJSON(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("sdjwt: not a JSON object")
	}
	return m, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, errors.New("sdjwt: JSON nested too deeply")
	}
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("sdjwt: invalid JSON: %w", err)
	}
	switch t := t.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("sdjwt: invalid JSON: %w", err)
				}
				name, ok := k.(string)
				if !ok {
					return nil, errors.New("sdjwt: invalid JSON member name")
				}
				if _, dup := m[name]; dup {
					return nil, errDuplicate
				}
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[name] = v
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, fmt.Errorf("sdjwt: invalid JSON: %w", err)
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, fmt.Errorf("sdjwt: invalid JSON: %w", err)
			}
			return a, nil
		}
		return nil, errors.New("sdjwt: invalid JSON")
	default:
		return t, nil // string・json.Number・bool・nil
	}
}
