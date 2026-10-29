// Package attribute はカスタム属性を扱う（design.md 11.7、ADR 0080）。
//
// realm ごとに属性を定義し（型・検証・本人による編集可否・トークンへの掲載・暗号化の有無）、ユーザーごとに値を持つ。
// 値は JSON で持ち、暗号化する属性はユーザーのデータ鍵で暗号化する（ユーザーの削除でデータ鍵を消すと読めなくなる）。
package attribute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー custom_attributes の宣言（features/customattributes が登録する）。
var Feature = feature.Feature{Name: feature.CustomAttributes, DataVersion: 1}

// 上限。
const (
	MaxDefs             = 50
	MaxStringLength     = 1024
	DefaultStringLength = 256
	MaxEnumValues       = 50
	MaxEnumValueLength  = 64
)

// 監査ログの出来事。
const (
	EventDefined      = "attribute.defined"
	EventUpdated      = "attribute.updated"
	EventDeleted      = "attribute.deleted"
	EventValuesUpdate = "user.attributes_updated"
)

// エラー。
var (
	ErrInvalidDef   = errs.WithCode(errs.KindInvalid, "invalid_attribute", "invalid attribute definition")
	ErrExists       = errs.WithCode(errs.KindConflict, "attribute_exists", "attribute exists")
	ErrLimit        = errs.WithCode(errs.KindFailedPrecondition, "attribute_limit", "too many attributes")
	ErrUnknown      = errs.WithCode(errs.KindInvalid, "unknown_attribute", "unknown attribute")
	ErrInvalidValue = errs.WithCode(errs.KindInvalid, "invalid_attribute_value", "invalid attribute value")
	ErrNotEditable  = errs.WithCode(errs.KindPermissionDenied, "attribute_not_editable", "attribute is not editable by the user")
)

const maxSafeInteger = 1<<53 - 1

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Service はカスタム属性を扱う。
type Service struct {
	Clock   clock.Clock
	Crypter *pii.Crypter
}

// Def は定義の入力。Type と Encrypted は作成のときだけ使う。
type Def struct {
	Key          string
	Type         port.AttributeType
	Values       []string
	MaxLength    int
	UserEditable bool
	InToken      bool
	Encrypted    bool
}

// Actor は操作する主体（監査ログ）。
type Actor struct {
	Audit     audit.Actor
	RequestID string
}

func (s *Service) record(ctx context.Context, tx port.Tx, realmID string, a Actor, typ string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: a.Audit,
		RequestID: a.RequestID, Details: details})
	return err
}

// check は型ごとの制約を確かめ、既定値を埋める。
func check(d *port.AttributeDef) error {
	switch d.Type {
	case port.AttributeString:
		if d.MaxLength == 0 {
			d.MaxLength = DefaultStringLength
		}
		if d.MaxLength < 1 || d.MaxLength > MaxStringLength || len(d.Values) != 0 {
			return ErrInvalidDef
		}
	case port.AttributeEnum:
		if len(d.Values) == 0 || len(d.Values) > MaxEnumValues || d.MaxLength != 0 {
			return ErrInvalidDef
		}
		for i, v := range d.Values {
			if v == "" || utf8.RuneCountInString(v) > MaxEnumValueLength || !utf8.ValidString(v) || slices.Contains(d.Values[:i], v) {
				return ErrInvalidDef
			}
		}
	case port.AttributeInteger, port.AttributeBoolean:
		if d.MaxLength != 0 || len(d.Values) != 0 {
			return ErrInvalidDef
		}
	default:
		return ErrInvalidDef
	}
	if d.Values == nil {
		d.Values = []string{}
	}
	return nil
}

func details(d port.AttributeDef) map[string]any {
	return map[string]any{"key": d.Key, "type": string(d.Type), "user_editable": d.UserEditable, "in_token": d.InToken, "encrypted": d.Encrypted}
}

// Define は属性を定義する。realm に MaxDefs まで。
func (s *Service) Define(ctx context.Context, tx port.Tx, realmID string, in Def, a Actor) (port.AttributeDef, error) {
	if !keyRE.MatchString(in.Key) {
		return port.AttributeDef{}, ErrInvalidDef
	}
	now := s.Clock.Now()
	d := port.AttributeDef{RealmID: realmID, Key: in.Key, Type: in.Type, Values: slices.Clone(in.Values), MaxLength: in.MaxLength,
		UserEditable: in.UserEditable, InToken: in.InToken, Encrypted: in.Encrypted, CreatedAt: now, UpdatedAt: now}
	if err := check(&d); err != nil {
		return port.AttributeDef{}, err
	}
	ds, err := tx.Attributes().ListDefs(ctx, realmID)
	if err != nil {
		return port.AttributeDef{}, err
	}
	if len(ds) >= MaxDefs {
		return port.AttributeDef{}, ErrLimit
	}
	if err := tx.Attributes().CreateDef(ctx, d); errors.Is(err, errs.Conflict) {
		return port.AttributeDef{}, ErrExists
	} else if err != nil {
		return port.AttributeDef{}, err
	}
	return d, s.record(ctx, tx, realmID, a, EventDefined, details(d))
}

// Update は定義の、型と暗号化の有無のほかを置き換える。制約を厳しくしても、既にある値はそのまま（次に書くときに確かめる）。
func (s *Service) Update(ctx context.Context, tx port.Tx, realmID string, in Def, a Actor) (port.AttributeDef, error) {
	d, err := tx.Attributes().GetDef(ctx, realmID, in.Key)
	if err != nil {
		return port.AttributeDef{}, err
	}
	d.Values, d.MaxLength, d.UserEditable, d.InToken, d.UpdatedAt = slices.Clone(in.Values), in.MaxLength, in.UserEditable, in.InToken, s.Clock.Now()
	if err := check(&d); err != nil {
		return port.AttributeDef{}, err
	}
	if err := tx.Attributes().UpdateDef(ctx, d); err != nil {
		return port.AttributeDef{}, err
	}
	return d, s.record(ctx, tx, realmID, a, EventUpdated, details(d))
}

// Delete は定義と、その属性のすべての値を消す。
func (s *Service) Delete(ctx context.Context, tx port.Tx, realmID, key string, a Actor) error {
	d, err := tx.Attributes().GetDef(ctx, realmID, key)
	if err != nil {
		return err
	}
	if err := tx.Attributes().DeleteDef(ctx, realmID, key); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, a, EventDeleted, details(d))
}

func defsByKey(ctx context.Context, tx port.Tx, realmID string) (map[string]port.AttributeDef, error) {
	ds, err := tx.Attributes().ListDefs(ctx, realmID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]port.AttributeDef, len(ds))
	for _, d := range ds {
		out[d.Key] = d
	}
	return out, nil
}

func aad(key string) string { return "user_attributes." + key }

// Values はユーザーの値を返す。onlyToken ならトークンに載せる属性だけ。復号できない値（データ鍵の削除）は返さない。
func (s *Service) Values(ctx context.Context, tx port.Tx, u port.User, onlyToken bool) (map[string]any, error) {
	realmID, userID := u.RealmID, u.ID
	defs, err := defsByKey(ctx, tx, realmID)
	if err != nil {
		return nil, err
	}
	vs, err := tx.Attributes().ListValues(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, v := range vs {
		d, ok := defs[v.Key]
		if !ok || onlyToken && !d.InToken {
			continue
		}
		raw := v.Value
		if d.Encrypted {
			raw, err = s.Crypter.Decrypt(ctx, tx.DataKeys(), userID, v.Value, aad(v.Key))
			if errors.Is(err, pii.ErrShredded) {
				continue
			}
			if err != nil {
				return nil, err
			}
		}
		var x any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&x); err != nil {
			return nil, err
		}
		out[v.Key] = x
	}
	return out, nil
}

// validate は値が定義に合うかを確かめ、保存する JSON を返す。
func validate(d port.AttributeDef, raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil || dec.More() {
		return nil, ErrInvalidValue
	}
	switch d.Type {
	case port.AttributeString:
		v, ok := x.(string)
		if !ok || utf8.RuneCountInString(v) > d.MaxLength {
			return nil, ErrInvalidValue
		}
	case port.AttributeEnum:
		v, ok := x.(string)
		if !ok || !slices.Contains(d.Values, v) {
			return nil, ErrInvalidValue
		}
	case port.AttributeBoolean:
		if _, ok := x.(bool); !ok {
			return nil, ErrInvalidValue
		}
	case port.AttributeInteger:
		n, ok := x.(json.Number)
		if !ok {
			return nil, ErrInvalidValue
		}
		i, err := n.Int64()
		// JavaScript で安全に扱える範囲に限る。
		if err != nil || i > maxSafeInteger || i < -maxSafeInteger {
			return nil, ErrInvalidValue
		}
		x = i
	default:
		return nil, ErrInvalidValue
	}
	return json.Marshal(x)
}

// Set はユーザーの値をまとめて書く（null は消す）。self なら本人の操作で、本人が編集できる属性だけを書ける。
// どれかが誤りなら何も書かない。監査ログには key だけを残す（値は残さない）。
func (s *Service) Set(ctx context.Context, tx port.Tx, u port.User, in map[string]json.RawMessage, self bool, a Actor) error {
	realmID, userID := u.RealmID, u.ID
	defs, err := defsByKey(ctx, tx, realmID)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	type write struct {
		key   string
		value []byte // nil なら消す
	}
	var ws []write
	for _, k := range keys {
		d, ok := defs[k]
		if !ok {
			return ErrUnknown
		}
		if self && !d.UserEditable {
			return ErrNotEditable
		}
		if bytes.Equal(bytes.TrimSpace(in[k]), []byte("null")) {
			ws = append(ws, write{key: k})
			continue
		}
		b, err := validate(d, in[k])
		if err != nil {
			return err
		}
		if d.Encrypted {
			if b, err = s.Crypter.Encrypt(ctx, tx.DataKeys(), userID, b, aad(k)); err != nil {
				return err
			}
		}
		ws = append(ws, write{key: k, value: b})
	}
	now := s.Clock.Now()
	for _, w := range ws {
		if w.value == nil {
			err = tx.Attributes().DeleteValue(ctx, realmID, userID, w.key)
		} else {
			err = tx.Attributes().SetValue(ctx, port.UserAttribute{RealmID: realmID, UserID: userID, Key: w.key, Value: w.value, UpdatedAt: now})
		}
		if err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return s.record(ctx, tx, realmID, a, EventValuesUpdate, map[string]any{"user_id": u.PublicID, "keys": keys, "by_self": self})
}
