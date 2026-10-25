// Package id は型付き接頭辞つきの ID（UUIDv7）を扱う（design.md 2.4、ADR 0039）。
//
// 文字列の形は "<接頭辞>_<UUID を Crockford Base32 で 26 文字>"（例：usr_01JB…）。
// UUIDv7 は生成時刻の順に並ぶため、文字列の辞書順も生成順になる。
package id

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Prefix は ID の種類を表す接頭辞。
type Prefix string

const (
	Realm          Prefix = "rlm"
	User           Prefix = "usr"
	Email          Prefix = "eml"
	Identity       Prefix = "idn"
	Connection     Prefix = "con"
	Org            Prefix = "org"
	Membership     Prefix = "mbr"
	Invitation     Prefix = "inv"
	Session        Prefix = "ses"
	Suspension     Prefix = "sus"
	ServiceAccount Prefix = "sva"
	Client         Prefix = "cli"
	Passkey        Prefix = "psk"
	Notification   Prefix = "ntf"
	Event          Prefix = "evt"
	Outbox         Prefix = "obx"
	Group          Prefix = "grp"
	Role           Prefix = "rol"
	Request        Prefix = "req"
	MasterKey      Prefix = "mk"
	IndexKey       Prefix = "ik"
)

// ErrInvalid は ID の形式が正しくないことを表す。
var ErrInvalid = errors.New("id: invalid")

// crockford は Crockford Base32 のアルファベット（I L O U を含まない）。
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var decodeMap = func() [256]byte {
	var m [256]byte
	for i := range m {
		m[i] = 0xFF
	}
	for i := 0; i < len(crockford); i++ {
		m[crockford[i]] = byte(i)
		m[strings.ToLower(crockford[i : i+1])[0]] = byte(i)
	}
	return m
}()

// New は接頭辞つきの新しい UUIDv7 の ID を返す。
func New(p Prefix) string {
	u := uuid.Must(uuid.NewV7())
	return string(p) + "_" + encode(u)
}

// FromUUID は既存の UUID を接頭辞つきの文字列にする（ストレージの復元用）。
func FromUUID(p Prefix, u uuid.UUID) string {
	return string(p) + "_" + encode(u)
}

// Parse は ID を検証し、UUID を返す。接頭辞が違えばエラーにする（取り違えの防止）。
func Parse(p Prefix, s string) (uuid.UUID, error) {
	head, tail, ok := strings.Cut(s, "_")
	if !ok || head != string(p) {
		return uuid.Nil, fmt.Errorf("%w: want prefix %q", ErrInvalid, p)
	}
	u, err := decode(tail)
	if err != nil {
		return uuid.Nil, err
	}
	if u.Version() != 7 {
		return uuid.Nil, fmt.Errorf("%w: not UUIDv7", ErrInvalid)
	}
	return u, nil
}

// Valid は s が接頭辞 p の正しい ID かを返す。
func Valid(p Prefix, s string) bool {
	_, err := Parse(p, s)
	return err == nil
}

// encode は 128bit を 26 文字にする（先頭の文字は上位 3bit を表す）。
func encode(u uuid.UUID) string {
	var out [26]byte
	// 130bit として扱い、上位から 5bit ずつ取り出す。
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(u[i])
		lo = lo<<8 | uint64(u[i+8])
	}
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&0x1F]
		lo = lo>>5 | (hi&0x1F)<<59
		hi >>= 5
	}
	return string(out[:])
}

func decode(s string) (uuid.UUID, error) {
	if len(s) != 26 {
		return uuid.Nil, fmt.Errorf("%w: length", ErrInvalid)
	}
	if decodeMap[s[0]] > 7 {
		return uuid.Nil, fmt.Errorf("%w: overflow", ErrInvalid)
	}
	var hi, lo uint64
	for i := 0; i < 26; i++ {
		v := decodeMap[s[i]]
		if v == 0xFF {
			return uuid.Nil, fmt.Errorf("%w: character", ErrInvalid)
		}
		hi = hi<<5 | lo>>59
		lo = lo<<5 | uint64(v)
	}
	var u uuid.UUID
	for i := 7; i >= 0; i-- {
		u[i] = byte(hi)
		u[i+8] = byte(lo)
		hi >>= 8
		lo >>= 8
	}
	return u, nil
}
