// Package id は型付き接頭辞つきの ID を扱う（design.md 2.4、ADR 0039、0045）。
//
// 文字列の形は "<接頭辞>_<128bit を Crockford Base32 で 26 文字>"（例：usr_01JB…）で固定する。
// 中身の作り方（採番の方式）は Generator で差し替えられ、形には依存しない。方式を変えても、
// 既存の ID と新しい ID は同じ形のまま混在できる（マイグレーション不要）。
//
// ID は2種類ある（ADR 0045）。
//   - 内部 ID（New）：DB の主キーと参照に使い、Storage の外には出さない。既定は UUIDv7
//     （74bit が乱数。生成時刻の順に並ぶため、DB のインデックスの効率が良い）
//   - 外部 ID（NewExternal）：API・Cookie・トークン・通知・監査ログの外部出力に出す。既定は 122bit の乱数
//     （作成時刻も順序も読めない）
package id

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Generator は 128bit の値を作る。暗号論的な乱数を使い、推測できないこと。
type Generator interface {
	Generate() (uuid.UUID, error)
}

// UUIDv7 は時刻（ミリ秒）の順に並ぶ UUIDv7（RFC 9562）。内部 ID の既定。
// 時刻の 48bit 以外の 74bit（rand_a と rand_b）をすべて crypto/rand で埋める。
// 同じミリ秒の中の順序は付けない（uuid.NewV7 は rand_a を連番に使い、乱数が 62bit に減るため使わない）。
type UUIDv7 struct{}

func (UUIDv7) Generate() (uuid.UUID, error) {
	var u uuid.UUID
	if _, err := rand.Read(u[6:]); err != nil {
		return uuid.UUID{}, err
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli())) // #nosec G115 -- 1970 年より後の時刻
	copy(u[:6], ts[2:])
	u[6] = u[6]&0x0f | 0x70 // version 7
	u[8] = u[8]&0x3f | 0x80 // variant 10
	return u, nil
}

// Random は 122bit の乱数の UUIDv4（crypto/rand）。外部 ID の既定。
type Random struct{}

func (Random) Generate() (uuid.UUID, error) { return uuid.NewRandom() }

// Generators は名前で選べる採番の方式（設定ファイルの ids.internal / ids.external）。
var Generators = map[string]Generator{"uuidv7": UUIDv7{}, "random": Random{}}

type generators struct{ internal, external Generator }

var current atomic.Pointer[generators]

func init() { current.Store(&generators{internal: UUIDv7{}, external: Random{}}) }

// SetGenerators は採番の方式を差し替える。起動時（ID を作り始める前）に呼ぶ。
// 外部 ID に時刻の読める方式を使わないことは呼び出し側（設定の検証）で確かめる。
func SetGenerators(internal, external Generator) {
	current.Store(&generators{internal: internal, external: external})
}

func generate(g Generator) uuid.UUID {
	u, err := g.Generate()
	if err != nil {
		// 乱数の取得に失敗したまま ID を作り続けない。
		panic(fmt.Sprintf("id: generate: %v", err))
	}
	return u
}

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
	QuotaGrant     Prefix = "qgr"
	Session        Prefix = "ses"
	Suspension     Prefix = "sus"
	ServiceAccount Prefix = "sva"
	SACredential   Prefix = "sac"
	Client         Prefix = "cli"
	SigningKey     Prefix = "sgk"
	Grant          Prefix = "gnt"
	AccessToken    Prefix = "atk"
	RefreshToken   Prefix = "rtk"
	Passkey        Prefix = "psk"
	TOTP           Prefix = "otp"
	Password       Prefix = "pwd"
	RecoveryCode   Prefix = "rcv"
	Notification   Prefix = "ntf"
	Event          Prefix = "evt"
	Outbox         Prefix = "obx"
	Group          Prefix = "grp"
	Role           Prefix = "rol"
	RoleBinding    Prefix = "rbd"
	Flow           Prefix = "flw"
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

// New は新しい内部 ID を返す。Storage の外に出してはならない。
func New(p Prefix) string { return string(p) + "_" + encode(generate(current.Load().internal)) }

// NewExternal は新しい外部 ID を返す。
func NewExternal(p Prefix) string { return string(p) + "_" + encode(generate(current.Load().external)) }

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
	// 中身の作り方（UUID の版）は確かめない。方式を変えても既存の ID を受け付けるため。
	return decode(tail)
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
