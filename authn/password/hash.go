package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params は argon2id のパラメータ（RFC 9106）。
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// DefaultParams は OWASP の推奨（m=19MiB, t=2, p=1）より重い既定。照合1回が数十ミリ秒になる。
var DefaultParams = Params{Memory: 64 * 1024, Time: 2, Threads: 1}

const (
	saltLen = 16
	keyLen  = 32
)

var b64 = base64.RawStdEncoding

// Hash はパスワードを argon2id で PHC 文字列にする。
func Hash(password string, p Params) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify はパスワードがハッシュと一致するかを定数時間で確かめる。rehash はパラメータが p と違うこと
// （照合に成功したら作り直す）。
func Verify(password, encoded string, p Params) (ok, rehash bool, err error) {
	got, salt, key, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	k := argon2.IDKey([]byte(password), salt, got.Time, got.Memory, got.Threads, uint32(len(key))) // #nosec G115 -- 長さは decode で上限を確かめた
	return subtle.ConstantTimeCompare(k, key) == 1, got != p, nil
}

var errFormat = errors.New("password: malformed hash")

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return Params{}, nil, nil, errFormat
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, errFormat
	}
	// 壊れた（または書き換えられた）ハッシュで過大な計算をしない。
	if p.Memory < 8 || p.Memory > 1<<21 || p.Time < 1 || p.Time > 16 || p.Threads < 1 || p.Threads > 16 {
		return Params{}, nil, nil, errFormat
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Params{}, nil, nil, errFormat
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return Params{}, nil, nil, errFormat
	}
	return p, salt, key, nil
}
