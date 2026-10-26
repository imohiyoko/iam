// Package totp は TOTP（RFC 6238。HMAC-SHA1、6 桁、30 秒）の秘密の生成とコードの照合を行う（design.md 4.1）。
//
// セキュリティ上重要なコード（13.2）。秘密はユーザーのデータ鍵で暗号化して置き（9.5）、ログに出さない。
// 照合は前後1つの時間窓まで受け入れ、使った窓は記録して同じか前の窓のコードを拒否する（再利用の防止）。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 の既定（認証器アプリの互換性）。HMAC としての利用で、衝突耐性に依らない
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	// Period は時間窓の長さ。
	Period = 30 * time.Second
	// Digits はコードの桁数。
	Digits = 6
	// Skew は前後に受け入れる時間窓の数（時計のずれと入力の遅れ）。
	Skew = 1
	// SecretSize は秘密の長さ（160bit。RFC 4226 の推奨）。
	SecretSize = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret は新しい秘密を返す。
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Encode は秘密を認証器アプリに入力する形（Base32、パディングなし）にする。
func Encode(secret []byte) string { return b32.EncodeToString(secret) }

// URI は認証器アプリに読ませる otpauth:// の URI（QR コードの内容）を返す。
func URI(secret []byte, issuer, account string) string {
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(int(Period / time.Second))}}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account, RawQuery: q.Encode()}).String()
}

// Step は t の時間窓。
func Step(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code は時間窓 step のコード（RFC 4226 の HOTP）。
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- 時間窓は負にならない
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1_000_000)
}

// Verify は code が now の前後 Skew の時間窓のどれかに合えば、その窓と true を返す。
// 呼び出し側は返した窓を記録し、同じか前の窓を拒否する。
func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := 0
	for d := int64(-Skew); d <= Skew; d++ {
		// 早く抜けず、全部の窓を同じ手順で比べる。
		if subtle.ConstantTimeCompare([]byte(Code(secret, cur+d)), []byte(code)) == 1 && ok == 0 {
			found, ok = cur+d, 1
		}
	}
	return found, ok == 1
}
