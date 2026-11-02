// Package hotp は HOTP（RFC 4226。HMAC-SHA1 のカウンター方式の OTP）の認証方式（ADR 0090、0092）。
//
// 認証方式のプラグインの参照実装。フィーチャー hotp（既定オフ）で動き、2要素目に使う。ハードウェアトークンと、
// カウンター方式の認証器アプリを想定する。
//
// セキュリティ上重要なコード（13.2）。秘密とカウンターは方式固有のデータとしてコアがユーザーのデータ鍵で暗号化して置き、
// ログに出さない。照合は次に期待するカウンターから先読みの窓（LookAhead）の中だけを受け入れ、受け入れたカウンターの次を
// 記録する（同じか前のカウンターのコードは再利用として拒否する）。記録はデータの比較つきの置き換え（CredentialStore.Update）で
// 原子的に行う。窓を外れたら、続けて出した2つのコードで再同期する（RFC 4226 7.4）。
package hotp

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 4226 の既定（トークンの互換性）。HMAC としての利用で、衝突耐性に依らない
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

const (
	// LookAhead はログインで受け入れる先読みの窓（次に期待するカウンターから数えた数。RFC 4226 7.4 のパラメーター s）。
	LookAhead = 10
	// ResyncWindow は再同期（続けて出した2つのコード）で探す窓。
	ResyncWindow = 200
	// SecretSize は生成する秘密の長さ（160bit。RFC 4226 4 の推奨）。
	SecretSize = 20
	// MinSecretSize は取り込む秘密の下限（128bit。RFC 4226 4 の要件）。
	MinSecretSize = 16
	// MaxSecretSize は取り込む秘密の上限（HMAC-SHA1 のブロック長）。
	MaxSecretSize = 64
)

var pow10 = [...]uint32{6: 1_000_000, 7: 10_000_000, 8: 100_000_000}

// ValidDigits は桁数として扱える値（6〜8。RFC 4226 5.3）かを返す。
func ValidDigits(d int) bool { return d >= 6 && d <= 8 }

// Code はカウンター counter のコード（RFC 4226 5.3）。digits は 6〜8。
func Code(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, v%pow10[digits])
}

// Verify は code が next から window 個（next, next+1, …, next+window-1）のどれかのカウンターに合えば、そのカウンターと true を返す。
// 呼び出し側は返したカウンターの次を記録し、それより前のカウンターを拒否する。早く抜けず、窓の全部を同じ手順で比べる。
func Verify(secret []byte, code string, next uint64, window, digits int) (uint64, bool) {
	if !ValidDigits(digits) || len(code) != digits || window <= 0 {
		return 0, false
	}
	var found uint64
	ok := 0
	for i := range uint64(window) { // #nosec G115 -- window は正
		c := next + i
		if c < next {
			break // 桁あふれ
		}
		if subtle.ConstantTimeCompare([]byte(Code(secret, c, digits)), []byte(code)) == 1 && ok == 0 {
			found, ok = c, 1
		}
	}
	return found, ok == 1
}

// Resync は code と nextCode が続いたカウンター（c と c+1）のコードになる c を、next から window 個の中で探す（RFC 4226 7.4）。
// 見つかれば c+1（最後に使ったカウンター）と true を返す。
func Resync(secret []byte, code, nextCode string, next uint64, window, digits int) (uint64, bool) {
	if !ValidDigits(digits) || len(code) != digits || len(nextCode) != digits || window <= 0 {
		return 0, false
	}
	var found uint64
	ok := 0
	prev := Code(secret, next, digits)
	for i := range uint64(window) { // #nosec G115 -- window は正
		c := next + i
		if c+1 < next {
			break // 桁あふれ
		}
		cur := Code(secret, c+1, digits)
		match := subtle.ConstantTimeCompare([]byte(prev), []byte(code)) & subtle.ConstantTimeCompare([]byte(cur), []byte(nextCode))
		if match == 1 && ok == 0 {
			found, ok = c+1, 1
		}
		prev = cur
	}
	return found, ok == 1
}
