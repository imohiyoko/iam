package pat

import (
	"crypto/rand"
	"crypto/sha256"
	"hash/crc32"
	"strings"

	"github.com/imohiyoko/iam/shared/id"
)

// トークンの形（ADR 0109）：
//
//	iampat_<トークン ID の 26 文字>_<秘密 43 文字><検査 6 文字>
//
// トークン ID は外部 ID（pat_…）の Crockford Base32 の部分。秘密は base62 で約 256 bit。検査は、その前のすべての CRC32（IEEE）を
// base62 の 6 文字にしたもの（秘密の走査で誤検知を減らすため。秘密ではない）。

const (
	// Prefix はトークンの接頭辞（秘密の走査で見つけやすくするため、他のトークンと重ならないもの）。
	Prefix = "iampat_"
	// Pattern は秘密の走査に使える正規表現（ドキュメント用）。
	Pattern = `iampat_[0-9A-HJKMNP-TV-Z]{26}_[0-9A-Za-z]{49}`

	idLength       = 26
	secretLength   = 43
	checksumLength = 6
	// TokenLength はトークンの長さ。
	TokenLength = len(Prefix) + idLength + 1 + secretLength + checksumLength
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Looks は token が PAT の接頭辞を持つか（どの経路で確かめるかを選ぶため。正しいかは Parse で確かめる）。
func Looks(token string) bool { return strings.HasPrefix(token, Prefix) }

// newSecret は base62 の秘密（crypto/rand から棄却法で一様に取る）を返す。
func newSecret() (string, error) {
	out := make([]byte, 0, secretLength)
	buf := make([]byte, 64)
	for len(out) < secretLength {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			// 248 = 62 × 4。それ以上は捨てる（偏りを無くす）。
			if b < 248 && len(out) < secretLength {
				out = append(out, base62[b%62])
			}
		}
	}
	return string(out), nil
}

// checksum は s の CRC32 を base62 の 6 文字にする（62^6 > 2^32）。
func checksum(s string) string {
	v := uint64(crc32.ChecksumIEEE([]byte(s)))
	var out [checksumLength]byte
	for i := checksumLength - 1; i >= 0; i-- {
		out[i] = base62[v%62]
		v /= 62
	}
	return string(out[:])
}

// format は トークン ID（pat_…）と秘密からトークンの文字列を作る。
func format(tokenID, secret string) string {
	body := Prefix + strings.TrimPrefix(tokenID, string(id.PAT)+"_") + "_" + secret
	return body + checksum(body)
}

// hashSecret は秘密の SHA-256。
func hashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Parse はトークンの形・文字の種類・検査の文字を確かめ、トークン ID（pat_…）と秘密を返す。どれかが違えば ok は false。
// DB は引かない。
func Parse(token string) (tokenID, secret string, ok bool) {
	if len(token) != TokenLength || !strings.HasPrefix(token, Prefix) {
		return "", "", false
	}
	rest := token[len(Prefix):]
	if rest[idLength] != '_' {
		return "", "", false
	}
	tokenID = string(id.PAT) + "_" + rest[:idLength]
	secret = rest[idLength+1 : idLength+1+secretLength]
	sum := rest[idLength+1+secretLength:]
	if !canonicalID(rest[:idLength]) || !id.Valid(id.PAT, tokenID) || !isBase62(secret) || !isBase62(sum) {
		return "", "", false
	}
	if checksum(token[:len(token)-checksumLength]) != sum {
		return "", "", false
	}
	return tokenID, secret, true
}

// canonicalID は ID の部分が id の出す形（大文字の Crockford Base32）だけでできているか（読み替えの効く別の綴りを拒む）。
func canonicalID(s string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(crockford, rune(s[i])) {
			return false
		}
	}
	return true
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}
