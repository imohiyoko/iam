package password

import (
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/imohiyoko/iam/shared/errs"
)

// 長さの規則（design.md 4.1、NIST SP 800-63B）。文字種の組み合わせは強制しない。
const (
	// MinLength は既定の最低長。MinLengthWithSecondFactor は2段階認証が必須のときの最低長。
	MinLength                 = 15
	MinLengthWithSecondFactor = 8
	// MaxLength は長さの上限（ハッシュの計算を際限なく重くしないため）。64 文字以上は受け入れる（NIST）。
	MaxLength = 128
)

var (
	// ErrTooShort・ErrTooLong・ErrBreached は登録・変更で拒否した理由。本人に返す。
	ErrTooShort = errs.WithCode(errs.KindInvalid, "password_too_short", "password is too short")
	ErrTooLong  = errs.WithCode(errs.KindInvalid, "password_too_long", "password is too long")
	ErrBreached = errs.WithCode(errs.KindInvalid, "password_breached", "password appears in a data breach")
)

// Normalize は Unicode の正規化（NFKC）をする。見た目が同じ入力を同じパスワードとして扱う。
func Normalize(s string) string { return norm.NFKC.String(s) }

// checkLength は正規化したパスワードの長さ（文字数）を確かめる。
func checkLength(normalized string, min int) error {
	n := utf8.RuneCountInString(normalized)
	switch {
	case n < min:
		return ErrTooShort
	case n > MaxLength:
		return ErrTooLong
	}
	return nil
}
