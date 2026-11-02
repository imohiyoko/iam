// Package acr は認証の強さ（NIST SP 800-63B の AAL）と、それを外に出す acr の値を扱う（ADR 0093）。
// authn（ID トークン・ログインポリシー）と authz（条件の評価）の両方が使うので shared に置く。
//
// AAL はセッションの amr（RFC 8176）から求める。対応表 Methods は amr の値ごとに引ける形にしてあり、
// 認証方式が自分の強さを宣言する形（ADR 0090）になれば、方式の宣言で置き換える。
package acr

import (
	"slices"
	"strings"

	"github.com/imohiyoko/iam/shared/feature"
)

// Feature はフィーチャー acr の宣言（features/acr が登録する）。
var Feature = feature.Feature{Name: feature.ACR, DataVersion: 1}

// Class は要素の分類（RFC 8176 の knowledge・possession・inherence）と、分類の分からない外部 ID。
type Class int

// 要素の分類。
const (
	Knowledge Class = iota + 1
	Possession
	Inherence
	// Federated は外部 IdP での認証（amr の fed）。上流の手段が分からないので、どの分類とも別の 1 要素として数える。
	Federated
)

// Method は amr の1つの値が AAL にどう効くか。
type Method struct {
	Class Class
	// PhishingResistant は検証者のなりすましに強い（SP 800-63B の verifier impersonation resistance。WebAuthn など）。
	PhishingResistant bool
	// HardwareBound は鍵が取り出せないハードウェアの中にあることを確かめた。AAL3 と phrh に要る。
	HardwareBound bool
}

// Methods は amr の値ごとの対応表。載っていない値（mfa・link・rec・kba・サービスアカウントの手段など）は AAL に数えない。
//
//   - hwk（passkey）は IAM が attestation を確かめず、同期する passkey と区別できないので HardwareBound にしない
//   - otp はメールのコードにも使っている。SP 800-63B はメールを認証器と認めないが、amr では区別できないので
//     TOTP と同じに扱う（方式の宣言に置き換えるときに分ける。ADR 0093）
//   - user・生体は、所持の要素と一緒のときだけ数える（SP 800-63B 5.2.3）
//   - kba は SP 800-63B が認めないので数えない
var Methods = map[string]Method{
	"pwd": {Class: Knowledge}, "pin": {Class: Knowledge},
	"otp": {Class: Possession}, "sms": {Class: Possession}, "tel": {Class: Possession},
	"hwk": {Class: Possession, PhishingResistant: true}, "swk": {Class: Possession}, "sc": {Class: Possession}, "pop": {Class: Possession},
	"user": {Class: Inherence}, "fpt": {Class: Inherence}, "face": {Class: Inherence}, "iris": {Class: Inherence},
	"retina": {Class: Inherence}, "vbm": {Class: Inherence},
	"fed": {Class: Federated},
}

// FedPrefix は信じる上流の手段の接頭辞（fed:otp など。ADR 0084）。上流の手段は分類としてだけ数え、
// 検証者のなりすましへの強さとハードウェアは数えない（IAM が確かめていない）。
const FedPrefix = "fed:"

// MaxAAL は AAL の上限。
const MaxAAL = 3

// strength は amr から求めた強さ。
type strength struct {
	classes           map[Class]bool
	phishingResistant bool
	hardwareBound     bool
}

func measure(amr []string) strength {
	s := strength{classes: map[Class]bool{}}
	fed, fedClass := false, false
	for _, a := range amr {
		if up, ok := strings.CutPrefix(a, FedPrefix); ok {
			if m, ok := Methods[up]; ok && m.Class != Federated {
				s.classes[m.Class], fedClass = true, true
			}
			continue
		}
		m, ok := Methods[a]
		if !ok {
			continue
		}
		if m.Class == Federated {
			fed = true
			continue
		}
		s.classes[m.Class] = true
		if m.PhishingResistant {
			s.phishingResistant = true
			if m.HardwareBound {
				s.hardwareBound = true
			}
		}
	}
	if fed && !fedClass {
		s.classes[Federated] = true
	}
	if s.classes[Inherence] && !s.classes[Possession] {
		delete(s.classes, Inherence)
	}
	return s
}

// AAL は amr から AAL（0〜3）を求める。0 は AAL1 にも届かない（数える手段が無い）。
//
//	AAL1：数える手段が1つ以上
//	AAL2：分類の違う2要素以上で、うち1つが所持
//	AAL3：AAL2 で、検証者のなりすましに強くハードウェアに鍵がある手段を IAM で使った
func AAL(amr []string) int {
	s := measure(amr)
	switch {
	case len(s.classes) == 0:
		return 0
	case len(s.classes) < 2 || !s.classes[Possession]:
		return 1
	case s.hardwareBound:
		return 3
	}
	return 2
}

// acr の値（ADR 0093）。SP 800-63 の AAL には IANA に登録された値が無いので IAM の URN を使い、検証者のなりすましへの
// 強さは IANA に登録された phr・phrh（OpenID Connect Extended Authentication Profile の ACR Values）を使う。
const (
	AAL1 = "urn:iam:aal1"
	AAL2 = "urn:iam:aal2"
	AAL3 = "urn:iam:aal3"
	// PHR は検証者のなりすましに強い手段で認証した。
	PHR = "phr"
	// PHRH は PHR で、鍵がハードウェアにある。
	PHRH = "phrh"
	// Zero は AAL1 にも届かない認証（OpenID Connect Core 2 の "0"）。返すだけで、要求には使えない。
	Zero = "0"
)

// Level は AAL n の acr の値。範囲の外なら Zero。
func Level(n int) string {
	switch n {
	case 1:
		return AAL1
	case 2:
		return AAL2
	case 3:
		return AAL3
	}
	return Zero
}

// LevelOf は acr の値の AAL（AAL の値でなければ 0）。
func LevelOf(v string) int {
	switch v {
	case AAL1:
		return 1
	case AAL2:
		return 2
	case AAL3:
		return 3
	}
	return 0
}

// Satisfies は amr の認証が acr の値 v を満たすかを返す。知らない値は満たさない。
func Satisfies(v string, amr []string) bool {
	if n := LevelOf(v); n > 0 {
		return AAL(amr) >= n
	}
	s := measure(amr)
	switch v {
	case PHR:
		return s.phishingResistant
	case PHRH:
		return s.hardwareBound
	}
	return false
}

// Supported は対応表で届く acr の値（Discovery の acr_values_supported）。届かない値（今は AAL3・phrh）は載せない。
func Supported() []string {
	pr, hw := false, false
	for _, m := range Methods {
		pr = pr || m.PhishingResistant
		hw = hw || (m.PhishingResistant && m.HardwareBound)
	}
	out := []string{AAL1, AAL2}
	if hw {
		out = append(out, AAL3)
	}
	if pr {
		out = append(out, PHR)
	}
	if hw {
		out = append(out, PHRH)
	}
	return out
}

// Requested は要求された acr の値から、対応するもの（Supported）を要求の順に、重複を除いて返す。知らない値は捨てる
// （acr_values は任意の要求。OpenID Connect Core 3.1.2.1）。
func Requested(values []string) []string {
	sup := Supported()
	var out []string
	for _, v := range values {
		if slices.Contains(sup, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Select は amr の認証が満たす値を、要求 requested の順で最初のものを返す。requested が空なら AAL の値（Level）。
// 要求があってどれも満たさなければ ok は false。
func Select(requested, amr []string) (v string, ok bool) {
	if len(requested) == 0 {
		return Level(AAL(amr)), true
	}
	for _, r := range requested {
		if Satisfies(r, amr) {
			return r, true
		}
	}
	return "", false
}
