package check

import (
	"strings"
	"time"
)

// 認証の文脈（ADR 0084）。authz は authn を import しないので、server がセッションやトークンから組み立てて渡す。

// AuthContext は判定の主体がどう認証したか（経路・強さ・経過時間）と、どれだけ危ういか（リスク）。
type AuthContext struct {
	// AMR は使った認証手段（RFC 8176 の pwd・otp・hwk など。外部 IdP は fed、信じる上流の手段は fed:<手段>）。
	AMR []string
	// Factors は要素の数（Factors で数える。サービスアカウントは 1）。
	Factors int
	// AuthTime は認証の時刻。
	AuthTime time.Time
	// Risk はリスクの種類ごとの点数（0〜100、高いほど危うい）。評価していない種類は無い。
	Risk map[string]int
	// Attested は文脈を IAM が確かめたか（セッションやトークンから組み立てたなら真、連携先の申告なら偽）。
	Attested bool
}

// 要素の分類（RFC 8176 の knowledge・possession・inherence）。
const (
	factorKnowledge = iota + 1
	factorPossession
	factorInherence
)

// factorClass は手段の分類。知らない手段は 0（数えない）。
var factorClass = map[string]int{
	"pwd": factorKnowledge, "pin": factorKnowledge, "kba": factorKnowledge,
	"otp": factorPossession, "hwk": factorPossession, "swk": factorPossession, "sms": factorPossession,
	"tel": factorPossession, "sc": factorPossession, "pop": factorPossession,
	// user は認証器の本人確認（UV。PIN か生体）。IAM は hwk と合わせて2要素とする。
	"user": factorInherence, "fpt": factorInherence, "face": factorInherence, "iris": factorInherence,
	"retina": factorInherence, "vbm": factorInherence,
}

// FedPrefix は信じる上流の手段の接頭辞（fed:hwk など）。
const FedPrefix = "fed:"

// Factors は amr から要素の数を数える。使った手段が属する分類の数。fed は（分類を数えずに）1 とし、fed:<手段> はその手段の
// 分類として数える（fed の 1 と重ねない）。fed:<手段> は、上流を信じる接続のときだけ amr に入っている前提。mfa があれば
// 少なくとも 2。
func Factors(amr []string) int {
	classes := map[int]bool{}
	fed, fedClass, mfa := false, false, false
	for _, m := range amr {
		switch {
		case m == "fed":
			fed = true
		case m == "mfa":
			mfa = true
		case strings.HasPrefix(m, FedPrefix):
			if c := factorClass[strings.TrimPrefix(m, FedPrefix)]; c != 0 {
				classes[c], fedClass = true, true
			}
		default:
			if c := factorClass[m]; c != 0 {
				classes[c] = true
			}
		}
	}
	n := len(classes)
	if fed && !fedClass {
		n++
	}
	if mfa {
		n = max(n, 2)
	}
	return n
}
