// Package warning は認証の警告を評価する（design.md 10章、ADR 0007）。
//
//	認証経路 ──Evidence──▶ ルール（経路を知らない）──▶ []Warning ──▶ アクション（ignore / warn / deny）
//
// ルールは Evidence の項目だけを見る。アクションはコードごとに設定で決める（2.8 の階層。M1 はホストの段のみ）。
// フィーチャー `warnings`（既定オン。11.0）が動いていないときは評価器を通さない。
package warning

import (
	"fmt"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(feature.Feature{Name: feature.Warnings, DataVersion: 1, DefaultEnabled: true})
}

// 警告のコード（公開の契約。11.10）。
const (
	CodeSingleFactor         = "single_factor"
	CodeOAuthEmailUnverified = "oauth_email_unverified"
)

// Action は警告への対応。
type Action string

const (
	Ignore Action = "ignore" // 記録もしない
	Warn   Action = "warn"   // 記録し、本人に返す
	Deny   Action = "deny"   // 認証を拒否する（本人確認の後なので理由を返す。4.9）
)

// Severity は警告の重さ（クライアントでの表示の目安）。
type Severity string

const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Evidence は認証経路が評価器に渡す事実。ルールはこれだけを見る。
type Evidence struct {
	AMR []string // RFC 8176 の値
	// OAuthEmailVerified はプロバイダがメールを確認済みとしたか。OAuth 以外では nil。
	OAuthEmailVerified *bool
}

// Warning は評価の結果の1件。sessions.warnings と監査ログに残し、本人に返す。
type Warning struct {
	Code     string         `json:"code"`
	Severity Severity       `json:"severity"`
	Action   Action         `json:"action"`
	Params   map[string]any `json:"params,omitempty"`
}

// Rule は1つのコードの判定。
type Rule struct {
	Code     string
	Severity Severity
	Default  Action
	// Check は該当すれば true と、警告に添える値を返す。
	Check func(Evidence) (map[string]any, bool)
}

// Rules は組み込みのルール（10章の表）。
var Rules = []Rule{
	{Code: CodeSingleFactor, Severity: Low, Default: Ignore, Check: singleFactor},
	{Code: CodeOAuthEmailUnverified, Severity: Medium, Default: Warn, Check: oauthEmailUnverified},
}

// factorOf は amr の値を要素の種類に分ける（RFC 8176）。分からない値は数えない。
var factorOf = map[string]string{
	"pwd": "knowledge", "pin": "knowledge", "kba": "knowledge",
	"otp": "possession", "sms": "possession", "tel": "possession", "hwk": "possession", "swk": "possession", "sc": "possession",
	"fpt": "inherence", "face": "inherence", "iris": "inherence", "retina": "inherence", "vbm": "inherence", "user": "inherence",
	// 外部プロバイダに任せた認証は、プロバイダ側の要素数が分からないため1要素とみなす。
	"fed": "federated",
}

func singleFactor(ev Evidence) (map[string]any, bool) {
	if slices.Contains(ev.AMR, "mfa") {
		return nil, false
	}
	kinds := map[string]bool{}
	for _, m := range ev.AMR {
		if k, ok := factorOf[m]; ok {
			kinds[k] = true
		}
	}
	return nil, len(kinds) < 2
}

func oauthEmailUnverified(ev Evidence) (map[string]any, bool) {
	return nil, ev.OAuthEmailVerified != nil && !*ev.OAuthEmailVerified
}

// Evaluator はルールを評価し、アクションを決める。
type Evaluator struct {
	rules   []Rule
	actions map[string]Action
}

// New は評価器を作る。actions はコードごとのアクションで、無いコードはルールの既定に従う。
func New(actions map[string]Action) (*Evaluator, error) {
	if err := Validate(actions); err != nil {
		return nil, err
	}
	return &Evaluator{rules: Rules, actions: actions}, nil
}

// Validate は設定のアクションを確かめる。未知のコードやアクションは拒否する（書き間違いで警告が効かないのを防ぐ）。
func Validate(actions map[string]Action) error {
	var problems []string
	for code, a := range actions {
		if !slices.ContainsFunc(Rules, func(r Rule) bool { return r.Code == code }) {
			problems = append(problems, fmt.Sprintf("unknown warning code %q", code))
		}
		if a != Ignore && a != Warn && a != Deny {
			problems = append(problems, fmt.Sprintf("%s: unknown action %q (ignore, warn or deny)", code, a))
		}
	}
	slices.Sort(problems)
	if len(problems) > 0 {
		return fmt.Errorf("warnings: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Evaluate は該当した警告のうち ignore でないものを返す。deny が1つでもあれば *DeniedError も返す。
// e が nil（フィーチャーが動いていない）なら何もしない。
func (e *Evaluator) Evaluate(ev Evidence) ([]Warning, error) {
	if e == nil {
		return nil, nil
	}
	var out []Warning
	var denied []string
	for _, r := range e.rules {
		params, hit := r.Check(ev)
		if !hit {
			continue
		}
		a, ok := e.actions[r.Code]
		if !ok {
			a = r.Default
		}
		switch a {
		case Ignore:
			continue
		case Deny:
			denied = append(denied, r.Code)
		}
		out = append(out, Warning{Code: r.Code, Severity: r.Severity, Action: a, Params: params})
	}
	if len(denied) > 0 {
		return out, &DeniedError{Codes: denied}
	}
	return out, nil
}

// DeniedError は警告が deny になったことを表す。本人確認の後なので、理由のコードを本人に返す（4.9）。
type DeniedError struct {
	Codes []string
}

func (e *DeniedError) Error() string { return "warning denied: " + strings.Join(e.Codes, ",") }

// Reasons は拒否理由のコード（`warning_denied.<code>`）。
func (e *DeniedError) Reasons() []string {
	out := make([]string, len(e.Codes))
	for i, c := range e.Codes {
		out[i] = "warning_denied." + c
	}
	return out
}
