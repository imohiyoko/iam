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
	CodePasswordBreached     = "password_breached"
	// CodeRecoveredViaEmail はメールによるアカウントの復旧（4.12）。deny にすればメールでは復旧できない。
	CodeRecoveredViaEmail = "recovered_via_email"
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
	// PasswordBreached はログインに使ったパスワードが漏洩済みか。パスワード以外か、確かめられなければ nil。
	PasswordBreached *bool
	// RecoveredViaEmail はメールでアカウントを復旧したか（復旧専用のセッションの発行のとき）。
	RecoveredViaEmail bool
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
	{Code: CodePasswordBreached, Severity: High, Default: Warn, Check: passwordBreached},
	{Code: CodeRecoveredViaEmail, Severity: Medium, Default: Warn, Check: recoveredViaEmail},
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

func passwordBreached(ev Evidence) (map[string]any, bool) {
	return nil, ev.PasswordBreached != nil && *ev.PasswordBreached
}

func recoveredViaEmail(ev Evidence) (map[string]any, bool) { return nil, ev.RecoveredViaEmail }

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
	return e.Apply(e.Hits(ev), nil)
}

// Hits は該当した警告をすべて（ignore のものも）、realm の段のアクションをつけて返す。
// セッションに残し、Org の段で厳しくしたアクションを後から当てはめる（Apply。2.8、10章）。
func (e *Evaluator) Hits(ev Evidence) []Warning {
	if e == nil {
		return nil
	}
	var out []Warning
	for _, r := range e.rules {
		params, hit := r.Check(ev)
		if !hit {
			continue
		}
		out = append(out, Warning{Code: r.Code, Severity: r.Severity, Action: e.action(r), Params: params})
	}
	return out
}

func (e *Evaluator) action(r Rule) Action {
	if a, ok := e.actions[r.Code]; ok {
		return a
	}
	return r.Default
}

// Action は realm の段の code のアクションを返す。未知のコードは ignore。
func (e *Evaluator) Action(code string) Action {
	if e == nil {
		return Ignore
	}
	for _, r := range e.rules {
		if r.Code == code {
			return e.action(r)
		}
	}
	return Ignore
}

// Apply は該当した警告（Hits）に、realm の段のアクションと、org（Org の段。厳しくする向きだけ効く）を当てはめ、
// ignore でないものを返す。deny が1つでもあれば *DeniedError も返す。e が nil なら何もしない。
func (e *Evaluator) Apply(hits []Warning, org map[string]Action) ([]Warning, error) {
	if e == nil {
		return nil, nil
	}
	var out []Warning
	var denied []string
	for _, w := range hits {
		a := e.Action(w.Code)
		if o, ok := org[w.Code]; ok && Stricter(o, a) {
			a = o
		}
		switch a {
		case Ignore:
			continue
		case Deny:
			denied = append(denied, w.Code)
		}
		w.Action = a
		out = append(out, w)
	}
	if len(denied) > 0 {
		return out, &DeniedError{Codes: denied}
	}
	return out, nil
}

// Stricter は a が b より厳しいか（ignore < warn < deny）。
func Stricter(a, b Action) bool { return rank(a) > rank(b) }

func rank(a Action) int {
	switch a {
	case Warn:
		return 1
	case Deny:
		return 2
	}
	return 0
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
