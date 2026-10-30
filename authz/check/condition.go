package check

import (
	"fmt"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/risk"
)

// 条件の言語（ADR 0084）。付与の条件・名前空間の要件・Org の要件に書く。任意のスクリプトは入れず、型付きの木で保存する。
//
//	condition := all(条件...) | any(条件...)
//	           | amr_has(<手段>...) | factors_at_least(<n>) | auth_within(<秒>)
//	           | risk_below(<種類>, <点数>) | risk_at_most(<種類>, low|medium|high) | attested()

// Condition は条件の木の1つの節。ちょうど1つの項目を持つ。
type Condition struct {
	All            []Condition `json:"all,omitempty"`
	Any            []Condition `json:"any,omitempty"`
	AMRHas         []string    `json:"amr_has,omitempty"`
	FactorsAtLeast int         `json:"factors_at_least,omitempty"`
	// AuthWithin は認証からの経過の上限（秒）。
	AuthWithin int        `json:"auth_within,omitempty"`
	RiskBelow  *RiskScore `json:"risk_below,omitempty"`
	RiskAtMost *RiskLevel `json:"risk_at_most,omitempty"`
	Attested   bool       `json:"attested,omitempty"`
}

// RiskScore は risk_below の引数。点数が Score 未満なら満たす。
type RiskScore struct {
	Type  string `json:"type"`
	Score int    `json:"score"`
}

// RiskLevel は risk_at_most の引数。点数を判定する範囲の境界で段階にし、Level 以下なら満たす。
type RiskLevel struct {
	Type  string `json:"type"`
	Level Level  `json:"level"`
}

// Level はリスクの段階（点数の別名）。
type Level string

const (
	LevelLow    Level = "low"
	LevelMedium Level = "medium"
	LevelHigh   Level = "high"
)

func (l Level) rank() int {
	return slices.Index([]Level{LevelLow, LevelMedium, LevelHigh}, l)
}

// levelOf は点数の段階。点数が境界の Medium 未満なら low、High 未満なら medium、それ以上なら high。
func levelOf(b risk.Band, score int) Level {
	switch {
	case score < b.Medium:
		return LevelLow
	case score < b.High:
		return LevelMedium
	}
	return LevelHigh
}

// Bands は種類ごとの段階の境界（判定する名前空間・Org で決めたもの）。無い種類は risk.DefaultBand。
type Bands map[string]risk.Band

func (b Bands) of(typ string) risk.Band {
	if v, ok := b[typ]; ok {
		return v
	}
	return risk.DefaultBand
}

// 条件の大きさと値の範囲。
const (
	MaxConditionDepth  = 4
	MaxConditionLeaves = 16
	MaxAuthWithin      = 86400
	MaxFactors         = 3
)

// 満たさなかった条件の理由のコード（Decision.Unmet）。
const (
	UnmetAMR      = "condition.amr"
	UnmetFactors  = "condition.factors"
	UnmetAuthAge  = "condition.auth_age"
	UnmetAttested = "condition.attested"
	// UnmetRiskPrefix の後ろにリスクの種類が付く（condition.risk.account など）。
	UnmetRiskPrefix = "condition.risk."
)

// Validate は条件を保存の前に確かめる（深さ・葉の数・値の範囲・リスクの種類）。riskType はリスクの種類が realm の一覧で
// 有効かを返す。外れていれば errs.KindInvalid（コード invalid_condition）。
func (c Condition) Validate(riskType func(string) bool) error {
	leaves := 0
	if err := c.validate(1, &leaves, riskType); err != nil {
		return errs.WithCode(errs.KindInvalid, "invalid_condition", err.Error())
	}
	return nil
}

func (c Condition) validate(depth int, leaves *int, riskType func(string) bool) error {
	if depth > MaxConditionDepth {
		return fmt.Errorf("condition deeper than %d", MaxConditionDepth)
	}
	set := 0
	for _, b := range []bool{c.All != nil, c.Any != nil, c.AMRHas != nil, c.FactorsAtLeast != 0, c.AuthWithin != 0,
		c.RiskBelow != nil, c.RiskAtMost != nil, c.Attested} {
		if b {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("a condition node must have exactly one item, has %d", set)
	}
	switch {
	case c.All != nil || c.Any != nil:
		children := slices.Concat(c.All, c.Any)
		if len(children) == 0 {
			return fmt.Errorf("all/any needs at least one condition")
		}
		for _, ch := range children {
			if err := ch.validate(depth+1, leaves, riskType); err != nil {
				return err
			}
		}
		return nil
	}
	if *leaves++; *leaves > MaxConditionLeaves {
		return fmt.Errorf("condition has more than %d leaves", MaxConditionLeaves)
	}
	switch {
	case c.AMRHas != nil:
		if len(c.AMRHas) == 0 || slices.Contains(c.AMRHas, "") {
			return fmt.Errorf("amr_has needs at least one method")
		}
	case c.FactorsAtLeast != 0:
		if c.FactorsAtLeast < 1 || c.FactorsAtLeast > MaxFactors {
			return fmt.Errorf("factors_at_least must be within [1, %d]", MaxFactors)
		}
	case c.AuthWithin != 0:
		if c.AuthWithin < 1 || c.AuthWithin > MaxAuthWithin {
			return fmt.Errorf("auth_within must be within [1, %d] seconds", MaxAuthWithin)
		}
	case c.RiskBelow != nil:
		if c.RiskBelow.Score < 1 || c.RiskBelow.Score > 100 {
			return fmt.Errorf("risk_below score must be within [1, 100]")
		}
		if riskType == nil || !riskType(c.RiskBelow.Type) {
			return fmt.Errorf("unknown or disabled risk type %q", c.RiskBelow.Type)
		}
	case c.RiskAtMost != nil:
		if c.RiskAtMost.Level.rank() < 0 {
			return fmt.Errorf("risk_at_most level must be low, medium or high")
		}
		if riskType == nil || !riskType(c.RiskAtMost.Type) {
			return fmt.Errorf("unknown or disabled risk type %q", c.RiskAtMost.Type)
		}
	}
	return nil
}

// RiskTypes は条件が見るリスクの種類（重複なし、順は木の順）。種類を止める前の確認に使う。
func (c Condition) RiskTypes() []string {
	var out []string
	var walk func(Condition)
	walk = func(c Condition) {
		for _, ch := range slices.Concat(c.All, c.Any) {
			walk(ch)
		}
		for _, t := range []string{riskTypeOf(c.RiskBelow), riskTypeOfLevel(c.RiskAtMost)} {
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	walk(c)
	return out
}

func riskTypeOf(r *RiskScore) string {
	if r == nil {
		return ""
	}
	return r.Type
}

func riskTypeOfLevel(r *RiskLevel) string {
	if r == nil {
		return ""
	}
	return r.Type
}

// Eval は条件を文脈と突き合わせる。満たさなければ、満たさなかった条件の理由のコード（重複なし、整列）を返す。
// 文脈が無ければ（nil）何も満たさない（fail-closed）。評価していないリスクの種類は満たさない。
func (c Condition) Eval(ac *AuthContext, now time.Time, bands Bands) (bool, []string) {
	ok, unmet := c.eval(ac, now, bands)
	if ok {
		return true, nil
	}
	slices.Sort(unmet)
	return false, slices.Compact(unmet)
}

func (c Condition) eval(ac *AuthContext, now time.Time, bands Bands) (bool, []string) {
	switch {
	case c.All != nil:
		var unmet []string
		for _, ch := range c.All {
			if ok, u := ch.eval(ac, now, bands); !ok {
				unmet = append(unmet, u...)
			}
		}
		return len(unmet) == 0, unmet
	case c.Any != nil:
		var unmet []string
		for _, ch := range c.Any {
			ok, u := ch.eval(ac, now, bands)
			if ok {
				return true, nil
			}
			unmet = append(unmet, u...)
		}
		return false, unmet
	}
	if code, ok := c.leaf(ac, now, bands); !ok {
		return false, []string{code}
	}
	return true, nil
}

// leaf は葉を評価し、満たさなければその理由のコードを返す。
func (c Condition) leaf(ac *AuthContext, now time.Time, bands Bands) (string, bool) {
	switch {
	case c.AMRHas != nil:
		return UnmetAMR, ac != nil && slices.ContainsFunc(c.AMRHas, func(m string) bool { return slices.Contains(ac.AMR, m) })
	case c.FactorsAtLeast != 0:
		return UnmetFactors, ac != nil && ac.Factors >= c.FactorsAtLeast
	case c.AuthWithin != 0:
		return UnmetAuthAge, ac != nil && !ac.AuthTime.IsZero() && !now.Before(ac.AuthTime) &&
			now.Sub(ac.AuthTime) <= time.Duration(c.AuthWithin)*time.Second
	case c.RiskBelow != nil:
		score, ok := riskOf(ac, c.RiskBelow.Type)
		return UnmetRiskPrefix + c.RiskBelow.Type, ok && score < c.RiskBelow.Score
	case c.RiskAtMost != nil:
		score, ok := riskOf(ac, c.RiskAtMost.Type)
		return UnmetRiskPrefix + c.RiskAtMost.Type, ok && levelOf(bands.of(c.RiskAtMost.Type), score).rank() <= c.RiskAtMost.Level.rank()
	case c.Attested:
		return UnmetAttested, ac != nil && ac.Attested
	}
	return "", false
}

func riskOf(ac *AuthContext, typ string) (int, bool) {
	if ac == nil {
		return 0, false
	}
	score, ok := ac.Risk[typ]
	return score, ok
}

// EvalRequirement は名前空間の要件と Org の要件を評価する。attested() を暗黙に AND する（申告の文脈では満たさない）。
func (c Condition) EvalRequirement(ac *AuthContext, now time.Time, bands Bands) (bool, []string) {
	return Condition{All: []Condition{{Attested: true}, c}}.Eval(ac, now, bands)
}

// Decision は判定の結果。Unmet は満たさなかった条件の理由のコード（条件で拒んだときだけ）。
type Decision struct {
	Allow bool
	Unmet []string
}
