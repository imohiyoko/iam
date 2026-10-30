package check_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/errs"
)

func TestFactors(t *testing.T) {
	for _, c := range []struct {
		amr  []string
		want int
	}{
		{nil, 0},
		{[]string{"pwd"}, 1},
		{[]string{"pwd", "otp"}, 2},
		{[]string{"hwk"}, 1},
		{[]string{"hwk", "user"}, 2},
		{[]string{"otp", "otp"}, 1},
		{[]string{"fed"}, 1},
		{[]string{"fed", "fed:pwd", "fed:otp"}, 2},
		{[]string{"fed", "fed:pwd"}, 1},
		{[]string{"fed", "fed:unknown"}, 1},
		{[]string{"fed", "otp"}, 2},
		{[]string{"pwd", "mfa"}, 2},
		{[]string{"sak"}, 0},
	} {
		if got := check.Factors(c.amr); got != c.want {
			t.Errorf("Factors(%v) = %d, want %d", c.amr, got, c.want)
		}
	}
}

func parse(t *testing.T, s string) check.Condition {
	t.Helper()
	var c check.Condition
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConditionValidate(t *testing.T) {
	known := func(typ string) bool { return typ == "account" || typ == "ip" }
	ok := []string{
		`{"amr_has":["hwk"]}`,
		`{"all":[{"factors_at_least":2},{"auth_within":300},{"risk_below":{"type":"account","score":30}}]}`,
		`{"any":[{"risk_at_most":{"type":"ip","level":"medium"}},{"attested":true}]}`,
		`{"all":[{"any":[{"all":[{"amr_has":["otp"]}]}]}]}`,
	}
	for _, s := range ok {
		if err := parse(t, s).Validate(known); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	sixteen := `{"all":[` + strings16(`{"attested":true}`) + `]}`
	bad := []string{
		`{}`,
		`{"amr_has":["hwk"],"attested":true}`,
		`{"all":[]}`,
		`{"amr_has":[]}`,
		`{"amr_has":[""]}`,
		`{"factors_at_least":4}`,
		`{"factors_at_least":-1}`,
		`{"auth_within":86401}`,
		`{"risk_below":{"type":"account","score":0}}`,
		`{"risk_below":{"type":"account","score":101}}`,
		`{"risk_below":{"type":"device","score":30}}`,
		`{"risk_at_most":{"type":"ip","level":"severe"}}`,
		`{"all":[{"all":[{"all":[{"all":[{"attested":true}]}]}]}]}`,
		`{"all":[` + strings16(`{"attested":true}`) + `,{"attested":true}]}`,
	}
	if err := parse(t, sixteen).Validate(known); err != nil {
		t.Errorf("16 leaves: %v", err)
	}
	for _, s := range bad {
		if err := parse(t, s).Validate(known); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: want invalid, got %v", s, err)
		}
	}
}

func strings16(leaf string) string {
	s := leaf
	for range 15 {
		s += "," + leaf
	}
	return s
}

func TestConditionEval(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC)
	ac := &check.AuthContext{AMR: []string{"hwk", "user"}, Factors: 2, AuthTime: now.Add(-5 * time.Minute),
		Risk: map[string]int{"account": 40, "ip": 10}, Attested: true}
	bands := check.Bands{"account": {Medium: 50, High: 80}}
	for _, c := range []struct {
		cond  string
		ac    *check.AuthContext
		ok    bool
		unmet []string
	}{
		{`{"amr_has":["pwd","hwk"]}`, ac, true, nil},
		{`{"amr_has":["otp"]}`, ac, false, []string{check.UnmetAMR}},
		{`{"factors_at_least":2}`, ac, true, nil},
		{`{"factors_at_least":3}`, ac, false, []string{check.UnmetFactors}},
		{`{"auth_within":300}`, ac, true, nil},
		{`{"auth_within":299}`, ac, false, []string{check.UnmetAuthAge}},
		{`{"risk_below":{"type":"account","score":41}}`, ac, true, nil},
		{`{"risk_below":{"type":"account","score":40}}`, ac, false, []string{"condition.risk.account"}},
		// 評価していない種類は満たさない。
		{`{"risk_below":{"type":"device","score":100}}`, ac, false, []string{"condition.risk.device"}},
		// account の境界は realm・名前空間で厳しくなっている（50 から medium）ので 40 は low。ip は既定（30）で 10 は low。
		{`{"risk_at_most":{"type":"account","level":"low"}}`, ac, true, nil},
		{`{"risk_at_most":{"type":"ip","level":"low"}}`, ac, true, nil},
		{`{"all":[{"amr_has":["otp"]},{"factors_at_least":3},{"amr_has":["pwd"]}]}`, ac, false, []string{check.UnmetAMR, check.UnmetFactors}},
		{`{"any":[{"amr_has":["otp"]},{"factors_at_least":2}]}`, ac, true, nil},
		{`{"any":[{"amr_has":["otp"]},{"factors_at_least":3}]}`, ac, false, []string{check.UnmetAMR, check.UnmetFactors}},
		{`{"attested":true}`, &check.AuthContext{}, false, []string{check.UnmetAttested}},
		// 子の無い all・any と、空の条件は満たさない（検査を通らない条件でも fail-closed）。
		{`{"all":[]}`, ac, false, nil},
		{`{"any":[]}`, ac, false, nil},
		{`{}`, ac, false, nil},
		// 文脈が無ければ何も満たさない。
		{`{"auth_within":86400}`, nil, false, []string{check.UnmetAuthAge}},
		{`{"risk_below":{"type":"ip","score":100}}`, nil, false, []string{"condition.risk.ip"}},
	} {
		ok, unmet := parse(t, c.cond).Eval(c.ac, now, bands)
		if ok != c.ok || !slices.Equal(unmet, c.unmet) {
			t.Errorf("%s: %v %v, want %v %v", c.cond, ok, unmet, c.ok, c.unmet)
		}
	}
	// account が 40 は既定の境界なら medium。
	if ok, _ := parse(t, `{"risk_at_most":{"type":"account","level":"low"}}`).Eval(ac, now, nil); ok {
		t.Error("default band: 40 should be medium")
	}
	// 要件は attested() を暗黙に求める。
	declared := *ac
	declared.Attested = false
	if ok, unmet := parse(t, `{"amr_has":["hwk"]}`).EvalRequirement(&declared, now, bands); ok || !slices.Equal(unmet, []string{check.UnmetAttested}) {
		t.Errorf("requirement with a declared context: %v %v", ok, unmet)
	}
	if ok, _ := parse(t, `{"amr_has":["hwk"]}`).EvalRequirement(ac, now, bands); !ok {
		t.Error("requirement with an attested context")
	}
}

func TestConditionRiskTypes(t *testing.T) {
	c := parse(t, `{"all":[{"risk_below":{"type":"account","score":30}},{"any":[{"risk_at_most":{"type":"ip","level":"low"}},{"risk_below":{"type":"account","score":10}}]}]}`)
	if got := c.RiskTypes(); !slices.Equal(got, []string{"account", "ip"}) {
		t.Fatalf("RiskTypes = %v", got)
	}
}
