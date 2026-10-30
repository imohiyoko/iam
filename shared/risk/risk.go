// Package risk はリスクの種類・点数・段階の境界を扱う（ADR 0084）。authn（セッションに保存する点数）と authz（条件の評価）の
// 両方が使うので shared に置く。
//
// 点数は 0〜100 の整数で、高いほど危うい。尺度をそろえるのは評価器の責任で、IAM は変換しない。
package risk

import (
	"maps"
	"regexp"
	"slices"

	"github.com/imohiyoko/iam/shared/port"
)

// 組み込みの種類。realm の一覧に既定で載り（有効）、止められる。
const (
	TypeIP      = "ip"
	TypeDevice  = "device"
	TypeAccount = "account"
)

// Builtin は組み込みの種類。
var Builtin = []string{TypeIP, TypeDevice, TypeAccount}

// MinScore・MaxScore は点数の範囲（両端を含む）。
const (
	MinScore = 0
	MaxScore = 100
)

// realm で足す種類は `<名前空間>.<名前>`。各部が [a-z0-9_]{1,32}。
var nameRE = regexp.MustCompile(`^[a-z0-9_]{1,32}\.[a-z0-9_]{1,32}$`)

// ValidName は種類の名前の形が正しいか（組み込みか `<名前空間>.<名前>`）を返す。
func ValidName(name string) bool {
	return slices.Contains(Builtin, name) || nameRE.MatchString(name)
}

// ValidScore は点数が範囲内かを返す。
func ValidScore(v int) bool { return v >= MinScore && v <= MaxScore }

// Band は種類の段階の境界。点数が Medium 未満なら low、High 未満なら medium、それ以上なら high。
type Band struct {
	Medium int `json:"medium"`
	High   int `json:"high"`
}

// DefaultBand は既定の境界（low < 30 ≦ medium < 70 ≦ high。design.md 2.8）。
var DefaultBand = Band{Medium: 30, High: 70}

// Valid は 1 ≦ Medium < High ≦ 100 かを返す。
func (b Band) Valid() bool { return b.Medium >= 1 && b.Medium < b.High && b.High <= MaxScore }

// Stricter は b が base 以上に厳しい（どちらの境界も低いか同じ）かを返す。名前空間の境界は realm の境界を厳しくする方向だけ
// 変えられる。
func (b Band) Stricter(base Band) bool { return b.Medium <= base.Medium && b.High <= base.High }

// Setting は realm の一覧の1つの種類。
type Setting struct {
	Enabled bool
	Band    Band
	// Builtin は組み込みの種類か。
	Builtin bool
}

// Catalog は realm の種類の一覧（名前 → 設定）。組み込みの種類は行が無くても有効で載る。
type Catalog map[string]Setting

// CatalogOf は保存した行から一覧を作る。
func CatalogOf(rows []port.RiskType) Catalog {
	c := Catalog{}
	for _, n := range Builtin {
		c[n] = Setting{Enabled: true, Band: DefaultBand, Builtin: true}
	}
	for _, r := range rows {
		c[r.Name] = Setting{Enabled: r.Enabled, Band: Band{Medium: r.BandMedium, High: r.BandHigh}, Builtin: slices.Contains(Builtin, r.Name)}
	}
	return c
}

// Enabled は種類が一覧で有効かを返す。
func (c Catalog) Enabled(name string) bool { return c[name].Enabled }

// Bands は有効な種類の境界。
func (c Catalog) Bands() map[string]Band {
	out := make(map[string]Band, len(c))
	for n, s := range c {
		if s.Enabled {
			out[n] = s.Band
		}
	}
	return out
}

// Names は種類の名前を整列して返す。
func (c Catalog) Names() []string { return slices.Sorted(maps.Keys(c)) }

// Keep は scores から、一覧で有効で範囲内の点数だけを残す。捨てた種類の名前を整列して返す。
func (c Catalog) Keep(scores map[string]int) (map[string]int, []string) {
	var kept map[string]int
	var dropped []string
	for n, v := range scores {
		if !c.Enabled(n) || !ValidScore(v) {
			dropped = append(dropped, n)
			continue
		}
		if kept == nil {
			kept = map[string]int{}
		}
		kept[n] = v
	}
	slices.Sort(dropped)
	return kept, dropped
}
