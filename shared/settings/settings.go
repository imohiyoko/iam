// Package settings はセキュリティ設定の階層（ホスト先 → realm → Org）を扱う（design.md 2.8、ADR 0033）。
//
// ホスト先（設定ファイル）が項目ごとに既定値と、realm・Org が設定できる範囲を決める。
// realm は範囲内で上書きし、Org も範囲内で上書きする。Org は既定では厳しくする方向にしか
// 変えられず、ホスト先が OrgMayRelax を許した項目だけ緩められる。
package settings

import (
	"cmp"
	"fmt"
	"time"
)

// Direction はどちら向きが「厳しい」か。
type Direction int

const (
	// LowerIsStricter は値が小さいほど厳しい（セッションの寿命など）。
	LowerIsStricter Direction = iota
	// HigherIsStricter は値が大きいほど厳しい（パスワードの最低長、警告のアクションなど）。
	HigherIsStricter
)

// Rule はホスト先が決める1項目の規則。
type Rule[T cmp.Ordered] struct {
	Key         string
	Default     T
	Min, Max    T // realm・Org が設定できる範囲（両端を含む）
	Direction   Direction
	OrgMayRelax bool // Org が realm の値より緩めてよいか
}

// Validate は規則そのものが矛盾していないかを確かめる（起動時に呼ぶ）。
func (r Rule[T]) Validate() error {
	if r.Min > r.Max {
		return fmt.Errorf("settings: %s: min > max", r.Key)
	}
	if r.Default < r.Min || r.Default > r.Max {
		return fmt.Errorf("settings: %s: default outside [min, max]", r.Key)
	}
	return nil
}

// stricterOrEqual は a が b と同じかより厳しいかを返す。
func (r Rule[T]) stricterOrEqual(a, b T) bool {
	if r.Direction == LowerIsStricter {
		return a <= b
	}
	return a >= b
}

// CheckRealm は realm が設定しようとする値を検査する（設定変更時）。
func (r Rule[T]) CheckRealm(v T) error {
	if v < r.Min || v > r.Max {
		return fmt.Errorf("settings: %s: %v is outside the range allowed by the host [%v, %v]", r.Key, v, r.Min, r.Max)
	}
	return nil
}

// CheckOrg は Org が設定しようとする値を、その時点の realm の値と比べて検査する。
func (r Rule[T]) CheckOrg(realmValue, v T) error {
	if err := r.CheckRealm(v); err != nil {
		return err
	}
	if !r.OrgMayRelax && !r.stricterOrEqual(v, realmValue) {
		return fmt.Errorf("settings: %s: an org may only make this stricter than the realm (%v)", r.Key, realmValue)
	}
	return nil
}

// Resolve は効く値を返す。realm、org は未設定なら nil（個人 Org は org を nil にして realm に従う）。
//
// 保存済みの値がその後のホスト先の設定変更で範囲外になった場合は、範囲に収め、
// Org が緩める方向なら realm の値に戻す（13.5：ホスト先が許した範囲を超えて緩められない）。
func (r Rule[T]) Resolve(realm, org *T) T {
	v := r.Default
	if realm != nil {
		v = clamp(*realm, r.Min, r.Max)
	}
	if org != nil {
		o := clamp(*org, r.Min, r.Max)
		if r.OrgMayRelax || r.stricterOrEqual(o, v) {
			v = o
		}
	}
	return v
}

func clamp[T cmp.Ordered](v, lo, hi T) T { return min(max(v, lo), hi) }

// Duration は時間の項目の規則。
type Duration = Rule[time.Duration]
