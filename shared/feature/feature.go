// Package feature はフィーチャーの登録と、台帳（installed_features）との突き合わせを行う
// （design.md 11.11、11.12、ADR 0010、0011）。
//
// フィーチャーのパッケージは init で Register を呼ぶ（自己登録）。バイナリに含めるかは
// import するかで決まる（build tag は使わない）。
package feature

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/imohiyoko/iam/shared/port"
)

// 既知のフィーチャー名（design.md 11.0）。名前は台帳に残るため変えない。
const (
	Org                 = "org"
	Warnings            = "warnings"
	ResourceScopedAuthz = "resource_scoped_authz"
	Password            = "password"
	Quota               = "quota"
	OrgLoginPolicy      = "org_login_policy"
	MultiRealm          = "multi_realm"
	ServiceAccounts     = "service_accounts"
	OrgManagedUsers     = "org_managed_users"
	OrgHierarchy        = "org_hierarchy"
	NestedGroups        = "nested_groups"
	AccountMerge        = "account_merge"
	CustomAttributes    = "custom_attributes"
	FlowHooks           = "flow_hooks"
)

// Feature はバイナリに含まれるフィーチャーの宣言。
type Feature struct {
	Name           string
	DataVersion    int      // データ形式のバージョン。前進のみ
	Requires       []string // 依存するフィーチャー
	DefaultEnabled bool     // 設定で指定がないときに有効にするか
}

var (
	mu       sync.Mutex
	registry = map[string]Feature{}
)

// Register はフィーチャーを登録する。フィーチャーのパッケージの init から呼ぶ。
func Register(f Feature) {
	mu.Lock()
	defer mu.Unlock()
	if f.Name == "" || f.DataVersion < 1 {
		panic("feature: invalid registration: " + f.Name)
	}
	if _, dup := registry[f.Name]; dup {
		panic("feature: duplicate registration: " + f.Name)
	}
	registry[f.Name] = f
}

// Registered はバイナリに含まれるフィーチャーを名前順に返す。
func Registered() []Feature {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Feature, 0, len(registry))
	for _, f := range registry {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ErrLedgerMismatch は台帳とバイナリの構成が合わず、起動できないことを表す。
var ErrLedgerMismatch = errors.New("feature: ledger does not match binary")

// CheckBuild はバイナリの構成そのものの整合（依存の欠落）を確かめる。
func CheckBuild(binary []Feature) error {
	have := map[string]bool{}
	for _, f := range binary {
		have[f.Name] = true
	}
	var problems []string
	for _, f := range binary {
		for _, r := range f.Requires {
			if !have[r] {
				problems = append(problems, fmt.Sprintf("%s requires %s, which is not in the binary", f.Name, r))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("feature: invalid build: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Plan は起動時の判定の結果。
type Plan struct {
	// Active は実際に動かすフィーチャー（含まれる・設定で有効・台帳で active が揃ったもの）。
	Active []string
	// Warnings は起動は続けるが知らせるべきこと（設定で有効だが台帳で未有効化など）。
	Warnings []string
}

// IsActive は name が動いているかを返す。
func (p Plan) IsActive(name string) bool { return slices.Contains(p.Active, name) }

// Resolve は台帳・バイナリ・設定を突き合わせる（design.md 11.12 の表）。
//
//	台帳に記録あり・バイナリに無い            → 拒否
//	台帳に記録なし・バイナリに有る            → 起動（無効のまま）
//	active だがデータ形式が古い / 新しすぎる → 拒否
//
// enabled は設定で有効にしたフィーチャー名。nil なら各フィーチャーの DefaultEnabled に従う。
func Resolve(ledger []port.FeatureRecord, binary []Feature, enabled []string) (Plan, error) {
	if err := CheckBuild(binary); err != nil {
		return Plan{}, err
	}
	bin := map[string]Feature{}
	for _, f := range binary {
		bin[f.Name] = f
	}
	led := map[string]port.FeatureRecord{}
	var problems []string
	for _, r := range ledger {
		led[r.Feature] = r
		f, ok := bin[r.Feature]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is recorded in the ledger (%s) but not included in this binary", r.Feature, r.State))
			continue
		}
		if r.State == port.FeatureActive && r.DataVersion != f.DataVersion {
			problems = append(problems, fmt.Sprintf("%s data version %d does not match binary (%d)", r.Feature, r.DataVersion, f.DataVersion))
		}
		if r.State != port.FeatureActive && r.State != port.FeatureEnabling && r.State != port.FeatureDisabling {
			// 未知の状態は扱えない（fail-closed）。
			problems = append(problems, fmt.Sprintf("%s has unknown ledger state %q", r.Feature, r.State))
		}
	}
	if len(problems) > 0 {
		return Plan{}, fmt.Errorf("%w: %s", ErrLedgerMismatch, strings.Join(problems, "; "))
	}

	want := map[string]bool{}
	if enabled == nil {
		for _, f := range binary {
			want[f.Name] = f.DefaultEnabled
		}
	} else {
		for _, n := range enabled {
			if _, ok := bin[n]; !ok {
				return Plan{}, fmt.Errorf("feature: %s is enabled in config but not included in this binary", n)
			}
			want[n] = true
		}
	}

	plan := Plan{Active: []string{}}
	for _, f := range binary {
		r, recorded := led[f.Name]
		switch {
		case want[f.Name] && recorded && r.State == port.FeatureActive:
			plan.Active = append(plan.Active, f.Name)
		case want[f.Name]:
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s is enabled in config but not active in the ledger; run `iam features enable %s`", f.Name, f.Name))
		case recorded && r.State == port.FeatureActive:
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s is active in the ledger but disabled in config; it will not run", f.Name))
		}
	}
	// 依存先が動いていないものは動かさない。
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(plan.Active); i++ {
			f := bin[plan.Active[i]]
			for _, r := range f.Requires {
				if !plan.IsActive(r) {
					plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s requires %s, which is not active; it will not run", f.Name, r))
					plan.Active = slices.Delete(plan.Active, i, i+1)
					i--
					changed = true
					break
				}
			}
		}
	}
	return plan, nil
}
