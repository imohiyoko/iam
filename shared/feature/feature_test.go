package feature

import (
	"errors"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/shared/port"
)

var (
	orgF   = Feature{Name: Org, DataVersion: 1, DefaultEnabled: true}
	quotaF = Feature{Name: Quota, DataVersion: 2, Requires: []string{Org}}
)

func active(name string, v int) port.FeatureRecord {
	return port.FeatureRecord{Feature: name, State: port.FeatureActive, DataVersion: v}
}

// 台帳にあるがバイナリに無いフィーチャーのデータがあると、起動を拒否する（roadmap M0 の完了条件）。
func TestRejectLedgerFeatureMissingFromBinary(t *testing.T) {
	for _, st := range []port.FeatureState{port.FeatureActive, port.FeatureEnabling, port.FeatureDisabling} {
		ledger := []port.FeatureRecord{{Feature: Quota, State: st, DataVersion: 2}}
		_, err := Resolve(ledger, []Feature{orgF}, nil)
		if !errors.Is(err, ErrLedgerMismatch) {
			t.Errorf("state %s: want ErrLedgerMismatch, got %v", st, err)
		}
	}
}

func TestRejectDataVersionMismatch(t *testing.T) {
	for _, v := range []int{1, 3} {
		_, err := Resolve([]port.FeatureRecord{active(Org, 1), active(Quota, v)}, []Feature{orgF, quotaF}, nil)
		if !errors.Is(err, ErrLedgerMismatch) {
			t.Errorf("version %d: want ErrLedgerMismatch, got %v", v, err)
		}
	}
}

func TestRejectUnknownState(t *testing.T) {
	_, err := Resolve([]port.FeatureRecord{{Feature: Org, State: "weird", DataVersion: 1}}, []Feature{orgF}, nil)
	if !errors.Is(err, ErrLedgerMismatch) {
		t.Fatalf("want ErrLedgerMismatch, got %v", err)
	}
}

func TestInBinaryNotInLedgerStartsDisabled(t *testing.T) {
	p, err := Resolve(nil, []Feature{orgF, quotaF}, []string{Org})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Active) != 0 {
		t.Fatalf("Active = %v, want none", p.Active)
	}
	if len(p.Warnings) != 1 {
		t.Fatalf("Warnings = %v", p.Warnings)
	}
}

func TestActiveRequiresAllThree(t *testing.T) {
	ledger := []port.FeatureRecord{active(Org, 1), active(Quota, 2)}
	p, err := Resolve(ledger, []Feature{orgF, quotaF}, []string{Org, Quota})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsActive(Org) || !p.IsActive(Quota) {
		t.Fatalf("Active = %v", p.Active)
	}
	// 設定で無効なら動かさない。
	p, _ = Resolve(ledger, []Feature{orgF, quotaF}, []string{Org})
	if p.IsActive(Quota) {
		t.Fatal("quota should not run when disabled in config")
	}
	// 依存先が動いていなければ動かさない。
	p, _ = Resolve(ledger, []Feature{orgF, quotaF}, []string{Quota})
	if p.IsActive(Quota) {
		t.Fatal("quota should not run without org")
	}
}

func TestDefaultEnabled(t *testing.T) {
	p, err := Resolve([]port.FeatureRecord{active(Org, 1)}, []Feature{orgF}, nil)
	if err != nil || !p.IsActive(Org) {
		t.Fatalf("p = %+v, err = %v", p, err)
	}
}

func TestConfigNamesUnknownFeature(t *testing.T) {
	if _, err := Resolve(nil, []Feature{orgF}, []string{Quota}); err == nil {
		t.Fatal("want error")
	}
}

func TestCheckBuildMissingDependency(t *testing.T) {
	if err := CheckBuild([]Feature{quotaF}); err == nil {
		t.Fatal("want error")
	}
}

func TestPlanChange(t *testing.T) {
	org := Feature{Name: "org", DataVersion: 1, DefaultEnabled: true}
	quota := Feature{Name: "quota", DataVersion: 1, Requires: []string{"org"}}
	pw := Feature{Name: "password", DataVersion: 1}
	pw2 := Feature{Name: "password", DataVersion: 2}
	active := func(n string, v int) port.FeatureRecord {
		return port.FeatureRecord{Feature: n, State: port.FeatureActive, DataVersion: v}
	}
	// 台帳にあるものを外すバイナリは配れない。
	c := PlanChange([]port.FeatureRecord{active("org", 1), active("password", 1)}, []Feature{org, pw}, []Feature{org}, nil)
	if len(c.Removed) != 1 || c.Removed[0] != "password" || len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "iam features disable password") {
		t.Fatalf("remove active = %+v", c)
	}
	// 足すだけなら配ってよく、設定で有効なら enable を促す。
	c = PlanChange([]port.FeatureRecord{active("org", 1)}, []Feature{org}, []Feature{org, quota}, []string{"org", "quota"})
	if len(c.Added) != 1 || len(c.Problems) != 0 || len(c.Steps) != 1 || !strings.Contains(c.Steps[0], "iam features enable quota") {
		t.Fatalf("add = %+v", c)
	}
	// 依存の欠けたバイナリ、設定にあってバイナリに無いもの。
	c = PlanChange(nil, []Feature{org}, []Feature{quota}, []string{"org"})
	if len(c.Problems) != 2 {
		t.Fatalf("broken = %+v", c)
	}
	// データ形式：新しすぎるバイナリは無いが、台帳より新しい形式は移行が要る。古いバイナリは拒否される。
	c = PlanChange([]port.FeatureRecord{active("password", 1)}, []Feature{pw}, []Feature{pw2}, []string{"password"})
	if len(c.Problems) != 0 || len(c.Steps) != 1 {
		t.Fatalf("newer data version = %+v", c)
	}
	c = PlanChange([]port.FeatureRecord{active("password", 2)}, []Feature{pw2}, []Feature{pw}, []string{"password"})
	if len(c.Problems) != 1 {
		t.Fatalf("older binary = %+v", c)
	}
}
