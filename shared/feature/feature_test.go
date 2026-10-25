package feature

import (
	"errors"
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
