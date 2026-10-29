package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// リポジトリの imports.go は全部入りの構成から作ったもの（`iam build -all -print > imports.go`）。
func TestImportsMatchAll(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"build", "-all", "-print"}, &out, &out); err != nil {
		t.Fatal(err)
	}
	have, err := os.ReadFile("imports.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, out.Bytes()) {
		t.Fatalf("imports.go is stale; run `go run . build -all -print > imports.go`:\n%s", out.String())
	}
}

func TestBuildPrintRejectsInvalidSpec(t *testing.T) {
	p := filepath.Join(t.TempDir(), "build.yaml")
	if err := os.WriteFile(p, []byte("features: [quota]\nadapters: {storage: [sqlite]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run(context.Background(), []string{"build", "-f", p, "-print"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "quota requires org") || !strings.Contains(err.Error(), "adapters.notifier") {
		t.Fatalf("err = %v", err)
	}
}

// features plan は、台帳にあるフィーチャーを外すバイナリを止め、disable の後は通す。
func TestFeaturesPlanAndDisable(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.json")
	var out bytes.Buffer
	ctx := context.Background()
	if err := run(ctx, []string{"keys", "generate", "-out", keys}, &out, &out); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "iam.yaml")
	cfg := fmt.Sprintf(`dev: true
features: [org, warnings, password]
storage: {driver: sqlite, path: %q}
ephemeral: {driver: memory}
keystore: {driver: file, path: %q}
event_sink: {driver: stdout}
notifier: {driver: dev}
`, filepath.Join(dir, "iam.db"), keys)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// 空の DB で起動すると、設定で有効なものが台帳で active になる。
	if err := run(ctx, []string{"features", "enable", "-config", cfgPath, "password"}, &out, &out); err != nil {
		t.Fatalf("enable: %v\n%s", err, out.String())
	}
	spec := filepath.Join(dir, "build.yaml")
	if err := os.WriteFile(spec, []byte("features: [org, warnings]\nadapters: {storage: [sqlite], ephemeral: [memory], keystore: [file], event_sink: [stdout], notifier: [dev]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err := run(ctx, []string{"features", "plan", "-config", cfgPath, "-build", spec}, &out, &out)
	if err == nil || !strings.Contains(out.String(), "BLOCKER: password is active in the ledger") || !strings.Contains(out.String(), "is enabled in config but not in the new binary") {
		t.Fatalf("plan before disable: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run(ctx, []string{"features", "disable", "-config", cfgPath, "password"}, &out, &out); err != nil {
		t.Fatalf("disable: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "password is disabled") {
		t.Fatalf("disable output: %s", out.String())
	}
	cfg = strings.Replace(cfg, "features: [org, warnings, password]", "features: [org, warnings]", 1)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(ctx, []string{"features", "plan", "-config", cfgPath, "-build", spec}, &out, &out); err != nil || !strings.Contains(out.String(), "ok: the new binary can start") {
		t.Fatalf("plan after disable: %v\n%s", err, out.String())
	}
}
