package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

// storageCmd は `iam storage export / import`（design.md 2.4、ADR 0068）。SQLite から PostgreSQL への移行などに使う。
// 書き出したファイルは暗号化した個人情報とハッシュを含む。KeyStore の鍵は含まないので、移行先でも同じ鍵を使う。
func storageCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	const use = "usage: iam storage export -config iam.yaml -out dump.jsonl | iam storage import -config iam.yaml -in dump.jsonl"
	if len(args) == 0 || (args[0] != "export" && args[0] != "import") {
		return errors.New(use)
	}
	fs := flag.NewFlagSet("storage "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "書き出すファイル（export。既にあれば失敗する）")
	in := fs.String("in", "", "読み込むファイル（import）")
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	sf, err := plugin.Storage(cfg.Storage.Driver)
	if err != nil {
		return err
	}
	opts := map[string]string{}
	for k, v := range cfg.Storage.Options {
		opts[k] = v
	}
	if args[0] == "import" {
		// 読み込み先はマイグレーション済みにしておく。
		opts["auto_migrate"] = "true"
	}
	s, err := sf(ctx, plugin.Config{Clock: clock.System{}, Options: opts, Dev: cfg.Dev})
	if err != nil {
		return err
	}
	defer s.Close()
	d, ok := s.(port.Dumper)
	if !ok {
		return fmt.Errorf("storage %s does not support export / import", cfg.Storage.Driver)
	}
	var stats map[string]int
	switch args[0] {
	case "export":
		if *out == "" {
			return errors.New("-out is required")
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 G703 -- 運営者が指定するファイル
		if err != nil {
			return err
		}
		if stats, err = d.Export(ctx, f); err != nil {
			_ = f.Close()
			_ = os.Remove(*out) // #nosec G703 -- 今作ったファイル
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	case "import":
		if *in == "" {
			return errors.New("-in is required")
		}
		f, err := os.Open(*in) // #nosec G304 G703 -- 運営者が指定するファイル
		if err != nil {
			return err
		}
		defer f.Close()
		if stats, err = d.Import(ctx, f); err != nil {
			return err
		}
		// 監査ログのチェーンが移行先でもつながっていることを確かめる。
		_, n, err := eventlog.Verify(ctx, s)
		if err != nil {
			return fmt.Errorf("imported, but the audit chain does not verify: %w", err)
		}
		fmt.Fprintf(stdout, "audit chain verified (through seq %d)\n", n)
	}
	names := make([]string, 0, len(stats))
	total := 0
	for n, c := range stats {
		names = append(names, n)
		total += c
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(stdout, "%-40s %d\n", n, stats[n])
	}
	fmt.Fprintf(stdout, "%sed %d rows\n", args[0], total)
	return nil
}
