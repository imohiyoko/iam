package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/imohiyoko/iam/server/buildspec"
)

// buildCmd は build.yaml で選んだフィーチャーとアダプタだけを含むバイナリをビルドする（design.md 11.11、ADR 0073）。
// imports.go を go build の -overlay で差し替えるため、ソースは書き換えない。Go のツールチェーンとリポジトリのソースが要る。
func buildCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("f", "build.yaml", "ビルドの構成")
	all := fs.Bool("all", false, "build.yaml の代わりに全部入りの構成を使う")
	out := fs.String("o", "iam", "出力するバイナリ")
	src := fs.String("src", "", "cmd/iam のソースのディレクトリ（省略時は ./cmd/iam か .）")
	ver := fs.String("version", "", "埋め込むバージョン")
	print := fs.Bool("print", false, "ビルドせず、生成する imports.go を表示する")
	if err := fs.Parse(args); err != nil {
		return err
	}
	spec := buildspec.All()
	if !*all {
		b, err := os.ReadFile(*specPath) // #nosec G304 -- 運営者が指定するファイル
		if err != nil {
			return err
		}
		if spec, err = buildspec.Parse(b); err != nil {
			return err
		}
	}
	code, err := spec.Imports()
	if err != nil {
		return err
	}
	if *print {
		_, err := stdout.Write(code)
		return err
	}
	dir, err := sourceDir(*src)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "iam-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	gen := filepath.Join(tmp, "imports.go")
	if err := os.WriteFile(gen, code, 0o600); err != nil { // #nosec G703 -- 作ったばかりの一時ディレクトリの中
		return err
	}
	ov, err := json.Marshal(map[string]map[string]string{"Replace": {filepath.Join(dir, "imports.go"): gen}})
	if err != nil {
		return err
	}
	overlay := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(overlay, ov, 0o600); err != nil {
		return err
	}
	dst, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	goArgs := []string{"build", "-trimpath", "-overlay", overlay, "-o", dst}
	if *ver != "" {
		goArgs = append(goArgs, "-ldflags", "-X main.version="+*ver)
	}
	cmd := exec.CommandContext(ctx, "go", append(goArgs, ".")...) // #nosec G204 -- 引数は固定の形
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build: %w", err)
	}
	fmt.Fprintf(stdout, "built %s (features: %v)\n", dst, spec.Features)
	return nil
}

// sourceDir は cmd/iam のソース（imports.go と main.go がある）を探す。
func sourceDir(src string) (string, error) {
	cands := []string{src}
	if src == "" {
		cands = []string{filepath.Join("cmd", "iam"), "."}
	}
	for _, c := range cands {
		if _, err := os.Stat(filepath.Join(c, "imports.go")); err == nil {
			if _, err := os.Stat(filepath.Join(c, "main.go")); err == nil {
				return filepath.Abs(c)
			}
		}
	}
	return "", errors.New("build: cmd/iam source not found; run in the repository or pass -src")
}
