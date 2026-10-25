// Package archtest はモジュール境界の違反を検出する（design.md 2.2、ADR 0001、0003）。
//
//   - コア（authn、authz、shared）は adapters/、server/、cmd/ を import しない
//   - authn と authz は互いを import しない（受け渡しは ID だけ）
//   - shared は authn、authz を import しない
package archtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/imohiyoko/iam/"

// rules は「from 以下のパッケージは forbidden 以下を import してはならない」。
var rules = []struct {
	from      string
	forbidden []string
}{
	{"authn", []string{"adapters", "server", "cmd", "authz"}},
	{"authz", []string{"adapters", "server", "cmd", "authn"}},
	{"shared", []string{"adapters", "server", "cmd", "authn", "authz"}},
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(b), "module github.com/imohiyoko/iam\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func under(path, dir string) bool { return path == dir || strings.HasPrefix(path, dir+"/") }

func TestModuleBoundaries(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	checked := 0
	for _, r := range rules {
		err := filepath.WalkDir(filepath.Join(root, r.from), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			checked++
			rel, _ := filepath.Rel(root, path)
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				target, ok := strings.CutPrefix(p, module)
				if !ok {
					continue
				}
				for _, bad := range r.forbidden {
					if under(target, bad) {
						t.Errorf("%s imports %s (%s/ must not import %s/)", filepath.ToSlash(rel), p, r.from, bad)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no files checked")
	}
}

// アダプタは組み立て側（server、cmd）に依存しない。
func TestAdaptersDoNotImportServer(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(root, "adapters"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if target, ok := strings.CutPrefix(p, module); ok && (under(target, "server") || under(target, "cmd")) {
				t.Errorf("%s imports %s", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
