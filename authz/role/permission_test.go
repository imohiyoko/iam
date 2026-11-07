package role_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
)

// 組み込みのロールの権限はすべて IAM 自身の権限でなければならない。そうでないと、管理の操作の「渡すには自分が持って
// いなければならない」の確認から外れ、roles:manage だけの主体が、持たない権限を独自のロールで自分に渡せる。
func TestBuiltinPermissionsAreIAM(t *testing.T) {
	for _, b := range role.Builtins() {
		for _, p := range b.Permissions {
			if !role.IAM(p) {
				t.Errorf("%s: permission %q is not role.IAM", b.Name, p)
			}
			if b.Scope != role.ScopeOrg && p != role.PermNotificationsClaim && !role.RealmOnly(p) {
				t.Errorf("%s: permission %q is not role.RealmOnly", b.Name, p)
			}
		}
	}
}

func TestIAMAdminResources(t *testing.T) {
	for _, p := range []string{
		role.PermRealmsManage, role.PermServiceAccountsManage, role.PermAuditRead, role.PermAuditReadClientData,
		role.PermEventSubscriptionsManage, role.PermSSFManage,
	} {
		if !role.IAM(p) || !role.RealmOnly(p) {
			t.Errorf("%q: IAM=%v RealmOnly=%v, want both true", p, role.IAM(p), role.RealmOnly(p))
		}
	}
	if role.IAM("project:read") {
		t.Error(`IAM("project:read") = true`)
	}
}

// role.go・org.go の Perm で始まる定数（IAM 自身の権限）は、すべて role.IAM で真でなければならない。どの組み込みのロールにも
// 入れずに新しい権限を足すと、ここで落ちる（その権限は連携先の権限と見なされ、持たなくても独自のロールで渡せてしまう）。
func TestPermConstantsAreIAM(t *testing.T) {
	fset := token.NewFileSet()
	n := 0
	for _, file := range []string{"role.go", "org.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, sp := range g.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Perm") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					p, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					n++
					if !role.IAM(p) {
						t.Errorf("%s (%s) = %q is not role.IAM: add it to a builtin role", file, name.Name, p)
					}
				}
			}
		}
	}
	if n < 50 {
		t.Fatalf("found only %d Perm constants; the parser no longer sees them", n)
	}
}
