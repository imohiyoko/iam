package role_test

import (
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
