package permcatalog_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/authz/permcatalog"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func defs(names ...string) []port.PermissionDef {
	out := make([]port.PermissionDef, 0, len(names))
	for _, n := range names {
		out = append(out, port.PermissionDef{Name: n})
	}
	return out
}

func TestNormalizeAndCovers(t *testing.T) {
	c, err := permcatalog.Normalize(port.PermissionCatalog{Prefix: "docs", DisplayName: " Docs ", Permissions: defs("docs.doc:write", "docs.doc:read")})
	if err != nil {
		t.Fatal(err)
	}
	if c.DisplayName != "Docs" || !reflect.DeepEqual(c.Permissions, defs("docs.doc:read", "docs.doc:write")) {
		t.Fatalf("normalized = %+v", c)
	}
	for p, want := range map[string]bool{"docs.doc:read": true, "docs.doc:*": true, "docs.doc:delete": false, "docs.page:*": false, "docs.do:*": false} {
		if got := permcatalog.Covers(c, p); got != want {
			t.Errorf("Covers(%q) = %v, want %v", p, got, want)
		}
	}
	if got := permcatalog.Uses([]string{"docs.doc:read", "docs.doc:write", "users:read", "wiki.page:read"}, "docs",
		&port.PermissionCatalog{Prefix: "docs", Permissions: defs("docs.doc:read")}); !reflect.DeepEqual(got, []string{"docs.doc:write"}) {
		t.Errorf("Uses = %v", got)
	}
	if got := permcatalog.Uses([]string{"docs.doc:read", "users:read"}, "docs", nil); !reflect.DeepEqual(got, []string{"docs.doc:read"}) {
		t.Errorf("Uses after delete = %v", got)
	}
}

func TestRequire(t *testing.T) {
	k := testkit.New(t)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.PermissionCatalogs().Create(ctx, port.PermissionCatalog{RealmID: k.RealmID, Prefix: "docs", DisplayName: "Docs",
			Permissions: defs("docs.doc:read"), CreatedAt: k.Clock.Now(), UpdatedAt: k.Clock.Now()})
	})
	for perms, ok := range map[string]bool{"docs.doc:read": true, "docs.doc:*": true, "users:delete": true, "docs.doc:write": false, "wiki.page:read": false} {
		k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			err := permcatalog.Require(ctx, tx, k.RealmID, []string{perms})
			var e *errs.Error
			if ok != (err == nil) || (!ok && (!errors.As(err, &e) || e.Code != permcatalog.CodeUnknownPermission)) {
				t.Errorf("Require(%q) = %v", perms, err)
			}
			return nil
		})
	}
}
