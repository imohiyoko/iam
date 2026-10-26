package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/imohiyoko/iam/shared/id"
)

// 00003 は既存のメールと外部 ID の紐付けに、id パッケージの形の外部 ID を入れる。
// 無効化した紐付けと同じ外部 ID を、新しい行として紐付け直せる。
func TestMigrationAddsPublicIDs(t *testing.T) {
	ctx := context.Background()
	d, err := sql.Open("sqlite", DSN(filepath.Join(t.TempDir(), "iam.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := Migrations(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO authn_user_emails (id, realm_id, user_id, ciphertext, email_index, domain_index, index_key_id, verified_via, is_primary, created_at)
		 VALUES ('eml_a', 'r', 'u', x'00', x'01', x'02', 'ik', 'code', 1, 't'), ('eml_b', 'r', 'u', x'00', x'03', x'02', 'ik', 'code', 0, 't')`,
		`INSERT INTO authn_user_identities (id, realm_id, user_id, connection_id, provider_subject, created_at, revoked_at)
		 VALUES ('idn_a', 'r', 'u', 'c', 's', 't', 't')`,
	} {
		if _, err := d.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, q := range []struct {
		table  string
		prefix id.Prefix
	}{{"authn_user_emails", id.Email}, {"authn_user_identities", id.Identity}} {
		rs, err := d.QueryContext(ctx, `SELECT public_id FROM `+q.table) // #nosec G202 -- テストの固定の表名
		if err != nil {
			t.Fatal(err)
		}
		for rs.Next() {
			var s string
			if err := rs.Scan(&s); err != nil {
				t.Fatal(err)
			}
			if !id.Valid(q.prefix, s) || ids[s] {
				t.Fatalf("%s: public_id %q", q.table, s)
			}
			ids[s] = true
		}
		if err := rs.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(ids) != 3 {
		t.Fatalf("public ids: %v", ids)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO authn_user_identities (id, public_id, realm_id, user_id, connection_id, provider_subject, created_at, revoke_reason)
		VALUES ('idn_b', 'idn_x', 'r', 'u', 'c', 's', 't', '')`); err != nil {
		t.Fatalf("relink after migration: %v", err)
	}
}
