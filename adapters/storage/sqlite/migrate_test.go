package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
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

// 00044 は既存の監査ログの索引を、audit.IndexOf と同じ規則で埋め戻す（ADR 0100）。
func TestMigrationBackfillsAuditIndex(t *testing.T) {
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
	if _, err := p.UpTo(ctx, 33); err != nil {
		t.Fatal(err)
	}
	events := []audit.Event{
		{ID: "evt_1", Time: time.Date(2026, 10, 1, 1, 2, 3, 999999999, time.UTC), Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: "r",
			Actor: audit.Actor{Type: "user", ID: "usr_a"}, OrgID: "org_1", Details: map[string]any{"user_id": "usr_b", "membership_id": "mbr_1",
				"count_id": 3, "reason": "x", "empty_id": "", "_id": "z"}},
		{ID: "evt_2", Time: time.Date(2026, 10, 1, 1, 2, 4, 0, time.UTC), Type: "system.started", RealmID: "r", Actor: audit.Actor{Type: "system"}},
		{ID: "evt_3", Time: time.Date(2026, 10, 1, 1, 2, 5, 500000000, time.UTC), Type: "x", RealmID: "r", Details: map[string]any{"list_id": []string{"a"}}},
	}
	var last *audit.Record
	var recs []audit.Record
	for _, e := range events {
		r, err := audit.Next(last, e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.ExecContext(ctx, `INSERT INTO shared_audit_events (seq, realm_id, prev_hash, hash, payload) VALUES (?, ?, ?, ?, ?)`,
			r.Seq, r.RealmID, r.PrevHash, r.Hash, r.Payload); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		last = &r
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		want, err := audit.IndexOf(r.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var got audit.Index
		if err := d.QueryRowContext(ctx, `SELECT event_id, occurred_unix, event_type, result, actor_type, actor_id, org_id FROM shared_audit_events WHERE seq = ?`,
			r.Seq).Scan(&got.EventID, &got.Unix, &got.Type, &got.Result, &got.ActorType, &got.ActorID, &got.OrgID); err != nil {
			t.Fatal(err)
		}
		rs, err := d.QueryContext(ctx, `SELECT ref_id FROM shared_audit_refs WHERE realm_id = 'r' AND seq = ? ORDER BY ref_id`, r.Seq)
		if err != nil {
			t.Fatal(err)
		}
		for rs.Next() {
			var s string
			if err := rs.Scan(&s); err != nil {
				t.Fatal(err)
			}
			got.Refs = append(got.Refs, s)
		}
		if err := rs.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("seq %d: backfilled %+v, want %+v", r.Seq, got, want)
		}
	}
}
