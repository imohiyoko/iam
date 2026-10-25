package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/adapters/storage/storagetest"
)

// スパイク（ADR 0042）：SQLite で「件数の確認と追加」を同じトランザクションで並行に行っても上限を超えないか。
//
// Quota（design.md 11.14）の判定と同じ形の処理を、専用の表で並行に実行する。
func TestSpikeCountThenInsertUnderConcurrency(t *testing.T) {
	const limit, workers = 5, 64

	run := func(t *testing.T, dsn string) (inserted int, busy int) {
		d, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if _, err := d.Exec(`CREATE TABLE members (org_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (org_id, user_id))`); err != nil {
			t.Fatal(err)
		}
		results := storagetest.Concurrent(workers, func(i int) error {
			tx, err := d.BeginTx(context.Background(), nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM members WHERE org_id = 'org'`).Scan(&n); err != nil {
				return err
			}
			if n+1 > limit {
				return errQuota
			}
			if _, err := tx.Exec(`INSERT INTO members VALUES ('org', ?)`, fmt.Sprint(i)); err != nil {
				return err
			}
			return tx.Commit()
		})
		for _, err := range results {
			switch {
			case err == nil:
			case errors.Is(err, errQuota):
			case strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "database is locked"):
				busy++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}
		if err := d.QueryRow(`SELECT count(*) FROM members`).Scan(&inserted); err != nil {
			t.Fatal(err)
		}
		return inserted, busy
	}

	t.Run("immediate", func(t *testing.T) {
		// アダプタの既定（BEGIN IMMEDIATE + busy_timeout）。
		n, busy := run(t, DSN(filepath.Join(t.TempDir(), "q.db")))
		if n != limit {
			t.Fatalf("inserted %d, want exactly %d", n, limit)
		}
		if busy != 0 {
			t.Fatalf("%d transactions failed with SQLITE_BUSY", busy)
		}
	})

	t.Run("deferred", func(t *testing.T) {
		// 比較：BEGIN DEFERRED では上限は超えないが、読み取りから書き込みへの昇格で
		// SQLITE_BUSY が起き、呼び出し側の再試行が必要になる。
		dsn := strings.Replace(DSN(filepath.Join(t.TempDir(), "q.db")), "_txlock=immediate", "_txlock=deferred", 1)
		n, busy := run(t, dsn)
		if n > limit {
			t.Fatalf("inserted %d, exceeds limit %d", n, limit)
		}
		t.Logf("deferred: inserted=%d busy=%d", n, busy)
	})
}

var errQuota = errors.New("quota exceeded")
