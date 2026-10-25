package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/storagetest"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

func openTemp(t testing.TB) *Storage {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "iam.db"), Options{AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestContract(t *testing.T) {
	storagetest.Run(t, storagetest.Harness{
		New: func(t *testing.T, _ clock.Clock) port.Storage { return openTemp(t) },
		TamperAudit: func(t *testing.T, s port.Storage, seq int64, payload []byte) {
			if _, err := s.(*Storage).DB().Exec(`UPDATE shared_audit_events SET payload = ? WHERE seq = ?`, payload, seq); err != nil {
				t.Fatal(err)
			}
		},
	})
}

func TestPendingMigrationsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam.db")
	if _, err := Open(context.Background(), path, Options{AutoMigrate: false}); err == nil {
		t.Fatal("want error for pending migrations")
	}
	s, err := Open(context.Background(), path, Options{AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(context.Background(), path, Options{AutoMigrate: false})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

// データ鍵を消した後、DB ファイルに鍵のバイト列が残らない（secure_delete。design.md 9.5、13.5）。
func TestDataKeyBytesNotLeftOnDisk(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "iam.db")
	s, err := Open(ctx, path, Options{AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	marker := bytes.Repeat([]byte("SHRED-ME-"), 8)
	tx := func(fn func(context.Context, port.Tx) error) {
		if err := s.Tx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	tx(func(ctx context.Context, tx port.Tx) error {
		return tx.DataKeys().Create(ctx, port.DataKey{UserID: "usr_x", WrappedKey: marker, KeyID: "k", CreatedAt: time.Now()})
	})
	if err := s.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if !fileContains(t, path, marker) {
		t.Fatal("test bug: marker not written")
	}
	tx(func(ctx context.Context, tx port.Tx) error { return tx.DataKeys().Delete(ctx, "usr_x") })
	if err := s.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal"} {
		if fileContains(t, p, marker) {
			t.Fatalf("deleted data key bytes remain in %s", filepath.Base(p))
		}
	}
}

func fileContains(t *testing.T, path string, b []byte) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Contains(data, b)
}
