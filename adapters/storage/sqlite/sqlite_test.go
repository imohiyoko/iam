package sqlite

import (
	"context"
	"path/filepath"
	"testing"

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
