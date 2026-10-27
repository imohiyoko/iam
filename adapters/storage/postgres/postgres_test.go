package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/imohiyoko/iam/adapters/storage/storagetest"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// 試験は IAM_TEST_POSTGRES（postgres://... 。CREATEDB の権限）があるときだけ動く。試験ごとに DB を作って消す。
func testDSN(t testing.TB) string {
	t.Helper()
	base := os.Getenv("IAM_TEST_POSTGRES")
	if base == "" {
		t.Skip("IAM_TEST_POSTGRES is not set")
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "iam_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin, err := sql.Open("pgx", base)
		if err != nil {
			return
		}
		defer admin.Close()
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func openTemp(t testing.TB) *Storage {
	t.Helper()
	s, err := Open(context.Background(), testDSN(t), Options{AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestContract(t *testing.T) {
	storagetest.Run(t, storagetest.Harness{
		New: func(t *testing.T, _ clock.Clock) port.Storage { return openTemp(t) },
		TamperAudit: func(t *testing.T, s port.Storage, seq int64, payload []byte) {
			if _, err := s.(*Storage).DB().Exec(`UPDATE shared_audit_events SET payload = $1 WHERE seq = $2`, payload, seq); err != nil {
				t.Fatal(err)
			}
		},
	})
}

func TestPendingMigrationsRejected(t *testing.T) {
	dsn := testDSN(t)
	if _, err := Open(context.Background(), dsn, Options{AutoMigrate: false}); err == nil {
		t.Fatal("want error for pending migrations")
	}
	s, err := Open(context.Background(), dsn, Options{AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(context.Background(), dsn, Options{AutoMigrate: false})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}
