package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type storageEnv struct {
	dir, keys string
}

func newStorageEnv(t *testing.T) *storageEnv {
	t.Helper()
	dir := t.TempDir()
	e := &storageEnv{dir: dir, keys: filepath.Join(dir, "keys.json")}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"keys", "generate", "-out", e.keys}, &out, &out); err != nil {
		t.Fatal(err)
	}
	return e
}

// config は storage の部分だけ違う設定ファイルを書く。
func (e *storageEnv) config(t *testing.T, name, storage string) string {
	t.Helper()
	p := filepath.Join(e.dir, name+".yaml")
	cfg := fmt.Sprintf(`dev: true
server: {public_url: "https://id.example.test"}
storage: %s
ephemeral: {driver: memory}
keystore: {driver: file, path: %q}
event_sink: {driver: stdout}
notifier: {driver: dev}
`, storage, e.keys)
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *storageEnv) sqlite(t *testing.T, name string) string {
	return e.config(t, name, fmt.Sprintf(`{driver: sqlite, path: %q}`, filepath.Join(e.dir, name+".db")))
}

func iam(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(context.Background(), args, &out, &out); err != nil {
		t.Fatalf("iam %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// seed はデータを作る（運営者のユーザー・メール・ロール・監査ログ・outbox）。
func seed(t *testing.T, cfg string) {
	t.Helper()
	iam(t, "migrate", "-config", cfg)
	iam(t, "operator", "create", "-config", cfg, "-email", "root@example.com")
	iam(t, "operator", "create", "-config", cfg, "-email", "admin@example.com", "-role", "realm:admin")
}

// migrateTo は from の中身を書き出して to に読み込み、to でも同じユーザーが見つかることを確かめる。
func migrateTo(t *testing.T, e *storageEnv, from, to string) {
	t.Helper()
	dump := filepath.Join(e.dir, "dump-"+filepath.Base(to)+".jsonl")
	exported := iam(t, "storage", "export", "-config", from, "-out", dump)
	if !strings.Contains(exported, "authn_users") || !strings.Contains(exported, "exported") {
		t.Fatalf("export: %s", exported)
	}
	if info, err := os.Stat(dump); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("dump file mode: %v %v", info, err)
	}
	out := iam(t, "storage", "import", "-config", to, "-in", dump)
	if !strings.Contains(out, "audit chain verified") {
		t.Fatalf("import: %s", out)
	}
	// 読み込み先から書き出し直しても、表ごとの件数が同じ。
	if again := iam(t, "storage", "export", "-config", to, "-out", filepath.Join(e.dir, "again-"+filepath.Base(to)+".jsonl")); again != exported {
		t.Fatalf("re-export differs:\n%s\nvs\n%s", exported, again)
	}
	// 読み込み先は空でなければならない。
	var buf bytes.Buffer
	if err := run(context.Background(), []string{"storage", "import", "-config", to, "-in", dump}, &buf, &buf); err == nil ||
		!strings.Contains(err.Error(), "not empty") {
		t.Fatalf("second import: %v", err)
	}
	// 移行先で、同じ鍵でメールのインデックスを引ける（既存のユーザーにロールが付く）。
	if out := iam(t, "operator", "create", "-config", to, "-email", "root@example.com", "-role", "realm:support"); !strings.Contains(out, "added role to existing user") {
		t.Fatalf("operator on migrated storage: %s", out)
	}
}

func TestStorageExportImportSQLite(t *testing.T) {
	e := newStorageEnv(t)
	from := e.sqlite(t, "from")
	seed(t, from)
	migrateTo(t, e, from, e.sqlite(t, "to"))
	var out bytes.Buffer
	if err := run(context.Background(), []string{"storage", "export", "-config", from, "-out", filepath.Join(e.dir, "dump-to.yaml.jsonl")}, &out, &out); err == nil {
		t.Fatal("export over an existing file must fail")
	}
	mem := e.config(t, "mem", `{driver: memory}`)
	if err := run(context.Background(), []string{"storage", "export", "-config", mem, "-out", filepath.Join(e.dir, "m.jsonl")}, &out, &out); err == nil ||
		!strings.Contains(err.Error(), "does not support") {
		t.Fatalf("memory export: %v", err)
	}
}

// SQLite から PostgreSQL への移行（roadmap M6 の完了条件）。IAM_TEST_POSTGRES があるときだけ動く。
func TestStorageMigrateSQLiteToPostgres(t *testing.T) {
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
	name := "iam_migrate_" + hex.EncodeToString(b)
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`) })
	u, _ := url.Parse(base)
	u.Path = "/" + name

	e := newStorageEnv(t)
	from := e.sqlite(t, "from")
	seed(t, from)
	pg := e.config(t, "pg", fmt.Sprintf(`{driver: postgres, dsn: %q}`, u.String()))
	migrateTo(t, e, from, pg)
	// PostgreSQL から SQLite にも戻せる。
	migrateTo(t, e, pg, e.sqlite(t, "back"))
}
