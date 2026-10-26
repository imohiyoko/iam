// Package sqlite は SQLite の Storage アダプタ（cgo 不要の modernc.org/sqlite を使う。design.md 2.4）。
//
// 単一インスタンス向け。書き込みを含むトランザクションは BEGIN IMMEDIATE で直列化するため、
// 「件数の確認と追加」を同じトランザクションで行っても上限を超えない（ADR 0042）。
// SQL は sqlc で、マイグレーションは goose で管理する（ADR 0039）。
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"net/url"
	"time"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

//go:embed migrations/*.sql
var migrations embed.FS

func init() {
	plugin.RegisterStorage("sqlite", func(ctx context.Context, cfg plugin.Config) (port.Storage, error) {
		if err := cfg.CheckOptions("path", "auto_migrate"); err != nil {
			return nil, err
		}
		path := cfg.Option("path", "")
		if path == "" {
			return nil, errors.New("storage sqlite: path is required")
		}
		return Open(ctx, path, Options{AutoMigrate: cfg.Option("auto_migrate", "true") == "true"})
	})
}

// timeFormat は固定長の RFC 3339（UTC、ナノ秒）。文字列の順が時刻の順になる。
const timeFormat = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func parseTime(s string) (time.Time, error) { return time.Parse(timeFormat, s) }

// Options は Open の追加の設定。
type Options struct {
	// AutoMigrate は起動時に未適用のマイグレーションを適用するか。false なら未適用があると Open が失敗する。
	AutoMigrate bool
}

// Storage は SQLite の Storage。
type Storage struct {
	db *sql.DB
}

var _ port.Storage = (*Storage)(nil)

// DSN は path に推奨の設定を付けた接続文字列を返す。
func DSN(path string) string {
	q := url.Values{}
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	// 監査ログは外部に chain.seq を出した後で失われてはいけないので、コミットごとに fsync する。
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	// 削除したデータ（データ鍵など）の内容を空き領域に残さない（crypto-shredding。design.md 9.5）。
	q.Add("_pragma", "secure_delete(ON)")
	q.Set("_time_format", "sqlite")
	return "file:" + path + "?" + q.Encode()
}

// Open は path の DB を開く。
func Open(ctx context.Context, path string, opt Options) (*Storage, error) {
	d, err := sql.Open("sqlite", DSN(path))
	if err != nil {
		return nil, err
	}
	s := &Storage{db: d}
	if err := s.migrate(ctx, opt.AutoMigrate); err != nil {
		_ = d.Close()
		return nil, err
	}
	return s, nil
}

// DB は内部の *sql.DB を返す（テストと CLI 用）。
func (s *Storage) DB() *sql.DB { return s.db }

func (s *Storage) migrate(ctx context.Context, apply bool) error {
	p, err := Migrations(s.db)
	if err != nil {
		return err
	}
	if apply {
		_, err := p.Up(ctx)
		return err
	}
	pending, err := p.HasPending(ctx)
	if err != nil {
		return err
	}
	if pending {
		return errors.New("storage sqlite: pending migrations; run `iam migrate`")
	}
	return nil
}

// Migrations は goose のプロバイダを返す（`iam migrate` 用）。
func Migrations(d *sql.DB) (*goose.Provider, error) {
	return goose.NewProvider(goose.DialectSQLite3, d, mustSub(migrations, "migrations"))
}

// Tx は fn を1つのトランザクションで実行する。
func (s *Storage) Tx(ctx context.Context, fn func(context.Context, port.Tx) error) (err error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = t.Rollback()
			panic(p)
		}
		if err != nil {
			_ = t.Rollback()
			return
		}
		err = mapErr(t.Commit())
	}()
	return fn(ctx, &tx{q: db.New(t)})
}

func (s *Storage) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Storage) Now(ctx context.Context) (time.Time, error) {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`).Scan(&v); err != nil {
		return time.Time{}, err
	}
	return time.Parse("2006-01-02T15:04:05.000Z", v)
}

func (s *Storage) Close() error { return s.db.Close() }

// Checkpoint は WAL の内容を本体に書き戻して WAL を空にする。
// 削除したデータが WAL のフレームに残る期間を縮めるため、データ鍵の削除などの後に呼ぶ。
func (s *Storage) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// mapErr は SQLite のエラーを errs の分類に変える。
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errs.Wrap(errs.KindNotFound, err, "not found")
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return errs.Wrap(errs.KindConflict, err, "unique constraint")
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return errs.Wrap(errs.KindUnavailable, err, "database busy")
		}
	}
	return err
}

type tx struct{ q *db.Queries }

func (t *tx) Realms() port.RealmRepo       { return realms{t.q} }
func (t *tx) Features() port.FeatureLedger { return features{t.q} }
func (t *tx) DataKeys() port.DataKeyRepo   { return dataKeys{t.q} }
func (t *tx) Audit() port.AuditRepo        { return auditRepo{t.q} }
func (t *tx) Outbox() port.OutboxRepo      { return outbox{t.q} }

func (t *tx) Users() port.UserRepo                     { return users{t.q} }
func (t *tx) Emails() port.EmailRepo                   { return emails{t.q} }
func (t *tx) Identities() port.IdentityRepo            { return identities{t.q} }
func (t *tx) Passkeys() port.PasskeyRepo               { return passkeys{t.q} }
func (t *tx) TOTP() port.TOTPRepo                      { return totps{t.q} }
func (t *tx) Passwords() port.PasswordRepo             { return passwords{t.q} }
func (t *tx) RecoveryCodes() port.RecoveryCodeRepo     { return recoveryCodes{t.q} }
func (t *tx) Suspensions() port.SuspensionRepo         { return suspensions{t.q} }
func (t *tx) ScheduledEvents() port.ScheduledEventRepo { return scheduledEvents{t.q} }
func (t *tx) Connections() port.ConnectionRepo         { return connections{t.q} }
func (t *tx) Sessions() port.SessionRepo               { return sessions{t.q} }
func (t *tx) ServiceAccounts() port.ServiceAccountRepo { return accounts{t.q} }
func (t *tx) RoleBindings() port.RoleBindingRepo       { return roleBindings{t.q} }

// ---------------------------------------------------------------------------

type realms struct{ q *db.Queries }

func (r realms) Create(ctx context.Context, v port.Realm) error {
	return mapErr(r.q.CreateRealm(ctx, db.CreateRealmParams{ID: v.ID, Slug: v.Slug, Settings: nonNil(v.Settings), CreatedAt: formatTime(v.CreatedAt)}))
}

func (r realms) Get(ctx context.Context, id string) (port.Realm, error) {
	row, err := r.q.GetRealm(ctx, id)
	if err != nil {
		return port.Realm{}, mapErr(err)
	}
	return toRealm(row)
}

func (r realms) GetBySlug(ctx context.Context, slug string) (port.Realm, error) {
	row, err := r.q.GetRealmBySlug(ctx, slug)
	if err != nil {
		return port.Realm{}, mapErr(err)
	}
	return toRealm(row)
}

func (r realms) List(ctx context.Context) ([]port.Realm, error) {
	rows, err := r.q.ListRealms(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]port.Realm, 0, len(rows))
	for _, row := range rows {
		v, err := toRealm(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func toRealm(row db.AuthnRealm) (port.Realm, error) {
	t, err := parseTime(row.CreatedAt)
	return port.Realm{ID: row.ID, Slug: row.Slug, Settings: row.Settings, CreatedAt: t}, err
}

// ---------------------------------------------------------------------------

type features struct{ q *db.Queries }

func (f features) List(ctx context.Context) ([]port.FeatureRecord, error) {
	rows, err := f.q.ListFeatures(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]port.FeatureRecord, 0, len(rows))
	for _, row := range rows {
		t, err := parseTime(row.UpdatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, port.FeatureRecord{Feature: row.Feature, State: port.FeatureState(row.State), DataVersion: int(row.DataVersion), UpdatedAt: t})
	}
	return out, nil
}

func (f features) Put(ctx context.Context, r port.FeatureRecord) error {
	return mapErr(f.q.PutFeature(ctx, db.PutFeatureParams{Feature: r.Feature, State: string(r.State), DataVersion: int64(r.DataVersion), UpdatedAt: formatTime(r.UpdatedAt)}))
}

func (f features) Delete(ctx context.Context, name string) error {
	return mapErr(f.q.DeleteFeature(ctx, name))
}

// ---------------------------------------------------------------------------

type dataKeys struct{ q *db.Queries }

func (d dataKeys) Create(ctx context.Context, k port.DataKey) error {
	return mapErr(d.q.CreateDataKey(ctx, db.CreateDataKeyParams{UserID: k.UserID, WrappedKey: k.WrappedKey, KeyID: k.KeyID, CreatedAt: formatTime(k.CreatedAt)}))
}

func (d dataKeys) Get(ctx context.Context, userID string) (port.DataKey, error) {
	row, err := d.q.GetDataKey(ctx, userID)
	if err != nil {
		return port.DataKey{}, mapErr(err)
	}
	t, err := parseTime(row.CreatedAt)
	return port.DataKey{UserID: row.UserID, WrappedKey: row.WrappedKey, KeyID: row.KeyID, CreatedAt: t}, err
}

func (d dataKeys) Delete(ctx context.Context, userID string) error {
	return mapErr(d.q.DeleteDataKey(ctx, userID))
}

// ---------------------------------------------------------------------------

type auditRepo struct{ q *db.Queries }

func (a auditRepo) Last(ctx context.Context) (*audit.Record, error) {
	row, err := a.q.LastAuditEvent(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return &audit.Record{Seq: row.Seq, RealmID: row.RealmID, PrevHash: row.PrevHash, Hash: row.Hash, Payload: row.Payload}, nil
}

func (a auditRepo) Append(ctx context.Context, r audit.Record) error {
	return mapErr(a.q.AppendAuditEvent(ctx, db.AppendAuditEventParams{Seq: r.Seq, RealmID: r.RealmID, PrevHash: r.PrevHash, Hash: r.Hash, Payload: r.Payload}))
}

func (a auditRepo) Scan(ctx context.Context, fromSeq int64, limit int) ([]audit.Record, error) {
	rows, err := a.q.ScanAuditEvents(ctx, db.ScanAuditEventsParams{Seq: fromSeq, Limit: int64(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]audit.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.Record{Seq: r.Seq, RealmID: r.RealmID, PrevHash: r.PrevHash, Hash: r.Hash, Payload: r.Payload})
	}
	return out, nil
}

func (a auditRepo) ListByRealm(ctx context.Context, realmID string, fromSeq int64, limit int) ([]audit.Record, error) {
	rows, err := a.q.ListAuditEventsByRealm(ctx, db.ListAuditEventsByRealmParams{RealmID: realmID, Seq: fromSeq, Limit: int64(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]audit.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.Record{Seq: r.Seq, RealmID: r.RealmID, PrevHash: r.PrevHash, Hash: r.Hash, Payload: r.Payload})
	}
	return out, nil
}

// ---------------------------------------------------------------------------

type outbox struct{ q *db.Queries }

func (o outbox) Add(ctx context.Context, m port.OutboxMessage) error {
	return mapErr(o.q.AddOutbox(ctx, db.AddOutboxParams{ID: m.ID, Topic: m.Topic, Payload: nonNil(m.Payload), CreatedAt: formatTime(m.CreatedAt)}))
}

func (o outbox) Pending(ctx context.Context, topic string, limit int) ([]port.OutboxMessage, error) {
	rows, err := o.q.PendingOutbox(ctx, db.PendingOutboxParams{Topic: topic, Limit: int64(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]port.OutboxMessage, 0, len(rows))
	for _, r := range rows {
		t, err := parseTime(r.CreatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, port.OutboxMessage{ID: r.ID, Topic: r.Topic, Payload: r.Payload, CreatedAt: t})
	}
	return out, nil
}

func (o outbox) MarkDelivered(ctx context.Context, ids []string, at time.Time) error {
	ts := sql.NullString{String: formatTime(at), Valid: true}
	for _, id := range ids {
		if err := o.q.MarkOutboxDelivered(ctx, db.MarkOutboxDeliveredParams{DeliveredAt: ts, ID: id}); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
