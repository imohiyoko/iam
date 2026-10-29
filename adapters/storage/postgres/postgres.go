// Package postgres は PostgreSQL の Storage アダプタ（pgx の database/sql ドライバを使う。design.md 2.4、ADR 0067）。
//
// 複数のインスタンスから同じ DB を使える。Storage ポートの約束（書き込みを含むトランザクションは直列化される。ADR 0042）は、
// すべてのトランザクションの始めにトランザクション単位の advisory lock を取って満たす。SQL と Repository の実装は SQLite の
// アダプタから cmd/pgport で作る（スキーマと時刻の表し方も SQLite と同じ）。マイグレーションは goose で管理する。
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql のドライバ "pgx"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/imohiyoko/iam/adapters/storage/postgres/db"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

//go:embed migrations/*.sql
var migrations embed.FS

func init() {
	plugin.RegisterStorage("postgres", func(ctx context.Context, cfg plugin.Config) (port.Storage, error) {
		if err := cfg.CheckOptions("dsn", "auto_migrate", "max_open_conns"); err != nil {
			return nil, err
		}
		dsn := cfg.Option("dsn", "")
		if dsn == "" {
			return nil, errors.New("storage postgres: dsn is required")
		}
		maxOpen, err := strconv.Atoi(cfg.Option("max_open_conns", defaultMaxOpenConns))
		if err != nil || maxOpen < 0 {
			return nil, fmt.Errorf("storage postgres: max_open_conns must be a non-negative integer: %q", cfg.Option("max_open_conns", ""))
		}
		return Open(ctx, dsn, Options{AutoMigrate: cfg.Option("auto_migrate", "true") == "true", MaxOpenConns: maxOpen})
	})
}

// timeFormat は固定長の RFC 3339（UTC、ナノ秒）。文字列の順（COLLATE "C"）が時刻の順になる。SQLite と同じ。
const timeFormat = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func parseTime(s string) (time.Time, error) { return time.Parse(timeFormat, s) }

// txLockKey はトランザクションを直列化する advisory lock の鍵（"iam" の ASCII）。
const txLockKey = 0x69616d

// Options は Open の追加の設定。
type Options struct {
	// AutoMigrate は起動時に未適用のマイグレーションを適用するか。false なら未適用があると Open が失敗する。
	AutoMigrate bool
	// MaxOpenConns は開いておく接続の上限（0 なら上限なし）。Tx は advisory lock で1つずつ進むので、待っている Tx が
	// 接続を持ったまま増えないよう、設定ファイルからは既定で defaultMaxOpenConns に抑える。
	MaxOpenConns int
}

// defaultMaxOpenConns は設定ファイルで max_open_conns を省いたときの接続の上限。
const defaultMaxOpenConns = "10"

// Storage は PostgreSQL の Storage。
type Storage struct {
	db *sql.DB
}

var _ port.Storage = (*Storage)(nil)

// Open は dsn（postgres://... か key=value の形）の DB を開く。
func Open(ctx context.Context, dsn string, opt Options) (*Storage, error) {
	d, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(opt.MaxOpenConns)
	if opt.MaxOpenConns > 0 {
		d.SetMaxIdleConns(opt.MaxOpenConns)
	}
	d.SetConnMaxIdleTime(5 * time.Minute)
	s := &Storage{db: d}
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, err
	}
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
		return errors.New("storage postgres: pending migrations; run `iam migrate`")
	}
	return nil
}

// Migrations は goose のプロバイダを返す（`iam migrate` 用）。複数のインスタンスが同時に起動しても、
// goose のセッションロックで1つずつ適用する。
func Migrations(d *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, d, mustSub(migrations, "migrations"), goose.WithSessionLocker(locker))
}

// Tx は fn を1つのトランザクションで実行する。始めに advisory lock を取り、ほかのトランザクションと直列にする（ADR 0042）。
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
	if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, txLockKey); err != nil {
		return mapErr(err)
	}
	return fn(ctx, &tx{q: db.New(stmtTx{t})})
}

// stmtTx は書き込みの文を SAVEPOINT で囲む。PostgreSQL では文の失敗でトランザクション全体が使えなくなるが、
// Storage ポートでは一意制約の違反（errs.Conflict）を受けてから同じトランザクションを続けてよい（SQLite と同じ）。
// RETURNING つきの書き込み（QueryContext を通る）は囲まないので、一意制約に触れうる列を書き換えないこと。
type stmtTx struct{ t *sql.Tx }

func (s stmtTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if !isWrite(q) {
		return s.t.ExecContext(ctx, q, args...)
	}
	if _, err := s.t.ExecContext(ctx, `SAVEPOINT iam_stmt`); err != nil {
		return nil, err
	}
	r, err := s.t.ExecContext(ctx, q, args...)
	if err != nil {
		if _, rerr := s.t.ExecContext(ctx, `ROLLBACK TO SAVEPOINT iam_stmt`); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
	}
	if _, rerr := s.t.ExecContext(ctx, `RELEASE SAVEPOINT iam_stmt`); rerr != nil && err == nil {
		return nil, rerr
	}
	return r, err
}

func (s stmtTx) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return s.t.PrepareContext(ctx, q)
}

func (s stmtTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.t.QueryContext(ctx, q, args...)
}

func (s stmtTx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return s.t.QueryRowContext(ctx, q, args...)
}

// isWrite は sqlc のクエリ（先頭は "-- name: ..." の行）が INSERT・UPDATE・DELETE かを返す。
func isWrite(q string) bool {
	for {
		q = strings.TrimSpace(q)
		if !strings.HasPrefix(q, "--") {
			break
		}
		_, q, _ = strings.Cut(q, "\n")
	}
	head, _, _ := strings.Cut(q, " ")
	switch strings.ToUpper(head) {
	case "INSERT", "UPDATE", "DELETE":
		return true
	}
	return false
}

func (s *Storage) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Storage) Now(ctx context.Context) (time.Time, error) {
	var v time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&v); err != nil {
		return time.Time{}, err
	}
	return v.UTC(), nil
}

func (s *Storage) Close() error { return s.db.Close() }

// mapErr は PostgreSQL のエラーを errs の分類に変える。
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errs.Wrap(errs.KindNotFound, err, "not found")
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505": // unique_violation
			return errs.Wrap(errs.KindConflict, err, "unique constraint")
		case "40001", "40P01", "55P03", "57P03", "53300": // 直列化の失敗・デッドロック・ロック待ち・起動中・接続数
			return errs.Wrap(errs.KindUnavailable, err, "database busy")
		}
	}
	return err
}

type tx struct{ q *db.Queries }

func (t *tx) Realms() port.RealmRepo       { return realms{t.q} }
func (t *tx) Features() port.FeatureLedger { return features{t.q} }
func (t *tx) DataKeys() port.DataKeyRepo   { return dataKeys{t.q} }
func (t *tx) AuditKeys() port.DataKeyRepo  { return auditKeys{t.q} }
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
func (t *tx) Orgs() port.OrgRepo                       { return orgs{t.q} }
func (t *tx) Memberships() port.MembershipRepo         { return memberships{t.q} }
func (t *tx) Invitations() port.InvitationRepo         { return invitations{t.q} }
func (t *tx) QuotaGrants() port.QuotaGrantRepo         { return quotaGrants{t.q} }
func (t *tx) OrgDomains() port.OrgDomainRepo           { return orgDomains{t.q} }
func (t *tx) ServiceAccounts() port.ServiceAccountRepo { return accounts{t.q} }
func (t *tx) RoleBindings() port.RoleBindingRepo       { return roleBindings{t.q} }
func (t *tx) Roles() port.RoleRepo                     { return roles{t.q} }
func (t *tx) Groups() port.GroupRepo                   { return groups{t.q} }
func (t *tx) Clients() port.ClientRepo                 { return clients{t.q} }
func (t *tx) SigningKeys() port.SigningKeyRepo         { return signingKeys{t.q} }
func (t *tx) Grants() port.GrantRepo                   { return grants{t.q} }
func (t *tx) OIDCTokens() port.OIDCTokenRepo           { return oidcTokens{t.q} }

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

type auditKeys struct{ q *db.Queries }

func (d auditKeys) Create(ctx context.Context, k port.DataKey) error {
	return mapErr(d.q.CreateAuditKey(ctx, db.CreateAuditKeyParams{Owner: k.UserID, WrappedKey: k.WrappedKey, KeyID: k.KeyID, CreatedAt: formatTime(k.CreatedAt)}))
}

func (d auditKeys) Get(ctx context.Context, owner string) (port.DataKey, error) {
	row, err := d.q.GetAuditKey(ctx, owner)
	if err != nil {
		return port.DataKey{}, mapErr(err)
	}
	t, err := parseTime(row.CreatedAt)
	return port.DataKey{UserID: row.Owner, WrappedKey: row.WrappedKey, KeyID: row.KeyID, CreatedAt: t}, err
}

func (d auditKeys) Delete(ctx context.Context, owner string) error {
	return mapErr(d.q.DeleteAuditKey(ctx, owner))
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

func (a auditRepo) Checkpoint(ctx context.Context) (*audit.Checkpoint, error) {
	row, err := a.q.GetAuditCheckpoint(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	t, err := parseTime(row.CreatedAt)
	return &audit.Checkpoint{Seq: row.Seq, Hash: row.Hash, At: t}, err
}

func (a auditRepo) Truncate(ctx context.Context, cp audit.Checkpoint) error {
	if err := a.q.TruncateAuditEvents(ctx, cp.Seq); err != nil {
		return mapErr(err)
	}
	return mapErr(a.q.PutAuditCheckpoint(ctx, db.PutAuditCheckpointParams{Seq: cp.Seq, Hash: cp.Hash, CreatedAt: formatTime(cp.At)}))
}

// ---------------------------------------------------------------------------

type outbox struct{ q *db.Queries }

func (o outbox) DeleteDelivered(ctx context.Context, before time.Time, limit int) (int, error) {
	n, err := o.q.DeleteDeliveredOutbox(ctx, db.DeleteDeliveredOutboxParams{Before: nullTime(&before), Lim: int64(limit)})
	return int(n), mapErr(err)
}

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
