// Package memory は Storage ポートのインメモリの参照実装（design.md 12章）。
//
// フィーチャーのテストはこの実装に対して行う。契約テスト（storagetest）も通す。
// トランザクションは1つのロックで直列化し、失敗時は取り消しの記録（undo log）で戻す。
package memory

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterStorage("memory", func(_ context.Context, cfg plugin.Config) (port.Storage, error) {
		// 永続化しないため、監査ログもデータ鍵も再起動で消える。本番では使わない。
		if !cfg.Dev {
			return nil, errors.New("storage memory: only available in development mode")
		}
		if err := cfg.CheckOptions(); err != nil {
			return nil, err
		}
		return New(cfg.Clock), nil
	})
}

type auditRow struct {
	rec audit.Record
}

type state struct {
	realms   map[string]port.Realm
	features map[string]port.FeatureRecord
	dataKeys map[string]port.DataKey
	audit    []auditRow
	outbox   []port.OutboxMessage
	outboxIx map[string]int

	users      map[string]port.User
	emails     map[string]port.UserEmail
	identities map[string]port.Identity
	passkeys   map[string]port.Passkey
	// revokedPasskeys は無効化した credential_id（realm と credential_id の組）。再登録を拒否する（4.6）。
	revokedPasskeys map[string]time.Time
	totps           map[string]port.TOTPCredential
	passwords       map[string]port.PasswordCredential
	recoveryCodes   map[string]port.RecoveryCode
	suspensions     map[string]port.Suspension
	scheduled       map[string]port.ScheduledEvent
	connections     map[string]port.Connection
	sessions        map[string]port.Session
	accounts        map[string]port.ServiceAccount
	credentials     map[string]port.ServiceAccountCredential
	roleBindings    map[string]port.RoleBinding
}

// Storage はインメモリの Storage。
type Storage struct {
	mu    sync.Mutex
	s     state
	clock clock.Clock
}

// New は空の Storage を返す。
func New(clk clock.Clock) *Storage {
	if clk == nil {
		clk = clock.System{}
	}
	return &Storage{clock: clk, s: state{
		realms: map[string]port.Realm{}, features: map[string]port.FeatureRecord{},
		dataKeys: map[string]port.DataKey{}, outboxIx: map[string]int{},
		users: map[string]port.User{}, emails: map[string]port.UserEmail{}, identities: map[string]port.Identity{},
		passkeys: map[string]port.Passkey{}, revokedPasskeys: map[string]time.Time{}, totps: map[string]port.TOTPCredential{},
		passwords: map[string]port.PasswordCredential{}, suspensions: map[string]port.Suspension{},
		scheduled: map[string]port.ScheduledEvent{}, recoveryCodes: map[string]port.RecoveryCode{},
		connections: map[string]port.Connection{}, sessions: map[string]port.Session{},
		accounts: map[string]port.ServiceAccount{}, credentials: map[string]port.ServiceAccountCredential{},
		roleBindings: map[string]port.RoleBinding{},
	}}
}

// Tx は fn を直列に実行する。エラーなら変更を取り消す。
func (m *Storage) Tx(ctx context.Context, fn func(context.Context, port.Tx) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &tx{s: &m.s}
	defer func() {
		if p := recover(); p != nil {
			t.rollback()
			panic(p)
		}
		if err != nil {
			t.rollback()
		}
	}()
	return fn(ctx, t)
}

func (m *Storage) Ping(ctx context.Context) error         { return ctx.Err() }
func (m *Storage) Now(context.Context) (time.Time, error) { return m.clock.Now(), nil }
func (m *Storage) Close() error                           { return nil }

type tx struct {
	s    *state
	undo []func()
}

func (t *tx) rollback() {
	for i := len(t.undo) - 1; i >= 0; i-- {
		t.undo[i]()
	}
}

func (t *tx) Realms() port.RealmRepo       { return realms{t} }
func (t *tx) Features() port.FeatureLedger { return features{t} }
func (t *tx) DataKeys() port.DataKeyRepo   { return dataKeys{t} }
func (t *tx) Audit() port.AuditRepo        { return auditRepo{t} }
func (t *tx) Outbox() port.OutboxRepo      { return outbox{t} }

func (t *tx) Users() port.UserRepo                     { return users{t} }
func (t *tx) Emails() port.EmailRepo                   { return emails{t} }
func (t *tx) Identities() port.IdentityRepo            { return identities{t} }
func (t *tx) Passkeys() port.PasskeyRepo               { return passkeys{t} }
func (t *tx) TOTP() port.TOTPRepo                      { return totps{t} }
func (t *tx) Passwords() port.PasswordRepo             { return passwords{t} }
func (t *tx) RecoveryCodes() port.RecoveryCodeRepo     { return recoveryCodes{t} }
func (t *tx) Suspensions() port.SuspensionRepo         { return suspensions{t} }
func (t *tx) ScheduledEvents() port.ScheduledEventRepo { return scheduledEvents{t} }
func (t *tx) Connections() port.ConnectionRepo         { return connections{t} }
func (t *tx) Sessions() port.SessionRepo               { return sessions{t} }
func (t *tx) ServiceAccounts() port.ServiceAccountRepo { return accounts{t} }
func (t *tx) RoleBindings() port.RoleBindingRepo       { return roleBindings{t} }

// setKey は map の値を設定し、取り消し方を記録する。
func setKey[K comparable, V any](t *tx, m map[K]V, k K, v V) {
	old, had := m[k]
	m[k] = v
	t.undo = append(t.undo, func() {
		if had {
			m[k] = old
		} else {
			delete(m, k)
		}
	})
}

func deleteKey[K comparable, V any](t *tx, m map[K]V, k K) {
	old, had := m[k]
	if !had {
		return
	}
	delete(m, k)
	t.undo = append(t.undo, func() { m[k] = old })
}

// ---------------------------------------------------------------------------

type realms struct{ t *tx }

func (r realms) Create(_ context.Context, v port.Realm) error {
	for _, x := range r.t.s.realms {
		if x.Slug == v.Slug {
			return errs.New(errs.KindConflict, "realm slug %q exists", v.Slug)
		}
	}
	if _, ok := r.t.s.realms[v.ID]; ok {
		return errs.New(errs.KindConflict, "realm %s exists", v.ID)
	}
	v.Settings = bytes.Clone(v.Settings)
	setKey(r.t, r.t.s.realms, v.ID, v)
	return nil
}

func (r realms) Get(_ context.Context, id string) (port.Realm, error) {
	v, ok := r.t.s.realms[id]
	if !ok {
		return port.Realm{}, errs.New(errs.KindNotFound, "realm %s", id)
	}
	return cloneRealm(v), nil
}

func (r realms) GetBySlug(_ context.Context, slug string) (port.Realm, error) {
	for _, v := range r.t.s.realms {
		if v.Slug == slug {
			return cloneRealm(v), nil
		}
	}
	return port.Realm{}, errs.New(errs.KindNotFound, "realm slug %q", slug)
}

func (r realms) List(context.Context) ([]port.Realm, error) {
	out := make([]port.Realm, 0, len(r.t.s.realms))
	for _, v := range r.t.s.realms {
		out = append(out, cloneRealm(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func cloneRealm(v port.Realm) port.Realm { v.Settings = bytes.Clone(v.Settings); return v }

// ---------------------------------------------------------------------------

type features struct{ t *tx }

func (f features) List(context.Context) ([]port.FeatureRecord, error) {
	out := make([]port.FeatureRecord, 0, len(f.t.s.features))
	for _, v := range f.t.s.features {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Feature < out[j].Feature })
	return out, nil
}

func (f features) Put(_ context.Context, r port.FeatureRecord) error {
	setKey(f.t, f.t.s.features, r.Feature, r)
	return nil
}

func (f features) Delete(_ context.Context, name string) error {
	deleteKey(f.t, f.t.s.features, name)
	return nil
}

// ---------------------------------------------------------------------------

type dataKeys struct{ t *tx }

func (d dataKeys) Create(_ context.Context, k port.DataKey) error {
	if _, ok := d.t.s.dataKeys[k.UserID]; ok {
		return errs.New(errs.KindConflict, "data key for %s exists", k.UserID)
	}
	k.WrappedKey = bytes.Clone(k.WrappedKey)
	setKey(d.t, d.t.s.dataKeys, k.UserID, k)
	return nil
}

func (d dataKeys) Get(_ context.Context, userID string) (port.DataKey, error) {
	k, ok := d.t.s.dataKeys[userID]
	if !ok {
		return port.DataKey{}, errs.New(errs.KindNotFound, "data key for %s", userID)
	}
	k.WrappedKey = bytes.Clone(k.WrappedKey)
	return k, nil
}

func (d dataKeys) Delete(_ context.Context, userID string) error {
	deleteKey(d.t, d.t.s.dataKeys, userID)
	return nil
}

// ---------------------------------------------------------------------------

type auditRepo struct{ t *tx }

func (a auditRepo) Last(context.Context) (*audit.Record, error) {
	if len(a.t.s.audit) == 0 {
		return nil, nil
	}
	r := cloneRecord(a.t.s.audit[len(a.t.s.audit)-1].rec)
	return &r, nil
}

func (a auditRepo) Append(_ context.Context, r audit.Record) error {
	s := a.t.s
	if r.Seq != int64(len(s.audit))+1 {
		return errs.New(errs.KindConflict, "audit seq %d: want %d", r.Seq, len(s.audit)+1)
	}
	s.audit = append(s.audit, auditRow{rec: cloneRecord(r)})
	a.t.undo = append(a.t.undo, func() { s.audit = s.audit[:len(s.audit)-1] })
	return nil
}

func (a auditRepo) Scan(_ context.Context, fromSeq int64, limit int) ([]audit.Record, error) {
	var out []audit.Record
	for i := max(fromSeq-1, 0); i < int64(len(a.t.s.audit)) && len(out) < limit; i++ {
		out = append(out, cloneRecord(a.t.s.audit[i].rec))
	}
	return out, nil
}

func (a auditRepo) ListByRealm(_ context.Context, realmID string, fromSeq int64, limit int) ([]audit.Record, error) {
	var out []audit.Record
	for i := max(fromSeq-1, 0); i < int64(len(a.t.s.audit)) && len(out) < limit; i++ {
		if row := a.t.s.audit[i]; row.rec.RealmID == realmID {
			out = append(out, cloneRecord(row.rec))
		}
	}
	return out, nil
}

func cloneRecord(r audit.Record) audit.Record {
	r.PrevHash, r.Hash, r.Payload = bytes.Clone(r.PrevHash), bytes.Clone(r.Hash), bytes.Clone(r.Payload)
	return r
}

// ---------------------------------------------------------------------------

type outbox struct{ t *tx }

func (o outbox) Add(_ context.Context, m port.OutboxMessage) error {
	s := o.t.s
	if _, ok := s.outboxIx[m.ID]; ok {
		return errs.New(errs.KindConflict, "outbox %s exists", m.ID)
	}
	m.Payload = bytes.Clone(m.Payload)
	s.outbox = append(s.outbox, m)
	s.outboxIx[m.ID] = len(s.outbox) - 1
	o.t.undo = append(o.t.undo, func() {
		delete(s.outboxIx, m.ID)
		s.outbox = s.outbox[:len(s.outbox)-1]
	})
	return nil
}

func (o outbox) Pending(_ context.Context, topic string, limit int) ([]port.OutboxMessage, error) {
	var out []port.OutboxMessage
	for _, m := range o.t.s.outbox {
		if len(out) >= limit {
			break
		}
		if m.Topic == topic && m.DeliveredAt == nil {
			m.Payload = bytes.Clone(m.Payload)
			out = append(out, m)
		}
	}
	return out, nil
}

func (o outbox) MarkDelivered(_ context.Context, ids []string, at time.Time) error {
	s := o.t.s
	for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
		i, ok := s.outboxIx[id]
		if !ok || s.outbox[i].DeliveredAt != nil {
			continue
		}
		at := at
		s.outbox[i].DeliveredAt = &at
		o.t.undo = append(o.t.undo, func() { s.outbox[i].DeliveredAt = nil })
	}
	return nil
}
