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
	"strings"
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
	// ix は照会の索引（追記のときにペイロードから作る。ADR 0100）。
	ix audit.Index
}

type state struct {
	realms   map[string]port.Realm
	features map[string]port.FeatureRecord
	dataKeys map[string]port.DataKey
	// auditKeys は監査ログの IP と UA の日ごとの鍵。
	auditKeys map[string]port.DataKey
	audit     []auditRow // seq は auditBase+1 から
	auditBase int64
	// checkpoint は監査ログを切り詰めた位置（auditBase と同じ seq）。
	checkpoint *audit.Checkpoint
	outbox     []port.OutboxMessage
	outboxIx   map[string]int

	users      map[string]port.User
	emails     map[string]port.UserEmail
	identities map[string]port.Identity
	// authnCreds は汎用の認証情報（ADR 0092）。
	authnCreds map[string]port.Credential
	// retiredLookups は退役した検索キー（ADR 0106）。キーは realm_id + method + lookup。
	retiredLookups map[string]port.RetiredLookup
	// devices は本人がログインした端末（ADR 0105）。
	devices       map[string]port.KnownDevice
	recoveryCodes map[string]port.RecoveryCode
	suspensions   map[string]port.Suspension
	scheduled     map[string]port.ScheduledEvent
	connections   map[string]port.Connection
	sessions      map[string]port.Session
	accounts      map[string]port.ServiceAccount
	credentials   map[string]port.ServiceAccountCredential
	saTokens      map[string]port.ServiceAccountToken
	roleBindings  map[string]port.RoleBinding
	roles         map[string]port.Role
	groups        map[string]port.Group
	// groupMembers のキーは group_id + member_type + member_id。
	groupMembers map[string]port.GroupMember
	// groupClosure のキーは realm_id + group_id + ancestor_id。値は depth。
	groupClosure map[string]groupLink
	// attrDefs のキーは realm_id + key、attrValues のキーは realm_id + user_id + key。
	attrDefs   map[string]port.AttributeDef
	attrValues map[string]port.UserAttribute
	// riskTypes のキーは realm_id + name。
	riskTypes map[string]port.RiskType
	// namespaces のキーは realm_id + name。
	namespaces  map[string]port.ActionNamespace
	orgs        map[string]port.Org
	memberships map[string]port.Membership
	invitations map[string]port.Invitation
	quotaGrants map[string]port.QuotaGrant
	orgDomains  map[string]port.OrgDomain
	clients     map[string]port.Client
	signingKeys map[string]port.SigningKey
	grants      map[string]port.Grant
	oidcTokens  map[string]port.OIDCToken
	// eventSubs はイベントの Webhook の購読（ADR 0100）。
	eventSubs map[string]port.EventSubscription
	// dirGroups はディレクトリの同期が管理する Group の対応（ADR 0102）。キーは realm_id + connection_id + external_key。
	dirGroups map[string]port.DirectoryGroup
	// wsfedRPs と wsfedCerts は WS-Federation の RP と署名の証明書（ADR 0110）。キーは realm_id + ID / key_id。
	wsfedRPs   map[string]port.WSFedRelyingParty
	wsfedCerts map[string]port.WSFedCertificate
	// oauthResources は自前の API（リソースサーバー）の登録（ADR 0112）。キーは realm_id + ID。
	oauthResources map[string]port.OAuthResource
	// pats は本人の Personal Access Token、patPolicies は realm ごとのポリシー（キーは realm_id。ADR 0109）。
	pats        map[string]port.PersonalAccessToken
	patPolicies map[string]port.PersonalAccessTokenPolicy
	// samlSPs と samlCerts は SAML の SP の登録と IdP の署名の証明書（ADR 0115）。キーは realm_id + ID / key_id。
	samlSPs   map[string]port.SAMLServiceProvider
	samlCerts map[string]port.SAMLIdPCertificate
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
		dataKeys: map[string]port.DataKey{}, auditKeys: map[string]port.DataKey{}, outboxIx: map[string]int{},
		users: map[string]port.User{}, emails: map[string]port.UserEmail{}, identities: map[string]port.Identity{},
		authnCreds: map[string]port.Credential{}, retiredLookups: map[string]port.RetiredLookup{}, devices: map[string]port.KnownDevice{},
		suspensions: map[string]port.Suspension{}, scheduled: map[string]port.ScheduledEvent{}, recoveryCodes: map[string]port.RecoveryCode{},
		connections: map[string]port.Connection{}, sessions: map[string]port.Session{},
		accounts: map[string]port.ServiceAccount{}, credentials: map[string]port.ServiceAccountCredential{},
		saTokens:     map[string]port.ServiceAccountToken{},
		roleBindings: map[string]port.RoleBinding{}, roles: map[string]port.Role{}, groups: map[string]port.Group{},
		groupMembers: map[string]port.GroupMember{}, groupClosure: map[string]groupLink{}, attrDefs: map[string]port.AttributeDef{}, attrValues: map[string]port.UserAttribute{}, riskTypes: map[string]port.RiskType{}, namespaces: map[string]port.ActionNamespace{}, orgs: map[string]port.Org{}, memberships: map[string]port.Membership{},
		invitations: map[string]port.Invitation{}, quotaGrants: map[string]port.QuotaGrant{}, orgDomains: map[string]port.OrgDomain{}, clients: map[string]port.Client{}, signingKeys: map[string]port.SigningKey{},
		grants: map[string]port.Grant{}, oidcTokens: map[string]port.OIDCToken{}, eventSubs: map[string]port.EventSubscription{},
		dirGroups: map[string]port.DirectoryGroup{},
		wsfedRPs:  map[string]port.WSFedRelyingParty{}, wsfedCerts: map[string]port.WSFedCertificate{},
		pats: map[string]port.PersonalAccessToken{}, patPolicies: map[string]port.PersonalAccessTokenPolicy{},
		samlSPs: map[string]port.SAMLServiceProvider{}, samlCerts: map[string]port.SAMLIdPCertificate{},
		oauthResources: map[string]port.OAuthResource{},
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
func (t *tx) DataKeys() port.DataKeyRepo   { return dataKeys{t, t.s.dataKeys} }
func (t *tx) AuditKeys() port.DataKeyRepo  { return dataKeys{t, t.s.auditKeys} }
func (t *tx) Audit() port.AuditRepo        { return auditRepo{t} }
func (t *tx) Outbox() port.OutboxRepo      { return outbox{t} }
func (t *tx) EventSubscriptions() port.EventSubscriptionRepo {
	return eventSubs{t}
}

func (t *tx) Users() port.UserRepo                       { return users{t} }
func (t *tx) Emails() port.EmailRepo                     { return emails{t} }
func (t *tx) Identities() port.IdentityRepo              { return identities{t} }
func (t *tx) DirectoryGroups() port.DirectoryGroupRepo   { return dirGroups{t} }
func (t *tx) Credentials() port.CredentialRepo           { return authnCredentials{t} }
func (t *tx) KnownDevices() port.KnownDeviceRepo         { return knownDevices{t} }
func (t *tx) RecoveryCodes() port.RecoveryCodeRepo       { return recoveryCodes{t} }
func (t *tx) Suspensions() port.SuspensionRepo           { return suspensions{t} }
func (t *tx) ScheduledEvents() port.ScheduledEventRepo   { return scheduledEvents{t} }
func (t *tx) Connections() port.ConnectionRepo           { return connections{t} }
func (t *tx) Sessions() port.SessionRepo                 { return sessions{t} }
func (t *tx) Orgs() port.OrgRepo                         { return orgs{t} }
func (t *tx) Memberships() port.MembershipRepo           { return memberships{t} }
func (t *tx) Invitations() port.InvitationRepo           { return invitations{t} }
func (t *tx) QuotaGrants() port.QuotaGrantRepo           { return quotaGrants{t} }
func (t *tx) OrgDomains() port.OrgDomainRepo             { return orgDomains{t} }
func (t *tx) ServiceAccounts() port.ServiceAccountRepo   { return accounts{t} }
func (t *tx) RoleBindings() port.RoleBindingRepo         { return roleBindings{t} }
func (t *tx) Roles() port.RoleRepo                       { return roles{t} }
func (t *tx) Groups() port.GroupRepo                     { return groups{t} }
func (t *tx) Attributes() port.AttributeRepo             { return attributes{t} }
func (t *tx) RiskTypes() port.RiskTypeRepo               { return riskTypes{t} }
func (t *tx) ActionNamespaces() port.ActionNamespaceRepo { return actionNamespaces{t} }
func (t *tx) Clients() port.ClientRepo                   { return clients{t} }
func (t *tx) SigningKeys() port.SigningKeyRepo           { return signingKeys{t} }
func (t *tx) Grants() port.GrantRepo                     { return grants{t} }
func (t *tx) OIDCTokens() port.OIDCTokenRepo             { return oidcTokens{t} }
func (t *tx) WSFed() port.WSFedRepo                      { return wsfed{t} }

// OAuthResources は自前の API（リソースサーバー）の登録（ADR 0112）。
func (t *tx) OAuthResources() port.OAuthResourceRepo { return oauthResources{t} }

// PersonalAccessTokens は本人の Personal Access Token（ADR 0109）。
func (t *tx) PersonalAccessTokens() port.PersonalAccessTokenRepo { return pats{t} }

// SAMLIdP は SAML の SP の登録と IdP の署名の証明書（ADR 0115）。
func (t *tx) SAMLIdP() port.SAMLIdPRepo { return samlIdP{t} }

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
	if err := r.hostsFree(v); err != nil {
		return err
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = v.CreatedAt
	}
	setKey(r.t, r.t.s.realms, v.ID, cloneRealm(v))
	return nil
}

func (r realms) hostsFree(v port.Realm) error {
	seen := map[string]bool{}
	for _, h := range v.Hosts {
		if seen[h] {
			return errs.New(errs.KindConflict, "realm host %q repeated", h)
		}
		seen[h] = true
	}
	for _, x := range r.t.s.realms {
		if x.ID == v.ID {
			continue
		}
		for _, h := range x.Hosts {
			if seen[h] {
				return errs.New(errs.KindConflict, "realm host %q exists", h)
			}
		}
	}
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

func (r realms) GetByHost(_ context.Context, host string) (port.Realm, error) {
	for _, v := range r.t.s.realms {
		if slices.Contains(v.Hosts, host) {
			return cloneRealm(v), nil
		}
	}
	return port.Realm{}, errs.New(errs.KindNotFound, "realm host %q", host)
}

func (r realms) List(context.Context) ([]port.Realm, error) {
	out := make([]port.Realm, 0, len(r.t.s.realms))
	for _, v := range r.t.s.realms {
		out = append(out, cloneRealm(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r realms) Update(_ context.Context, v port.Realm) error {
	cur, ok := r.t.s.realms[v.ID]
	if !ok {
		return errs.New(errs.KindNotFound, "realm %s", v.ID)
	}
	if err := r.hostsFree(v); err != nil {
		return err
	}
	cur.Settings, cur.Hosts, cur.UpdatedAt = v.Settings, v.Hosts, v.UpdatedAt
	setKey(r.t, r.t.s.realms, v.ID, cloneRealm(cur))
	return nil
}

func cloneRealm(v port.Realm) port.Realm {
	v.Settings = bytes.Clone(v.Settings)
	v.Hosts = slices.Clone(v.Hosts)
	if len(v.Hosts) == 0 {
		v.Hosts = nil
	}
	return v
}

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

type dataKeys struct {
	t *tx
	m map[string]port.DataKey
}

func (d dataKeys) Create(_ context.Context, k port.DataKey) error {
	if _, ok := d.m[k.UserID]; ok {
		return errs.New(errs.KindConflict, "data key for %s exists", k.UserID)
	}
	k.WrappedKey = bytes.Clone(k.WrappedKey)
	setKey(d.t, d.m, k.UserID, k)
	return nil
}

func (d dataKeys) Get(_ context.Context, userID string) (port.DataKey, error) {
	k, ok := d.m[userID]
	if !ok {
		return port.DataKey{}, errs.New(errs.KindNotFound, "data key for %s", userID)
	}
	k.WrappedKey = bytes.Clone(k.WrappedKey)
	return k, nil
}

func (d dataKeys) Delete(_ context.Context, userID string) error {
	deleteKey(d.t, d.m, userID)
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
	if want := s.auditBase + int64(len(s.audit)) + 1; r.Seq != want {
		return errs.New(errs.KindConflict, "audit seq %d: want %d", r.Seq, want)
	}
	ix, err := audit.IndexOf(r.Payload)
	if err != nil {
		return err
	}
	s.audit = append(s.audit, auditRow{rec: cloneRecord(r), ix: ix})
	a.t.undo = append(a.t.undo, func() { s.audit = s.audit[:len(s.audit)-1] })
	return nil
}

func (a auditRepo) Scan(_ context.Context, fromSeq int64, limit int) ([]audit.Record, error) {
	var out []audit.Record
	s := a.t.s
	for i := max(fromSeq-1-s.auditBase, 0); i < int64(len(s.audit)) && len(out) < limit; i++ {
		out = append(out, cloneRecord(s.audit[i].rec))
	}
	return out, nil
}

func (a auditRepo) ListByRealm(_ context.Context, realmID string, fromSeq int64, limit int) ([]audit.Record, error) {
	var out []audit.Record
	s := a.t.s
	for i := max(fromSeq-1-s.auditBase, 0); i < int64(len(s.audit)) && len(out) < limit; i++ {
		if row := s.audit[i]; row.rec.RealmID == realmID {
			out = append(out, cloneRecord(row.rec))
		}
	}
	return out, nil
}

func (a auditRepo) Query(_ context.Context, q port.AuditQuery) ([]audit.Record, error) {
	out := []audit.Record{}
	s := a.t.s
	for i := len(s.audit) - 1; i >= 0 && len(out) < q.Limit; i-- {
		row := s.audit[i]
		if row.rec.RealmID != q.RealmID || (q.BeforeSeq > 0 && row.rec.Seq >= q.BeforeSeq) || !indexMatches(row.ix, q.Filter) {
			continue
		}
		out = append(out, cloneRecord(row.rec))
	}
	return out, nil
}

// indexMatches は索引が条件に合うかを返す（SQL のアダプタの WHERE と同じ。時刻は秒の単位で、境界の秒を含める）。
func indexMatches(ix audit.Index, f audit.Filter) bool {
	switch {
	case !f.Since.IsZero() && ix.Unix < f.Since.Unix():
	case !f.Until.IsZero() && ix.Unix > f.Until.Unix():
	case f.Type != "" && ix.Type != f.Type:
	case f.TypePrefix != "" && !strings.HasPrefix(ix.Type, f.TypePrefix):
	case f.Result != "" && ix.Result != string(f.Result):
	case f.ActorType != "" && ix.ActorType != f.ActorType:
	case f.ActorID != "" && ix.ActorID != f.ActorID:
	case f.OrgID != "" && ix.OrgID != f.OrgID:
	case f.Ref != "" && !slices.Contains(ix.Refs, f.Ref):
	default:
		return true
	}
	return false
}

func (a auditRepo) GetByEventID(_ context.Context, realmID, eventID string) (audit.Record, error) {
	for _, row := range a.t.s.audit {
		if row.rec.RealmID == realmID && row.ix.EventID == eventID {
			return cloneRecord(row.rec), nil
		}
	}
	return audit.Record{}, errs.New(errs.KindNotFound, "audit event")
}

func (a auditRepo) Checkpoint(context.Context) (*audit.Checkpoint, error) {
	if a.t.s.checkpoint == nil {
		return nil, nil
	}
	cp := *a.t.s.checkpoint
	cp.Hash = bytes.Clone(cp.Hash)
	return &cp, nil
}

func (a auditRepo) Truncate(_ context.Context, cp audit.Checkpoint) error {
	s := a.t.s
	oldAudit, oldBase, oldCP := s.audit, s.auditBase, s.checkpoint
	if n := cp.Seq - s.auditBase; n > 0 {
		s.audit = slices.Clone(s.audit[min(n, int64(len(s.audit))):])
		s.auditBase = cp.Seq
	}
	cp.Hash = bytes.Clone(cp.Hash)
	s.checkpoint = &cp
	a.t.undo = append(a.t.undo, func() { s.audit, s.auditBase, s.checkpoint = oldAudit, oldBase, oldCP })
	return nil
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

func (o outbox) DeleteDelivered(_ context.Context, before time.Time, limit int) (int, error) {
	s := o.t.s
	oldOutbox, oldIx := s.outbox, s.outboxIx
	kept := make([]port.OutboxMessage, 0, len(s.outbox))
	n := 0
	for _, m := range s.outbox {
		if n < limit && m.DeliveredAt != nil && m.DeliveredAt.Before(before) {
			n++
			continue
		}
		kept = append(kept, m)
	}
	if n == 0 {
		return 0, nil
	}
	s.outbox, s.outboxIx = kept, make(map[string]int, len(kept))
	for i, m := range kept {
		s.outboxIx[m.ID] = i
	}
	o.t.undo = append(o.t.undo, func() { s.outbox, s.outboxIx = oldOutbox, oldIx })
	return n, nil
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
