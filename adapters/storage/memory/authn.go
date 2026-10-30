package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// get は realm が一致するときだけ値を返す（別の realm のデータは存在しないものとして扱う）。
func get[V any](m map[string]V, realmID, id string, realmOf func(V) string, what string) (V, error) {
	v, ok := m[id]
	if !ok || realmOf(v) != realmID {
		var zero V
		return zero, errs.New(errs.KindNotFound, "%s %s", what, id)
	}
	return v, nil
}

// ---------------------------------------------------------------------------

type users struct{ t *tx }

func cloneUser(u port.User) port.User {
	u.ValidFrom, u.ValidUntil, u.DeletionScheduledAt = cloneTime(u.ValidFrom), cloneTime(u.ValidUntil), cloneTime(u.DeletionScheduledAt)
	u.ManagedAt = cloneTime(u.ManagedAt)
	return u
}

func (r users) Create(_ context.Context, u port.User) error {
	if _, ok := r.t.s.users[u.ID]; ok {
		return errs.New(errs.KindConflict, "user %s exists", u.ID)
	}
	for _, x := range r.t.s.users {
		if x.RealmID == u.RealmID && x.PublicID == u.PublicID {
			return errs.New(errs.KindConflict, "user public id exists in realm")
		}
	}
	setKey(r.t, r.t.s.users, u.ID, cloneUser(u))
	return nil
}

func (r users) Get(_ context.Context, realmID, id string) (port.User, error) {
	u, err := get(r.t.s.users, realmID, id, func(u port.User) string { return u.RealmID }, "user")
	return cloneUser(u), err
}

func (r users) GetByPublicID(_ context.Context, realmID, publicID string) (port.User, error) {
	for _, u := range r.t.s.users {
		if u.RealmID == realmID && u.PublicID == publicID {
			return cloneUser(u), nil
		}
	}
	return port.User{}, errs.New(errs.KindNotFound, "user")
}

func (r users) List(_ context.Context, realmID, afterID string, limit int) ([]port.User, error) {
	var out []port.User
	for _, u := range r.t.s.users {
		if u.RealmID == realmID && u.ID > afterID {
			out = append(out, cloneUser(u))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---------------------------------------------------------------------------

type emails struct{ t *tx }

func cloneEmail(e port.UserEmail) port.UserEmail {
	e.Ciphertext, e.Index, e.DomainIndex = bytes.Clone(e.Ciphertext), bytes.Clone(e.Index), bytes.Clone(e.DomainIndex)
	e.VerifiedAt = cloneTime(e.VerifiedAt)
	return e
}

func (r emails) Create(_ context.Context, e port.UserEmail) error {
	if _, ok := r.t.s.emails[e.ID]; ok {
		return errs.New(errs.KindConflict, "email %s exists", e.ID)
	}
	for _, x := range r.t.s.emails {
		if x.RealmID == e.RealmID && bytes.Equal(x.Index, e.Index) {
			return errs.New(errs.KindConflict, "email index exists in realm")
		}
		if x.RealmID == e.RealmID && x.PublicID == e.PublicID {
			return errs.New(errs.KindConflict, "email public id exists in realm")
		}
	}
	setKey(r.t, r.t.s.emails, e.ID, cloneEmail(e))
	return nil
}

func (r emails) GetByIndex(_ context.Context, realmID string, index []byte) (port.UserEmail, error) {
	for _, x := range r.t.s.emails {
		if x.RealmID == realmID && bytes.Equal(x.Index, index) {
			return cloneEmail(x), nil
		}
	}
	return port.UserEmail{}, errs.New(errs.KindNotFound, "email")
}

func (r emails) GetByPublicID(_ context.Context, realmID, publicID string) (port.UserEmail, error) {
	for _, x := range r.t.s.emails {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneEmail(x), nil
		}
	}
	return port.UserEmail{}, errs.New(errs.KindNotFound, "email")
}

func (r emails) SetPrimary(_ context.Context, realmID, userID, id string) error {
	e, err := get(r.t.s.emails, realmID, id, func(e port.UserEmail) string { return e.RealmID }, "email")
	if err != nil || e.UserID != userID {
		return errs.New(errs.KindNotFound, "email %s", id)
	}
	for k, x := range r.t.s.emails {
		if x.RealmID == realmID && x.UserID == userID && x.IsPrimary != (k == id) {
			x.IsPrimary = k == id
			setKey(r.t, r.t.s.emails, k, x)
		}
	}
	return nil
}

func (r emails) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.emails, realmID, id, func(e port.UserEmail) string { return e.RealmID }, "email"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.emails, id)
	return nil
}

func (r emails) ClearCiphertexts(_ context.Context, realmID string, limit int) (int, error) {
	n := 0
	for k, x := range r.t.s.emails {
		if n < limit && x.RealmID == realmID && len(x.Ciphertext) > 0 {
			x.Ciphertext = nil
			setKey(r.t, r.t.s.emails, k, x)
			n++
		}
	}
	return n, nil
}

func (r emails) ListByUser(_ context.Context, realmID, userID string) ([]port.UserEmail, error) {
	var out []port.UserEmail
	for _, x := range r.t.s.emails {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneEmail(x))
		}
	}
	sortByCreated(out, func(x port.UserEmail) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

// ---------------------------------------------------------------------------

type identities struct{ t *tx }

func cloneIdentity(i port.Identity) port.Identity { i.RevokedAt = cloneTime(i.RevokedAt); return i }

func (r identities) Create(_ context.Context, i port.Identity) error {
	if _, ok := r.t.s.identities[i.ID]; ok {
		return errs.New(errs.KindConflict, "identity %s exists", i.ID)
	}
	for _, x := range r.t.s.identities {
		if x.ConnectionID == i.ConnectionID && x.ProviderSubject == i.ProviderSubject && x.RevokedAt == nil && i.RevokedAt == nil {
			return errs.New(errs.KindConflict, "identity exists for connection")
		}
		if x.RealmID == i.RealmID && x.PublicID == i.PublicID {
			return errs.New(errs.KindConflict, "identity public id exists in realm")
		}
	}
	setKey(r.t, r.t.s.identities, i.ID, cloneIdentity(i))
	return nil
}

func (r identities) GetBySubject(_ context.Context, realmID, connectionID, subject string) (port.Identity, error) {
	for _, x := range r.t.s.identities {
		if x.RealmID == realmID && x.ConnectionID == connectionID && x.ProviderSubject == subject && x.RevokedAt == nil {
			return cloneIdentity(x), nil
		}
	}
	return port.Identity{}, errs.New(errs.KindNotFound, "identity")
}

func (r identities) GetByPublicID(_ context.Context, realmID, publicID string) (port.Identity, error) {
	for _, x := range r.t.s.identities {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneIdentity(x), nil
		}
	}
	return port.Identity{}, errs.New(errs.KindNotFound, "identity")
}

func (r identities) Get(_ context.Context, realmID, id string) (port.Identity, error) {
	i, err := get(r.t.s.identities, realmID, id, func(i port.Identity) string { return i.RealmID }, "identity")
	return cloneIdentity(i), err
}

func (r identities) RevokeByConnection(_ context.Context, realmID, connectionID string, at time.Time, reason string) (int, error) {
	n := 0
	for k, x := range r.t.s.identities {
		if x.RealmID == realmID && x.ConnectionID == connectionID && x.RevokedAt == nil {
			x = cloneIdentity(x)
			x.RevokedAt, x.RevokeReason = &at, reason
			setKey(r.t, r.t.s.identities, k, x)
			n++
		}
	}
	return n, nil
}

func (r identities) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	i, err := get(r.t.s.identities, realmID, id, func(i port.Identity) string { return i.RealmID }, "identity")
	if err != nil || i.RevokedAt != nil {
		return err
	}
	i = cloneIdentity(i)
	i.RevokedAt, i.RevokeReason = &at, reason
	setKey(r.t, r.t.s.identities, id, i)
	return nil
}

func (r identities) ListByUser(_ context.Context, realmID, userID string) ([]port.Identity, error) {
	var out []port.Identity
	for _, x := range r.t.s.identities {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneIdentity(x))
		}
	}
	sortByCreated(out, func(x port.Identity) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

// ---------------------------------------------------------------------------

type connections struct{ t *tx }

func cloneConnection(c port.Connection) port.Connection { c.Config = bytes.Clone(c.Config); return c }

func (r connections) Create(_ context.Context, c port.Connection) error {
	if _, ok := r.t.s.connections[c.ID]; ok {
		return errs.New(errs.KindConflict, "connection %s exists", c.ID)
	}
	for _, x := range r.t.s.connections {
		if x.RealmID == c.RealmID && x.Slug == c.Slug {
			return errs.New(errs.KindConflict, "connection slug %q exists", c.Slug)
		}
	}
	setKey(r.t, r.t.s.connections, c.ID, cloneConnection(c))
	return nil
}

func (r connections) Get(_ context.Context, realmID, id string) (port.Connection, error) {
	c, err := get(r.t.s.connections, realmID, id, func(c port.Connection) string { return c.RealmID }, "connection")
	return cloneConnection(c), err
}

func (r connections) GetBySlug(_ context.Context, realmID, slug string) (port.Connection, error) {
	for _, x := range r.t.s.connections {
		if x.RealmID == realmID && x.Slug == slug {
			return cloneConnection(x), nil
		}
	}
	return port.Connection{}, errs.New(errs.KindNotFound, "connection %q", slug)
}

func (r connections) List(_ context.Context, realmID string) ([]port.Connection, error) {
	var out []port.Connection
	for _, x := range r.t.s.connections {
		if x.RealmID == realmID {
			out = append(out, cloneConnection(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (r connections) ListByOwner(_ context.Context, realmID, orgID string) ([]port.Connection, error) {
	var out []port.Connection
	for _, x := range r.t.s.connections {
		if x.RealmID == realmID && x.OwnerOrgID == orgID {
			out = append(out, cloneConnection(x))
		}
	}
	sortByCreated(out, func(x port.Connection) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r connections) CountOwned(_ context.Context, realmID string) (int, error) {
	n := 0
	for _, x := range r.t.s.connections {
		if x.RealmID == realmID && x.OwnerOrgID != "" {
			n++
		}
	}
	return n, nil
}

func (r connections) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.connections, realmID, id, func(c port.Connection) string { return c.RealmID }, "connection"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.connections, id)
	return nil
}

// ---------------------------------------------------------------------------

type sessions struct{ t *tx }

func cloneSession(s port.Session) port.Session {
	s.TokenHash, s.Warnings, s.IP, s.UserAgent = bytes.Clone(s.TokenHash), bytes.Clone(s.Warnings), bytes.Clone(s.IP), bytes.Clone(s.UserAgent)
	s.Risk = bytes.Clone(s.Risk)
	s.AuthMethods, s.AuthCredentialIDs = slices.Clone(s.AuthMethods), slices.Clone(s.AuthCredentialIDs)
	s.RevokedAt = cloneTime(s.RevokedAt)
	return s
}

func (r sessions) Create(_ context.Context, s port.Session) error {
	if _, ok := r.t.s.sessions[s.ID]; ok {
		return errs.New(errs.KindConflict, "session %s exists", s.ID)
	}
	setKey(r.t, r.t.s.sessions, s.ID, cloneSession(s))
	return nil
}

func (r sessions) Get(_ context.Context, realmID, id string) (port.Session, error) {
	s, err := get(r.t.s.sessions, realmID, id, func(s port.Session) string { return s.RealmID }, "session")
	return cloneSession(s), err
}

func (r sessions) ListByPrincipal(_ context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.Session, error) {
	var out []port.Session
	for _, s := range r.t.s.sessions {
		if s.RealmID == realmID && s.PrincipalType == t && s.PrincipalID == principalID {
			out = append(out, cloneSession(s))
		}
	}
	// 作成の新しい順。ID は乱数なので順序には使わない（同時刻の並びを決めるだけ）。
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (r sessions) GetCurrentBySID(_ context.Context, realmID, sid string) (port.Session, error) {
	var cur *port.Session
	for _, s := range r.t.s.sessions {
		if s.RealmID != realmID || s.SID != sid {
			continue
		}
		if cur == nil || s.CreatedAt.After(cur.CreatedAt) || (s.CreatedAt.Equal(cur.CreatedAt) && s.ID > cur.ID) {
			cur = &s
		}
	}
	if cur == nil {
		return port.Session{}, errs.New(errs.KindNotFound, "session lineage %s", sid)
	}
	return cloneSession(*cur), nil
}

func (r sessions) update(realmID, id string, fn func(*port.Session)) error {
	s, err := get(r.t.s.sessions, realmID, id, func(s port.Session) string { return s.RealmID }, "session")
	if err != nil {
		return err
	}
	s = cloneSession(s)
	fn(&s)
	setKey(r.t, r.t.s.sessions, id, s)
	return nil
}

func (r sessions) Touch(_ context.Context, realmID, id string, at time.Time) error {
	return r.update(realmID, id, func(s *port.Session) {
		if at.After(s.LastSeenAt) {
			s.LastSeenAt = at
		}
	})
}

func (r sessions) SetRisk(_ context.Context, realmID, id string, risk []byte) error {
	return r.update(realmID, id, func(s *port.Session) { s.Risk = bytes.Clone(risk) })
}

func (r sessions) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	return r.update(realmID, id, func(s *port.Session) {
		if s.RevokedAt == nil || at.Before(*s.RevokedAt) {
			s.RevokedAt, s.RevokeReason = &at, reason
		}
	})
}

func (r sessions) RevokeByPrincipal(_ context.Context, realmID string, t port.PrincipalType, principalID, exceptID string, at time.Time, reason string) ([]string, error) {
	var ids []string
	for _, s := range r.t.s.sessions {
		if s.RealmID == realmID && s.PrincipalType == t && s.PrincipalID == principalID && s.ID != exceptID && (s.RevokedAt == nil || at.Before(*s.RevokedAt)) {
			ids = append(ids, s.ID)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := r.Revoke(context.Background(), realmID, id, at, reason); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

func (r sessions) DeleteEnded(_ context.Context, before time.Time, limit int) (int, error) {
	n := 0
	for id, x := range r.t.s.sessions {
		if n < limit && (x.ExpiresAt.Before(before) || (x.RevokedAt != nil && x.RevokedAt.Before(before))) {
			deleteKey(r.t, r.t.s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (r sessions) MoveOrg(_ context.Context, realmID, userID, fromOrgID, toOrgID string) ([]string, error) {
	var ids []string
	for _, s := range r.t.s.sessions {
		if s.RealmID == realmID && s.PrincipalType == port.PrincipalUser && s.PrincipalID == userID && s.ActiveOrgID == fromOrgID {
			ids = append(ids, s.ID)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := r.update(realmID, id, func(s *port.Session) { s.ActiveOrgID = toOrgID }); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// ---------------------------------------------------------------------------

type accounts struct{ t *tx }

func cloneCredential(c port.ServiceAccountCredential) port.ServiceAccountCredential {
	c.SecretHash, c.PublicKey = bytes.Clone(c.SecretHash), bytes.Clone(c.PublicKey)
	c.ExpiresAt, c.RevokedAt = cloneTime(c.ExpiresAt), cloneTime(c.RevokedAt)
	return c
}

func cloneAccount(a port.ServiceAccount) port.ServiceAccount {
	a.ValidFrom, a.ValidUntil, a.DeletedAt = cloneTime(a.ValidFrom), cloneTime(a.ValidUntil), cloneTime(a.DeletedAt)
	return a
}

func (r accounts) Create(_ context.Context, a port.ServiceAccount) error {
	if _, ok := r.t.s.accounts[a.ID]; ok {
		return errs.New(errs.KindConflict, "service account %s exists", a.ID)
	}
	setKey(r.t, r.t.s.accounts, a.ID, cloneAccount(a))
	return nil
}

func (r accounts) Get(_ context.Context, realmID, id string) (port.ServiceAccount, error) {
	a, err := get(r.t.s.accounts, realmID, id, func(a port.ServiceAccount) string { return a.RealmID }, "service account")
	return cloneAccount(a), err
}

func (r accounts) List(_ context.Context, realmID, afterID string, limit int) ([]port.ServiceAccount, error) {
	var out []port.ServiceAccount
	for _, a := range r.t.s.accounts {
		if a.RealmID == realmID && a.ID > afterID {
			out = append(out, cloneAccount(a))
		}
	}
	slices.SortFunc(out, func(a, b port.ServiceAccount) int { return strings.Compare(a.ID, b.ID) })
	return out[:min(limit, len(out))], nil
}

func (r accounts) SetDeleted(_ context.Context, realmID, id string, at time.Time) error {
	a, err := r.Get(context.Background(), realmID, id)
	if err != nil {
		return err
	}
	if a.DeletedAt == nil {
		a.DeletedAt = &at
		setKey(r.t, r.t.s.accounts, id, a)
	}
	return nil
}

func (r accounts) ListCredentials(_ context.Context, realmID, serviceAccountID string) ([]port.ServiceAccountCredential, error) {
	var out []port.ServiceAccountCredential
	for _, c := range r.t.s.credentials {
		if c.RealmID == realmID && c.ServiceAccountID == serviceAccountID {
			out = append(out, cloneCredential(c))
		}
	}
	sortByCreated(out, func(c port.ServiceAccountCredential) (time.Time, string) { return c.CreatedAt, c.ID })
	return out, nil
}

func (r accounts) CreateToken(_ context.Context, t port.ServiceAccountToken) error {
	if _, ok := r.t.s.saTokens[t.ID]; ok {
		return errs.New(errs.KindConflict, "token %s exists", t.ID)
	}
	t.Hash = bytes.Clone(t.Hash)
	setKey(r.t, r.t.s.saTokens, t.ID, t)
	return nil
}

func (r accounts) GetToken(_ context.Context, realmID, id string) (port.ServiceAccountToken, error) {
	t, err := get(r.t.s.saTokens, realmID, id, func(t port.ServiceAccountToken) string { return t.RealmID }, "token")
	t.Hash = bytes.Clone(t.Hash)
	return t, err
}

func (r accounts) DeleteExpiredTokens(_ context.Context, before time.Time, limit int) (int, error) {
	n := 0
	for id, t := range r.t.s.saTokens {
		if n < limit && t.ExpiresAt.Before(before) {
			deleteKey(r.t, r.t.s.saTokens, id)
			n++
		}
	}
	return n, nil
}

func (r accounts) CreateCredential(_ context.Context, c port.ServiceAccountCredential) error {
	if _, ok := r.t.s.credentials[c.ID]; ok {
		return errs.New(errs.KindConflict, "credential %s exists", c.ID)
	}
	if _, err := r.Get(context.Background(), c.RealmID, c.ServiceAccountID); err != nil {
		return err
	}
	setKey(r.t, r.t.s.credentials, c.ID, cloneCredential(c))
	return nil
}

func (r accounts) GetCredential(_ context.Context, realmID, id string) (port.ServiceAccountCredential, error) {
	c, err := get(r.t.s.credentials, realmID, id, func(c port.ServiceAccountCredential) string { return c.RealmID }, "credential")
	return cloneCredential(c), err
}

func (r accounts) RevokeCredential(_ context.Context, realmID, id string, at time.Time) error {
	c, err := r.GetCredential(context.Background(), realmID, id)
	if err != nil {
		return err
	}
	if c.RevokedAt == nil {
		c.RevokedAt = &at
		setKey(r.t, r.t.s.credentials, id, c)
	}
	return nil
}

// ---------------------------------------------------------------------------

// sortByCreated は作成時刻の順（同時刻は ID の順）に並べる。ID は乱数のことがあるので、順序の主には使わない。
func sortByCreated[T any](out []T, key func(T) (time.Time, string)) {
	sort.Slice(out, func(i, j int) bool {
		ti, ii := key(out[i])
		tj, ij := key(out[j])
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return ii < ij
	})
}

func (r users) SetValidity(_ context.Context, realmID, id string, from, until *time.Time, updatedAt time.Time) error {
	u, err := get(r.t.s.users, realmID, id, func(u port.User) string { return u.RealmID }, "user")
	if err != nil {
		return err
	}
	u = cloneUser(u)
	u.ValidFrom, u.ValidUntil, u.UpdatedAt = cloneTime(from), cloneTime(until), updatedAt
	setKey(r.t, r.t.s.users, id, u)
	return nil
}

func (r users) SetDeletion(_ context.Context, realmID, id string, scheduledAt *time.Time, updatedAt time.Time) error {
	return r.change(realmID, id, func(u *port.User) { u.DeletionScheduledAt, u.UpdatedAt = cloneTime(scheduledAt), updatedAt })
}

func (r users) SetLegalHold(_ context.Context, realmID, id string, hold bool, updatedAt time.Time) error {
	return r.change(realmID, id, func(u *port.User) { u.LegalHold, u.UpdatedAt = hold, updatedAt })
}

func (r users) SetMerged(_ context.Context, realmID, id, into string, at time.Time) error {
	u, err := get(r.t.s.users, realmID, id, func(u port.User) string { return u.RealmID }, "user")
	if err != nil {
		return err
	}
	if u.Status != port.UserActive {
		return errs.New(errs.KindNotFound, "user")
	}
	return r.change(realmID, id, func(u *port.User) {
		u.Status, u.MergedInto, u.DeletionScheduledAt, u.UpdatedAt = port.UserMerged, into, nil, at
	})
}

func (r users) SetManagedOrg(_ context.Context, realmID, id, orgID string, at time.Time) error {
	return r.change(realmID, id, func(u *port.User) {
		u.ManagedOrgID, u.ManagedAt, u.UpdatedAt = orgID, nil, at
		if orgID != "" {
			u.ManagedAt = cloneTime(&at)
		}
	})
}

func (r users) ListManagedByOrg(_ context.Context, realmID, orgID, afterID string, limit int) ([]port.User, error) {
	var out []port.User
	for _, u := range r.t.s.users {
		if u.RealmID == realmID && orgID != "" && u.ManagedOrgID == orgID && u.ID > afterID {
			out = append(out, cloneUser(u))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r users) CountManaged(context.Context) (int, error) {
	n := 0
	for _, u := range r.t.s.users {
		if u.ManagedOrgID != "" {
			n++
		}
	}
	return n, nil
}

func (r users) ReleaseManaged(_ context.Context, limit int, at time.Time) (int, error) {
	n := 0
	for id, u := range r.t.s.users {
		if n >= limit {
			break
		}
		if u.ManagedOrgID == "" {
			continue
		}
		u = cloneUser(u)
		u.ManagedOrgID, u.ManagedAt, u.UpdatedAt = "", nil, at
		setKey(r.t, r.t.s.users, id, u)
		n++
	}
	return n, nil
}

func (r users) change(realmID, id string, fn func(*port.User)) error {
	u, err := get(r.t.s.users, realmID, id, func(u port.User) string { return u.RealmID }, "user")
	if err != nil {
		return err
	}
	u = cloneUser(u)
	fn(&u)
	setKey(r.t, r.t.s.users, id, u)
	return nil
}

func (r users) Erase(_ context.Context, realmID, id string, at time.Time) error {
	if err := r.change(realmID, id, func(u *port.User) { u.Status, u.DeletionScheduledAt, u.UpdatedAt = port.UserDeleted, nil, at }); err != nil {
		return err
	}
	s := r.t.s
	eraseWhere(r.t, s.emails, func(x port.UserEmail) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.identities, func(x port.Identity) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.passkeys, func(x port.Passkey) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.totps, func(x port.TOTPCredential) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.passwords, func(x port.PasswordCredential) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.recoveryCodes, func(x port.RecoveryCode) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.sessions, func(x port.Session) bool {
		return x.RealmID == realmID && x.PrincipalType == port.PrincipalUser && x.PrincipalID == id
	})
	eraseWhere(r.t, s.roleBindings, func(x port.RoleBinding) bool {
		return x.RealmID == realmID && x.PrincipalType == port.PrincipalUser && x.PrincipalID == id
	})
	eraseGrants(r.t, func(g port.Grant) bool { return g.RealmID == realmID && g.UserID == id })
	eraseWhere(r.t, s.attrValues, func(x port.UserAttribute) bool { return x.RealmID == realmID && x.UserID == id })
	eraseWhere(r.t, s.groupMembers, func(x port.GroupMember) bool {
		g, ok := s.groups[x.GroupID]
		return ok && g.RealmID == realmID && x.MemberType == port.PrincipalUser && x.MemberID == id
	})
	return nil
}

func eraseWhere[V any](t *tx, m map[string]V, match func(V) bool) {
	var keys []string
	for k, v := range m {
		if match(v) {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		deleteKey(t, m, k)
	}
}
