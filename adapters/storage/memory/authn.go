package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
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
	u.ValidFrom, u.ValidUntil = cloneTime(u.ValidFrom), cloneTime(u.ValidUntil)
	return u
}

func (r users) Create(_ context.Context, u port.User) error {
	if _, ok := r.t.s.users[u.ID]; ok {
		return errs.New(errs.KindConflict, "user %s exists", u.ID)
	}
	setKey(r.t, r.t.s.users, u.ID, cloneUser(u))
	return nil
}

func (r users) Get(_ context.Context, realmID, id string) (port.User, error) {
	u, err := get(r.t.s.users, realmID, id, func(u port.User) string { return u.RealmID }, "user")
	return cloneUser(u), err
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

func (r emails) ListByUser(_ context.Context, realmID, userID string) ([]port.UserEmail, error) {
	var out []port.UserEmail
	for _, x := range r.t.s.emails {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneEmail(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
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
		if x.ConnectionID == i.ConnectionID && x.ProviderSubject == i.ProviderSubject {
			return errs.New(errs.KindConflict, "identity exists for connection")
		}
	}
	setKey(r.t, r.t.s.identities, i.ID, cloneIdentity(i))
	return nil
}

func (r identities) GetBySubject(_ context.Context, realmID, connectionID, subject string) (port.Identity, error) {
	for _, x := range r.t.s.identities {
		if x.RealmID == realmID && x.ConnectionID == connectionID && x.ProviderSubject == subject {
			return cloneIdentity(x), nil
		}
	}
	return port.Identity{}, errs.New(errs.KindNotFound, "identity")
}

func (r identities) ListByUser(_ context.Context, realmID, userID string) ([]port.Identity, error) {
	var out []port.Identity
	for _, x := range r.t.s.identities {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneIdentity(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
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

// ---------------------------------------------------------------------------

type sessions struct{ t *tx }

func cloneSession(s port.Session) port.Session {
	s.TokenHash, s.Warnings, s.IP, s.UserAgent = bytes.Clone(s.TokenHash), bytes.Clone(s.Warnings), bytes.Clone(s.IP), bytes.Clone(s.UserAgent)
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
	// ID は UUIDv7 なので、ID の降順が新しい順。
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
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

// ---------------------------------------------------------------------------

type accounts struct{ t *tx }

func cloneCredential(c port.ServiceAccountCredential) port.ServiceAccountCredential {
	c.SecretHash = bytes.Clone(c.SecretHash)
	c.ExpiresAt, c.RevokedAt = cloneTime(c.ExpiresAt), cloneTime(c.RevokedAt)
	return c
}

func (r accounts) Create(_ context.Context, a port.ServiceAccount) error {
	if _, ok := r.t.s.accounts[a.ID]; ok {
		return errs.New(errs.KindConflict, "service account %s exists", a.ID)
	}
	setKey(r.t, r.t.s.accounts, a.ID, a)
	return nil
}

func (r accounts) Get(_ context.Context, realmID, id string) (port.ServiceAccount, error) {
	return get(r.t.s.accounts, realmID, id, func(a port.ServiceAccount) string { return a.RealmID }, "service account")
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

type roleBindings struct{ t *tx }

func (r roleBindings) Create(_ context.Context, b port.RoleBinding) error {
	if _, ok := r.t.s.roleBindings[b.ID]; ok {
		return errs.New(errs.KindConflict, "role binding %s exists", b.ID)
	}
	for _, x := range r.t.s.roleBindings {
		if x.RealmID == b.RealmID && x.Role == b.Role && x.PrincipalType == b.PrincipalType && x.PrincipalID == b.PrincipalID && x.OrgID == b.OrgID {
			return errs.New(errs.KindConflict, "role binding exists")
		}
	}
	setKey(r.t, r.t.s.roleBindings, b.ID, b)
	return nil
}

func (r roleBindings) list(match func(port.RoleBinding) bool) []port.RoleBinding {
	var out []port.RoleBinding
	for _, x := range r.t.s.roleBindings {
		if match(x) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r roleBindings) ListByPrincipal(_ context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.RoleBinding, error) {
	return r.list(func(x port.RoleBinding) bool {
		return x.RealmID == realmID && x.PrincipalType == t && x.PrincipalID == principalID
	}), nil
}

func (r roleBindings) ListByRole(_ context.Context, realmID, role string) ([]port.RoleBinding, error) {
	return r.list(func(x port.RoleBinding) bool { return x.RealmID == realmID && x.Role == role }), nil
}
