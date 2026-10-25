package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func nullTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(*t), Valid: true}
}

// times は文字列の時刻をまとめて読む。最初のエラーを返す。
type times struct{ err error }

func (p *times) at(s string) time.Time {
	t, err := parseTime(s)
	if err != nil && p.err == nil {
		p.err = err
	}
	return t
}

func (p *times) null(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t := p.at(s.String)
	return &t
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// rows は sqlc の行の一覧を変換する。
func rows[R, V any](rs []R, err error, conv func(R) (V, error)) ([]V, error) {
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]V, 0, len(rs))
	for _, r := range rs {
		v, err := conv(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func one[R, V any](r R, err error, conv func(R) (V, error)) (V, error) {
	if err != nil {
		var zero V
		return zero, mapErr(err)
	}
	return conv(r)
}

// affected は更新した行が無ければ NotFound にする（別の realm の行も含む）。
func affected(n int64, err error, what string) error {
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "%s", what)
	}
	return nil
}

// ---------------------------------------------------------------------------

type users struct{ q *db.Queries }

func toUser(r db.AuthnUser) (port.User, error) {
	var p times
	u := port.User{ID: r.ID, RealmID: r.RealmID, Status: port.UserStatus(r.Status),
		ValidFrom: p.null(r.ValidFrom), ValidUntil: p.null(r.ValidUntil), CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	return u, p.err
}

func (r users) Create(ctx context.Context, u port.User) error {
	return mapErr(r.q.CreateUser(ctx, db.CreateUserParams{ID: u.ID, RealmID: u.RealmID, Status: string(u.Status),
		ValidFrom: nullTime(u.ValidFrom), ValidUntil: nullTime(u.ValidUntil), CreatedAt: formatTime(u.CreatedAt), UpdatedAt: formatTime(u.UpdatedAt)}))
}

func (r users) Get(ctx context.Context, realmID, id string) (port.User, error) {
	row, err := r.q.GetUser(ctx, db.GetUserParams{RealmID: realmID, ID: id})
	return one(row, err, toUser)
}

// ---------------------------------------------------------------------------

type emails struct{ q *db.Queries }

func toEmail(r db.AuthnUserEmail) (port.UserEmail, error) {
	var p times
	e := port.UserEmail{ID: r.ID, RealmID: r.RealmID, UserID: r.UserID, Ciphertext: r.Ciphertext, Index: r.EmailIndex,
		DomainIndex: r.DomainIndex, IndexKeyID: r.IndexKeyID, VerifiedAt: p.null(r.VerifiedAt), VerifiedVia: port.VerifiedVia(r.VerifiedVia),
		IsPrimary: r.IsPrimary != 0, CreatedAt: p.at(r.CreatedAt)}
	return e, p.err
}

func (r emails) Create(ctx context.Context, e port.UserEmail) error {
	return mapErr(r.q.CreateEmail(ctx, db.CreateEmailParams{ID: e.ID, RealmID: e.RealmID, UserID: e.UserID, Ciphertext: nonNil(e.Ciphertext),
		EmailIndex: nonNil(e.Index), DomainIndex: nonNil(e.DomainIndex), IndexKeyID: e.IndexKeyID, VerifiedAt: nullTime(e.VerifiedAt),
		VerifiedVia: string(e.VerifiedVia), IsPrimary: boolInt(e.IsPrimary), CreatedAt: formatTime(e.CreatedAt)}))
}

func (r emails) GetByIndex(ctx context.Context, realmID string, index []byte) (port.UserEmail, error) {
	row, err := r.q.GetEmailByIndex(ctx, db.GetEmailByIndexParams{RealmID: realmID, EmailIndex: nonNil(index)})
	return one(row, err, toEmail)
}

func (r emails) ListByUser(ctx context.Context, realmID, userID string) ([]port.UserEmail, error) {
	rs, err := r.q.ListEmailsByUser(ctx, db.ListEmailsByUserParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toEmail)
}

// ---------------------------------------------------------------------------

type identities struct{ q *db.Queries }

func toIdentity(r db.AuthnUserIdentity) (port.Identity, error) {
	var p times
	i := port.Identity{ID: r.ID, RealmID: r.RealmID, UserID: r.UserID, ConnectionID: r.ConnectionID, ProviderSubject: r.ProviderSubject,
		CreatedAt: p.at(r.CreatedAt), RevokedAt: p.null(r.RevokedAt)}
	return i, p.err
}

func (r identities) Create(ctx context.Context, i port.Identity) error {
	return mapErr(r.q.CreateIdentity(ctx, db.CreateIdentityParams{ID: i.ID, RealmID: i.RealmID, UserID: i.UserID, ConnectionID: i.ConnectionID,
		ProviderSubject: i.ProviderSubject, CreatedAt: formatTime(i.CreatedAt), RevokedAt: nullTime(i.RevokedAt)}))
}

func (r identities) GetBySubject(ctx context.Context, realmID, connectionID, subject string) (port.Identity, error) {
	row, err := r.q.GetIdentityBySubject(ctx, db.GetIdentityBySubjectParams{RealmID: realmID, ConnectionID: connectionID, ProviderSubject: subject})
	return one(row, err, toIdentity)
}

func (r identities) ListByUser(ctx context.Context, realmID, userID string) ([]port.Identity, error) {
	rs, err := r.q.ListIdentitiesByUser(ctx, db.ListIdentitiesByUserParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toIdentity)
}

// ---------------------------------------------------------------------------

type connections struct{ q *db.Queries }

func toConnection(r db.AuthnConnection) (port.Connection, error) {
	t, err := parseTime(r.CreatedAt)
	return port.Connection{ID: r.ID, RealmID: r.RealmID, Slug: r.Slug, Type: r.Type, Config: r.Config, CreatedAt: t}, err
}

func (r connections) Create(ctx context.Context, c port.Connection) error {
	return mapErr(r.q.CreateConnection(ctx, db.CreateConnectionParams{ID: c.ID, RealmID: c.RealmID, Slug: c.Slug, Type: c.Type,
		Config: nonNil(c.Config), CreatedAt: formatTime(c.CreatedAt)}))
}

func (r connections) Get(ctx context.Context, realmID, id string) (port.Connection, error) {
	row, err := r.q.GetConnection(ctx, db.GetConnectionParams{RealmID: realmID, ID: id})
	return one(row, err, toConnection)
}

func (r connections) GetBySlug(ctx context.Context, realmID, slug string) (port.Connection, error) {
	row, err := r.q.GetConnectionBySlug(ctx, db.GetConnectionBySlugParams{RealmID: realmID, Slug: slug})
	return one(row, err, toConnection)
}

func (r connections) List(ctx context.Context, realmID string) ([]port.Connection, error) {
	rs, err := r.q.ListConnections(ctx, realmID)
	return rows(rs, err, toConnection)
}

// ---------------------------------------------------------------------------

type sessions struct{ q *db.Queries }

func toSession(r db.AuthnSession) (port.Session, error) {
	var p times
	s := port.Session{ID: r.ID, RealmID: r.RealmID, PrincipalType: port.PrincipalType(r.PrincipalType), PrincipalID: r.PrincipalID,
		ActiveOrgID: r.ActiveOrgID, TokenHash: r.TokenHash, Warnings: r.Warnings, IP: r.Ip, UserAgent: r.UserAgent,
		AuthenticatedAt: p.at(r.AuthenticatedAt), CreatedAt: p.at(r.CreatedAt), LastSeenAt: p.at(r.LastSeenAt), ExpiresAt: p.at(r.ExpiresAt), RevokedAt: p.null(r.RevokedAt),
		RevokeReason: r.RevokeReason}
	if p.err != nil {
		return s, p.err
	}
	if err := json.Unmarshal([]byte(r.AuthMethods), &s.AuthMethods); err != nil {
		return s, err
	}
	return s, json.Unmarshal([]byte(r.AuthCredentialIds), &s.AuthCredentialIDs)
}

func jsonList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func (r sessions) Create(ctx context.Context, s port.Session) error {
	return mapErr(r.q.CreateSession(ctx, db.CreateSessionParams{ID: s.ID, RealmID: s.RealmID, PrincipalType: string(s.PrincipalType),
		PrincipalID: s.PrincipalID, ActiveOrgID: s.ActiveOrgID, TokenHash: nonNil(s.TokenHash), AuthMethods: jsonList(s.AuthMethods),
		AuthCredentialIds: jsonList(s.AuthCredentialIDs), Warnings: nonNil(s.Warnings), Ip: nonNil(s.IP), UserAgent: nonNil(s.UserAgent),
		AuthenticatedAt: formatTime(s.AuthenticatedAt), CreatedAt: formatTime(s.CreatedAt), LastSeenAt: formatTime(s.LastSeenAt), ExpiresAt: formatTime(s.ExpiresAt),
		RevokedAt: nullTime(s.RevokedAt), RevokeReason: s.RevokeReason}))
}

func (r sessions) Get(ctx context.Context, realmID, id string) (port.Session, error) {
	row, err := r.q.GetSession(ctx, db.GetSessionParams{RealmID: realmID, ID: id})
	return one(row, err, toSession)
}

func (r sessions) ListByPrincipal(ctx context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.Session, error) {
	rs, err := r.q.ListSessionsByPrincipal(ctx, db.ListSessionsByPrincipalParams{RealmID: realmID, PrincipalType: string(t), PrincipalID: principalID})
	return rows(rs, err, toSession)
}

func (r sessions) Touch(ctx context.Context, realmID, id string, at time.Time) error {
	n, err := r.q.TouchSession(ctx, db.TouchSessionParams{At: formatTime(at), RealmID: realmID, ID: id})
	return affected(n, err, "session")
}

func (r sessions) Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error {
	n, err := r.q.RevokeSession(ctx, db.RevokeSessionParams{At: nullTime(&at), Reason: reason, RealmID: realmID, ID: id})
	return affected(n, err, "session")
}

func (r sessions) RevokeByPrincipal(ctx context.Context, realmID string, t port.PrincipalType, principalID, exceptID string, at time.Time, reason string) ([]string, error) {
	ids, err := r.q.RevokeSessionsByPrincipal(ctx, db.RevokeSessionsByPrincipalParams{At: nullTime(&at), Reason: reason, RealmID: realmID,
		PrincipalType: string(t), PrincipalID: principalID, ExceptID: exceptID})
	return ids, mapErr(err)
}

// ---------------------------------------------------------------------------

type accounts struct{ q *db.Queries }

func toCredential(r db.AuthnServiceAccountCredential) (port.ServiceAccountCredential, error) {
	var p times
	c := port.ServiceAccountCredential{ID: r.ID, RealmID: r.RealmID, ServiceAccountID: r.ServiceAccountID, Type: r.Type,
		SecretHash: r.SecretHash, CreatedAt: p.at(r.CreatedAt), ExpiresAt: p.null(r.ExpiresAt), RevokedAt: p.null(r.RevokedAt)}
	return c, p.err
}

func (r accounts) Create(ctx context.Context, a port.ServiceAccount) error {
	return mapErr(r.q.CreateServiceAccount(ctx, db.CreateServiceAccountParams{ID: a.ID, RealmID: a.RealmID, Name: a.Name, CreatedAt: formatTime(a.CreatedAt)}))
}

func (r accounts) Get(ctx context.Context, realmID, id string) (port.ServiceAccount, error) {
	row, err := r.q.GetServiceAccount(ctx, db.GetServiceAccountParams{RealmID: realmID, ID: id})
	return one(row, err, func(r db.AuthnServiceAccount) (port.ServiceAccount, error) {
		t, err := parseTime(r.CreatedAt)
		return port.ServiceAccount{ID: r.ID, RealmID: r.RealmID, Name: r.Name, CreatedAt: t}, err
	})
}

func (r accounts) CreateCredential(ctx context.Context, c port.ServiceAccountCredential) error {
	// 同じ realm のサービスアカウントにだけ付ける。
	if _, err := r.Get(ctx, c.RealmID, c.ServiceAccountID); err != nil {
		return err
	}
	return mapErr(r.q.CreateServiceAccountCredential(ctx, db.CreateServiceAccountCredentialParams{ID: c.ID, RealmID: c.RealmID,
		ServiceAccountID: c.ServiceAccountID, Type: c.Type, SecretHash: nonNil(c.SecretHash), CreatedAt: formatTime(c.CreatedAt),
		ExpiresAt: nullTime(c.ExpiresAt), RevokedAt: nullTime(c.RevokedAt)}))
}

func (r accounts) GetCredential(ctx context.Context, realmID, id string) (port.ServiceAccountCredential, error) {
	row, err := r.q.GetServiceAccountCredential(ctx, db.GetServiceAccountCredentialParams{RealmID: realmID, ID: id})
	return one(row, err, toCredential)
}

func (r accounts) RevokeCredential(ctx context.Context, realmID, id string, at time.Time) error {
	n, err := r.q.RevokeServiceAccountCredential(ctx, db.RevokeServiceAccountCredentialParams{At: nullTime(&at), RealmID: realmID, ID: id})
	return affected(n, err, "credential")
}

// ---------------------------------------------------------------------------

type roleBindings struct{ q *db.Queries }

func toRoleBinding(r db.AuthzRoleBinding) (port.RoleBinding, error) {
	t, err := parseTime(r.CreatedAt)
	return port.RoleBinding{ID: r.ID, RealmID: r.RealmID, Role: r.Role, PrincipalType: port.PrincipalType(r.PrincipalType),
		PrincipalID: r.PrincipalID, OrgID: r.OrgID, CreatedAt: t}, err
}

func (r roleBindings) Create(ctx context.Context, b port.RoleBinding) error {
	return mapErr(r.q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: b.ID, RealmID: b.RealmID, Role: b.Role,
		PrincipalType: string(b.PrincipalType), PrincipalID: b.PrincipalID, OrgID: b.OrgID, CreatedAt: formatTime(b.CreatedAt)}))
}

func (r roleBindings) ListByPrincipal(ctx context.Context, realmID string, t port.PrincipalType, principalID string) ([]port.RoleBinding, error) {
	rs, err := r.q.ListRoleBindingsByPrincipal(ctx, db.ListRoleBindingsByPrincipalParams{RealmID: realmID, PrincipalType: string(t), PrincipalID: principalID})
	return rows(rs, err, toRoleBinding)
}

func (r roleBindings) ListByRole(ctx context.Context, realmID, role string) ([]port.RoleBinding, error) {
	rs, err := r.q.ListRoleBindingsByRole(ctx, db.ListRoleBindingsByRoleParams{RealmID: realmID, Role: role})
	return rows(rs, err, toRoleBinding)
}
