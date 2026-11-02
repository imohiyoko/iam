package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/port"
)

// pats は本人の Personal Access Token と realm のポリシー（authn_personal_access_tokens・authn_personal_access_token_policies。ADR 0109）。
type pats struct{ q *db.Queries }

func toPAT(r db.AuthnPersonalAccessToken) (port.PersonalAccessToken, error) {
	var p times
	t := port.PersonalAccessToken{ID: r.ID, RealmID: r.RealmID, UserID: r.UserID, Name: r.Name, Hash: r.TokenHash,
		CreatedAt: p.at(r.CreatedAt), ExpiresAt: p.null(r.ExpiresAt), LastUsedAt: p.null(r.LastUsedAt), RevokedAt: p.null(r.RevokedAt),
		RevokeReason: r.RevokeReason}
	if p.err != nil {
		return t, p.err
	}
	return t, json.Unmarshal([]byte(r.Scopes), &t.Scopes)
}

func (r pats) Create(ctx context.Context, t port.PersonalAccessToken) error {
	return mapErr(r.q.CreatePAT(ctx, db.CreatePATParams{ID: t.ID, RealmID: t.RealmID, UserID: t.UserID, Name: t.Name, Scopes: jsonList(t.Scopes),
		TokenHash: nonNil(t.Hash), CreatedAt: formatTime(t.CreatedAt), ExpiresAt: nullTime(t.ExpiresAt), LastUsedAt: nullTime(t.LastUsedAt),
		RevokedAt: nullTime(t.RevokedAt), RevokeReason: t.RevokeReason}))
}

func (r pats) Get(ctx context.Context, realmID, id string) (port.PersonalAccessToken, error) {
	row, err := r.q.GetPAT(ctx, db.GetPATParams{RealmID: realmID, ID: id})
	return one(row, err, toPAT)
}

func (r pats) ListByUser(ctx context.Context, realmID, userID string) ([]port.PersonalAccessToken, error) {
	rs, err := r.q.ListPATsByUser(ctx, db.ListPATsByUserParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toPAT)
}

func (r pats) Touch(ctx context.Context, realmID, id string, at time.Time) error {
	n, err := r.q.TouchPAT(ctx, db.TouchPATParams{LastUsedAt: nullTime(&at), RealmID: realmID, ID: id})
	return affected(n, err, "personal access token")
}

func (r pats) Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) (bool, error) {
	n, err := r.q.RevokePAT(ctx, db.RevokePATParams{RevokedAt: nullTime(&at), RevokeReason: reason, RealmID: realmID, ID: id})
	if err != nil {
		return false, mapErr(err)
	}
	if n > 0 {
		return true, nil
	}
	// 無いのか、もう取り消したのかを分ける。
	_, err = r.Get(ctx, realmID, id)
	return false, err
}

func (r pats) RevokeByUser(ctx context.Context, realmID, userID string, at time.Time, reason string) (int, error) {
	n, err := r.q.RevokePATsByUser(ctx, db.RevokePATsByUserParams{RevokedAt: nullTime(&at), RevokeReason: reason, RealmID: realmID, UserID: userID})
	return int(n), mapErr(err)
}

func (r pats) DeleteByUser(ctx context.Context, realmID, userID string) (int, error) {
	n, err := r.q.DeletePATsByUser(ctx, db.DeletePATsByUserParams{RealmID: realmID, UserID: userID})
	return int(n), mapErr(err)
}

func toPATPolicy(r db.AuthnPersonalAccessTokenPolicy) (port.PersonalAccessTokenPolicy, error) {
	var p times
	out := port.PersonalAccessTokenPolicy{RealmID: r.RealmID, MaxLifetimeSeconds: r.MaxLifetimeSeconds, RequireExpiry: r.RequireExpiry != 0,
		UpdatedAt: p.at(r.UpdatedAt)}
	if p.err != nil {
		return out, p.err
	}
	if err := json.Unmarshal([]byte(r.AllowedScopes), &out.AllowedScopes); err != nil {
		return out, err
	}
	if len(out.AllowedScopes) == 0 {
		out.AllowedScopes = nil
	}
	return out, nil
}

func (r pats) GetPolicy(ctx context.Context, realmID string) (port.PersonalAccessTokenPolicy, error) {
	row, err := r.q.GetPATPolicy(ctx, realmID)
	return one(row, err, toPATPolicy)
}

func (r pats) PutPolicy(ctx context.Context, p port.PersonalAccessTokenPolicy) error {
	return mapErr(r.q.PutPATPolicy(ctx, db.PutPATPolicyParams{RealmID: p.RealmID, MaxLifetimeSeconds: p.MaxLifetimeSeconds,
		AllowedScopes: jsonList(p.AllowedScopes), RequireExpiry: boolInt(p.RequireExpiry), UpdatedAt: formatTime(p.UpdatedAt)}))
}

func (r pats) Count(ctx context.Context) (int, error) {
	n, err := r.q.CountPATs(ctx)
	if err != nil {
		return 0, mapErr(err)
	}
	m, err := r.q.CountPATPolicies(ctx)
	return int(n + m), mapErr(err)
}

func (r pats) Purge(ctx context.Context, limit int) (int, error) {
	n, err := r.q.PurgePATs(ctx, int64(limit))
	if err != nil || int(n) >= limit {
		return int(n), mapErr(err)
	}
	m, err := r.q.PurgePATPolicies(ctx, int64(limit)-n)
	return int(n + m), mapErr(err)
}
