package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type passwords struct{ q *db.Queries }

func toPassword(r db.AuthnPasswordCredential) (port.PasswordCredential, error) {
	var p times
	c := port.PasswordCredential{ID: r.ID, RealmID: r.RealmID, UserID: r.UserID, Hash: r.Hash, CreatedAt: p.at(r.CreatedAt),
		RevokedAt: p.null(r.RevokedAt), RevokeReason: r.RevokeReason}
	return c, p.err
}

func (r passwords) Create(ctx context.Context, c port.PasswordCredential) error {
	return mapErr(r.q.CreatePassword(ctx, db.CreatePasswordParams{ID: c.ID, RealmID: c.RealmID, UserID: c.UserID, Hash: c.Hash,
		CreatedAt: formatTime(c.CreatedAt), RevokedAt: nullTime(c.RevokedAt), RevokeReason: c.RevokeReason}))
}

func (r passwords) Get(ctx context.Context, realmID, id string) (port.PasswordCredential, error) {
	row, err := r.q.GetPassword(ctx, db.GetPasswordParams{RealmID: realmID, ID: id})
	return one(row, err, toPassword)
}

func (r passwords) GetActive(ctx context.Context, realmID, userID string) (port.PasswordCredential, error) {
	row, err := r.q.GetActivePassword(ctx, db.GetActivePasswordParams{RealmID: realmID, UserID: userID})
	return one(row, err, toPassword)
}

func (r passwords) UpdateHash(ctx context.Context, realmID, id, hash string) error {
	n, err := r.q.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{Hash: hash, RealmID: realmID, ID: id})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "password")
	}
	return nil
}

func (r passwords) Count(ctx context.Context) (int, error) {
	n, err := r.q.CountPasswords(ctx)
	return int(n), mapErr(err)
}

func (r passwords) Purge(ctx context.Context, limit int) (int, error) {
	n, err := r.q.PurgePasswords(ctx, int64(limit))
	return int(n), mapErr(err)
}

func (r passwords) Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error {
	if _, err := r.q.GetPassword(ctx, db.GetPasswordParams{RealmID: realmID, ID: id}); err != nil {
		return mapErr(err)
	}
	return mapErr(r.q.RevokePassword(ctx, db.RevokePasswordParams{RevokedAt: nullTime(&at), RevokeReason: reason, RealmID: realmID, ID: id}))
}
