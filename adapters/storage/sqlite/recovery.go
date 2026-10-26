package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type recoveryCodes struct{ q *db.Queries }

func toRecoveryCode(r db.AuthnRecoveryCode) (port.RecoveryCode, error) {
	var p times
	c := port.RecoveryCode{ID: r.ID, RealmID: r.RealmID, UserID: r.UserID, Lookup: r.Lookup, Hash: r.Hash,
		CreatedAt: p.at(r.CreatedAt), UsedAt: p.null(r.UsedAt)}
	return c, p.err
}

func (r recoveryCodes) Replace(ctx context.Context, realmID, userID string, codes []port.RecoveryCode) error {
	if err := r.q.DeleteRecoveryCodes(ctx, db.DeleteRecoveryCodesParams{RealmID: realmID, UserID: userID}); err != nil {
		return mapErr(err)
	}
	for _, c := range codes {
		if c.RealmID != realmID || c.UserID != userID {
			return errs.New(errs.KindConflict, "recovery code %s for another user", c.ID)
		}
		if err := r.q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{ID: c.ID, RealmID: c.RealmID, UserID: c.UserID,
			Lookup: c.Lookup, Hash: c.Hash, CreatedAt: formatTime(c.CreatedAt), UsedAt: nullTime(c.UsedAt)}); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (r recoveryCodes) ListByUser(ctx context.Context, realmID, userID string) ([]port.RecoveryCode, error) {
	rs, err := r.q.ListRecoveryCodes(ctx, db.ListRecoveryCodesParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toRecoveryCode)
}

func (r recoveryCodes) MarkUsed(ctx context.Context, realmID, id string, at time.Time) (bool, error) {
	n, err := r.q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{UsedAt: nullTime(&at), RealmID: realmID, ID: id})
	return n > 0, mapErr(err)
}
