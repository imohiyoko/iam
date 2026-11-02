package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// credentials は汎用の認証情報（authn_credentials。ADR 0092）。
type authnCredentials struct{ q *db.Queries }

func toAuthnCredential(r db.AuthnCredential) (port.Credential, error) {
	var p times
	c := port.Credential{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, UserID: r.UserID, Method: r.Method, Lookup: lookupOrNil(r.Lookup), LookupKeyID: r.LookupKeyID,
		Data: r.Data, DataVersion: int(r.DataVersion), CreatedAt: p.at(r.CreatedAt), LastUsedAt: p.null(r.LastUsedAt),
		RevokedAt: p.null(r.RevokedAt), RevokeReason: r.RevokeReason, PreferredOrgID: r.PreferredOrgID, ReserveLookup: r.ReserveLookup != 0}
	return c, p.err
}

// lookupOrNil は空の検索キーを nil（NULL）にする。NULL は一意の制約の対象にならない。
func lookupOrNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (r authnCredentials) Create(ctx context.Context, c port.Credential) error {
	// 退役した検索キー（ADR 0106）は、無効化していないものとしては作れない。トランザクションは直列なので、数えてから作ってよい。
	if len(c.Lookup) > 0 && c.RevokedAt == nil {
		if retired, err := r.LookupRetired(ctx, c.RealmID, c.Method, c.Lookup); err != nil {
			return err
		} else if retired {
			return errs.New(errs.KindConflict, "credential lookup retired")
		}
	}
	return mapErr(r.q.CreateCredential(ctx, db.CreateCredentialParams{ID: c.ID, PublicID: c.PublicID, RealmID: c.RealmID, UserID: c.UserID,
		Method: c.Method, Lookup: lookupOrNil(c.Lookup), LookupKeyID: c.LookupKeyID, Data: nonNil(c.Data), DataVersion: int64(c.DataVersion), CreatedAt: formatTime(c.CreatedAt),
		LastUsedAt: nullTime(c.LastUsedAt), RevokedAt: nullTime(c.RevokedAt), RevokeReason: c.RevokeReason, PreferredOrgID: c.PreferredOrgID,
		ReserveLookup: boolInt(c.ReserveLookup)}))
}

func (r authnCredentials) Get(ctx context.Context, realmID, id string) (port.Credential, error) {
	row, err := r.q.GetCredential(ctx, db.GetCredentialParams{RealmID: realmID, ID: id})
	return one(row, err, toAuthnCredential)
}

func (r authnCredentials) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Credential, error) {
	row, err := r.q.GetCredentialByPublicID(ctx, db.GetCredentialByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toAuthnCredential)
}

func (r authnCredentials) GetByLookup(ctx context.Context, realmID, method string, lookup []byte) (port.Credential, error) {
	if len(lookup) == 0 {
		return port.Credential{}, errs.New(errs.KindNotFound, "credential")
	}
	row, err := r.q.GetCredentialByLookup(ctx, db.GetCredentialByLookupParams{RealmID: realmID, Method: method, Lookup: lookup})
	return one(row, err, toAuthnCredential)
}

func (r authnCredentials) LookupKeyIDs(ctx context.Context, realmID, method string) ([]string, error) {
	ids, err := r.q.ListCredentialLookupKeys(ctx, db.ListCredentialLookupKeysParams{RealmID: realmID, Method: method})
	return ids, mapErr(err)
}

func (r authnCredentials) ListByUser(ctx context.Context, realmID, userID, method string) ([]port.Credential, error) {
	if method == "" {
		rs, err := r.q.ListCredentialsByUser(ctx, db.ListCredentialsByUserParams{RealmID: realmID, UserID: userID})
		return rows(rs, err, toAuthnCredential)
	}
	rs, err := r.q.ListCredentialsByUserMethod(ctx, db.ListCredentialsByUserMethodParams{RealmID: realmID, UserID: userID, Method: method})
	return rows(rs, err, toAuthnCredential)
}

func (r authnCredentials) UpdateData(ctx context.Context, realmID, id string, old, data []byte, dataVersion int) error {
	n, err := r.q.UpdateCredentialData(ctx, db.UpdateCredentialDataParams{Data: nonNil(data), DataVersion: int64(dataVersion),
		RealmID: realmID, ID: id, Old: nonNil(old)})
	if err != nil {
		return mapErr(err)
	}
	if n > 0 {
		return nil
	}
	if _, err := r.q.GetCredential(ctx, db.GetCredentialParams{RealmID: realmID, ID: id}); err != nil {
		return mapErr(err)
	}
	return errs.New(errs.KindConflict, "credential data changed")
}

func (r authnCredentials) Used(ctx context.Context, realmID, id string, at time.Time) error {
	n, err := r.q.UseCredential(ctx, db.UseCredentialParams{LastUsedAt: nullTime(&at), RealmID: realmID, ID: id})
	return affected(n, err, "credential")
}

func (r authnCredentials) Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error {
	c, err := r.q.GetCredential(ctx, db.GetCredentialParams{RealmID: realmID, ID: id})
	if err != nil {
		return mapErr(err)
	}
	if c.RevokedAt.Valid {
		return nil
	}
	if c.ReserveLookup != 0 && len(c.Lookup) > 0 {
		if err := r.Retire(ctx, port.RetiredLookup{RealmID: realmID, Method: c.Method, Lookup: c.Lookup, LookupKeyID: c.LookupKeyID, RetiredAt: at}); err != nil {
			return err
		}
	}
	return mapErr(r.q.RevokeCredential(ctx, db.RevokeCredentialParams{RevokedAt: nullTime(&at), RevokeReason: reason, RealmID: realmID, ID: id}))
}

func (r authnCredentials) SetPreferredOrg(ctx context.Context, realmID, id, orgID string) error {
	n, err := r.q.SetCredentialPreferredOrg(ctx, db.SetCredentialPreferredOrgParams{PreferredOrgID: orgID, RealmID: realmID, ID: id})
	return affected(n, err, "credential")
}

func (r authnCredentials) Retire(ctx context.Context, x port.RetiredLookup) error {
	if len(x.Lookup) == 0 {
		return errs.New(errs.KindInvalid, "retired lookup is empty")
	}
	return mapErr(r.q.RetireCredentialLookup(ctx, db.RetireCredentialLookupParams{RealmID: x.RealmID, Method: x.Method, Lookup: x.Lookup,
		LookupKeyID: x.LookupKeyID, RetiredAt: formatTime(x.RetiredAt)}))
}

func (r authnCredentials) LookupRetired(ctx context.Context, realmID, method string, lookup []byte) (bool, error) {
	if len(lookup) == 0 {
		return false, nil
	}
	n, err := r.q.CountRetiredCredentialLookup(ctx, db.CountRetiredCredentialLookupParams{RealmID: realmID, Method: method, Lookup: lookup})
	return n > 0, mapErr(err)
}

func (r authnCredentials) RetiredLookupKeyIDs(ctx context.Context, realmID, method string) ([]string, error) {
	ids, err := r.q.ListRetiredCredentialLookupKeys(ctx, db.ListRetiredCredentialLookupKeysParams{RealmID: realmID, Method: method})
	return ids, mapErr(err)
}

func (r authnCredentials) MoveUser(ctx context.Context, realmID, fromUserID, toUserID string) (int, error) {
	n, err := r.q.MoveCredentials(ctx, db.MoveCredentialsParams{ToUserID: toUserID, RealmID: realmID, FromUserID: fromUserID})
	return int(n), mapErr(err)
}

func (r authnCredentials) Count(ctx context.Context, method string) (int, error) {
	n, err := r.q.CountCredentials(ctx, method)
	return int(n), mapErr(err)
}

func (r authnCredentials) Purge(ctx context.Context, method string, limit int) (int, error) {
	n, err := r.q.PurgeCredentials(ctx, db.PurgeCredentialsParams{Method: method, Lim: int64(limit)})
	return int(n), mapErr(err)
}
