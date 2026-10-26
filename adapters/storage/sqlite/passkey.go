package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type passkeys struct{ q *db.Queries }

func toPasskey(r db.AuthnPasskey) (port.Passkey, error) {
	var p times
	var transports []string
	if err := json.Unmarshal([]byte(r.Transports), &transports); err != nil {
		return port.Passkey{}, fmt.Errorf("sqlite: passkey transports: %w", err)
	}
	if r.SignCount < 0 || r.SignCount > 1<<32-1 || r.Flags < 0 || r.Flags > 0xff {
		return port.Passkey{}, fmt.Errorf("sqlite: passkey %s: counter or flags out of range", r.ID)
	}
	k := port.Passkey{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, UserID: r.UserID, CredentialID: r.CredentialID,
		PublicKey: r.PublicKey, Alg: r.Alg, SignCount: uint32(r.SignCount), Flags: uint8(r.Flags), AAGUID: r.Aaguid,
		Transports: transports, Name: r.Name, CreatedAt: p.at(r.CreatedAt), LastUsedAt: p.null(r.LastUsedAt),
		RevokedAt: p.null(r.RevokedAt), RevokeReason: r.RevokeReason}
	return k, p.err
}

func (r passkeys) Create(ctx context.Context, k port.Passkey) error {
	n, err := r.q.IsPasskeyCredentialRevoked(ctx, db.IsPasskeyCredentialRevokedParams{RealmID: k.RealmID, CredentialID: k.CredentialID})
	if err != nil {
		return mapErr(err)
	}
	if n > 0 {
		return errs.New(errs.KindConflict, "passkey credential revoked")
	}
	transports := k.Transports
	if transports == nil {
		transports = []string{}
	}
	tj, err := json.Marshal(transports)
	if err != nil {
		return err
	}
	return mapErr(r.q.CreatePasskey(ctx, db.CreatePasskeyParams{ID: k.ID, PublicID: k.PublicID, RealmID: k.RealmID, UserID: k.UserID,
		CredentialID: k.CredentialID, PublicKey: k.PublicKey, Alg: k.Alg, SignCount: int64(k.SignCount), Flags: int64(k.Flags),
		Aaguid: append([]byte{}, k.AAGUID...), Transports: string(tj), Name: k.Name, CreatedAt: formatTime(k.CreatedAt),
		LastUsedAt: nullTime(k.LastUsedAt), RevokedAt: nullTime(k.RevokedAt), RevokeReason: k.RevokeReason}))
}

func (r passkeys) GetByCredentialID(ctx context.Context, realmID string, credentialID []byte) (port.Passkey, error) {
	row, err := r.q.GetPasskeyByCredentialID(ctx, db.GetPasskeyByCredentialIDParams{RealmID: realmID, CredentialID: credentialID})
	return one(row, err, toPasskey)
}

func (r passkeys) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Passkey, error) {
	row, err := r.q.GetPasskeyByPublicID(ctx, db.GetPasskeyByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toPasskey)
}

func (r passkeys) ListByUser(ctx context.Context, realmID, userID string) ([]port.Passkey, error) {
	rs, err := r.q.ListPasskeysByUser(ctx, db.ListPasskeysByUserParams{RealmID: realmID, UserID: userID})
	return rows(rs, err, toPasskey)
}

func (r passkeys) Used(ctx context.Context, realmID, id string, signCount uint32, flags uint8, at time.Time) error {
	n, err := r.q.UsePasskey(ctx, db.UsePasskeyParams{SignCount: int64(signCount), Flags: int64(flags), LastUsedAt: nullTime(&at), RealmID: realmID, ID: id})
	return affected(n, err, "passkey")
}

func (r passkeys) Rename(ctx context.Context, realmID, id, name string) error {
	n, err := r.q.RenamePasskey(ctx, db.RenamePasskeyParams{Name: name, RealmID: realmID, ID: id})
	return affected(n, err, "passkey")
}

func (r passkeys) Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error {
	k, err := r.q.GetPasskey(ctx, db.GetPasskeyParams{RealmID: realmID, ID: id})
	if err != nil {
		return mapErr(err)
	}
	if k.RevokedAt.Valid {
		return nil
	}
	if err := r.q.AddRevokedPasskeyCredential(ctx, db.AddRevokedPasskeyCredentialParams{RealmID: realmID, CredentialID: k.CredentialID, RevokedAt: formatTime(at)}); err != nil {
		return mapErr(err)
	}
	return mapErr(r.q.RevokePasskey(ctx, db.RevokePasskeyParams{RevokedAt: nullTime(&at), RevokeReason: reason, RealmID: realmID, ID: id}))
}
