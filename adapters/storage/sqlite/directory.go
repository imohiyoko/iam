package sqlite

import (
	"context"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// dirGroups はディレクトリの同期が管理する Group の対応（authn_directory_groups。ADR 0102）。
type dirGroups struct{ q *db.Queries }

func toDirectoryGroup(r db.AuthnDirectoryGroup) (port.DirectoryGroup, error) {
	var p times
	g := port.DirectoryGroup{RealmID: r.RealmID, ConnectionID: r.ConnectionID, ExternalKey: r.ExternalKey, GroupID: r.GroupID, CreatedAt: p.at(r.CreatedAt)}
	return g, p.err
}

func (r dirGroups) Create(ctx context.Context, g port.DirectoryGroup) error {
	return mapErr(r.q.CreateDirectoryGroup(ctx, db.CreateDirectoryGroupParams{RealmID: g.RealmID, ConnectionID: g.ConnectionID,
		ExternalKey: g.ExternalKey, GroupID: g.GroupID, CreatedAt: formatTime(g.CreatedAt)}))
}

func (r dirGroups) ListByConnection(ctx context.Context, realmID, connectionID string) ([]port.DirectoryGroup, error) {
	rs, err := r.q.ListDirectoryGroupsByConnection(ctx, db.ListDirectoryGroupsByConnectionParams{RealmID: realmID, ConnectionID: connectionID})
	return rows(rs, err, toDirectoryGroup)
}

func (r dirGroups) Delete(ctx context.Context, realmID, connectionID, externalKey string) error {
	n, err := r.q.DeleteDirectoryGroup(ctx, db.DeleteDirectoryGroupParams{RealmID: realmID, ConnectionID: connectionID, ExternalKey: externalKey})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "directory group")
	}
	return nil
}

func (r dirGroups) DeleteByConnection(ctx context.Context, realmID, connectionID string) (int, error) {
	n, err := r.q.DeleteDirectoryGroupsByConnection(ctx, db.DeleteDirectoryGroupsByConnectionParams{RealmID: realmID, ConnectionID: connectionID})
	return int(n), mapErr(err)
}

func (r dirGroups) Count(ctx context.Context) (int, error) {
	n, err := r.q.CountDirectoryGroups(ctx)
	return int(n), mapErr(err)
}

func (r dirGroups) Purge(ctx context.Context, limit int) (int, error) {
	n, err := r.q.PurgeDirectoryGroups(ctx, int64(limit))
	return int(n), mapErr(err)
}

func (r identities) ListActiveByConnection(ctx context.Context, realmID, connectionID, afterID string, limit int) ([]port.Identity, error) {
	rs, err := r.q.ListActiveIdentitiesByConnection(ctx, db.ListActiveIdentitiesByConnectionParams{RealmID: realmID, ConnectionID: connectionID,
		After: afterID, Lim: int64(limit)})
	return rows(rs, err, toIdentity)
}
