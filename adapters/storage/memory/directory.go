package memory

import (
	"context"
	"sort"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// ディレクトリの同期が管理する Group の対応（ADR 0102）。

type dirGroups struct{ t *tx }

func dirGroupKey(realmID, connectionID, externalKey string) string {
	return realmID + "\x00" + connectionID + "\x00" + externalKey
}

func (r dirGroups) Create(_ context.Context, g port.DirectoryGroup) error {
	for k, x := range r.t.s.dirGroups {
		if k == dirGroupKey(g.RealmID, g.ConnectionID, g.ExternalKey) || (x.RealmID == g.RealmID && x.GroupID == g.GroupID) {
			return errs.New(errs.KindConflict, "directory group exists")
		}
	}
	setKey(r.t, r.t.s.dirGroups, dirGroupKey(g.RealmID, g.ConnectionID, g.ExternalKey), g)
	return nil
}

func (r dirGroups) ListByConnection(_ context.Context, realmID, connectionID string) ([]port.DirectoryGroup, error) {
	var out []port.DirectoryGroup
	for _, x := range r.t.s.dirGroups {
		if x.RealmID == realmID && x.ConnectionID == connectionID {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExternalKey < out[j].ExternalKey })
	return out, nil
}

func (r dirGroups) Delete(_ context.Context, realmID, connectionID, externalKey string) error {
	k := dirGroupKey(realmID, connectionID, externalKey)
	if _, ok := r.t.s.dirGroups[k]; !ok {
		return errs.New(errs.KindNotFound, "directory group")
	}
	deleteKey(r.t, r.t.s.dirGroups, k)
	return nil
}

func (r dirGroups) DeleteByConnection(_ context.Context, realmID, connectionID string) (int, error) {
	n := 0
	eraseWhere(r.t, r.t.s.dirGroups, func(x port.DirectoryGroup) bool {
		ok := x.RealmID == realmID && x.ConnectionID == connectionID
		if ok {
			n++
		}
		return ok
	})
	return n, nil
}

func (r dirGroups) Count(context.Context) (int, error) { return len(r.t.s.dirGroups), nil }

func (r dirGroups) Purge(_ context.Context, limit int) (int, error) {
	keys := make([]string, 0, len(r.t.s.dirGroups))
	for k := range r.t.s.dirGroups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if limit >= 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.dirGroups, k)
	}
	return len(keys), nil
}
