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

// pats は本人の Personal Access Token と realm のポリシー（ADR 0109）。
type pats struct{ t *tx }

func clonePAT(p port.PersonalAccessToken) port.PersonalAccessToken {
	p.Scopes, p.Hash = slices.Clone(p.Scopes), bytes.Clone(p.Hash)
	p.ExpiresAt, p.LastUsedAt, p.RevokedAt = cloneTime(p.ExpiresAt), cloneTime(p.LastUsedAt), cloneTime(p.RevokedAt)
	return p
}

func patRealm(p port.PersonalAccessToken) string { return p.RealmID }

func (r pats) Create(_ context.Context, p port.PersonalAccessToken) error {
	if _, ok := r.t.s.pats[p.ID]; ok {
		return errs.New(errs.KindConflict, "personal access token %s exists", p.ID)
	}
	setKey(r.t, r.t.s.pats, p.ID, clonePAT(p))
	return nil
}

func (r pats) Get(_ context.Context, realmID, id string) (port.PersonalAccessToken, error) {
	p, err := get(r.t.s.pats, realmID, id, patRealm, "personal access token")
	return clonePAT(p), err
}

func (r pats) ListByUser(_ context.Context, realmID, userID string) ([]port.PersonalAccessToken, error) {
	var out []port.PersonalAccessToken
	for _, x := range r.t.s.pats {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, clonePAT(x))
		}
	}
	sortByCreated(out, func(x port.PersonalAccessToken) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r pats) Touch(_ context.Context, realmID, id string, at time.Time) error {
	p, err := get(r.t.s.pats, realmID, id, patRealm, "personal access token")
	if err != nil {
		return err
	}
	p = clonePAT(p)
	p.LastUsedAt = &at
	setKey(r.t, r.t.s.pats, id, p)
	return nil
}

func (r pats) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) (bool, error) {
	p, err := get(r.t.s.pats, realmID, id, patRealm, "personal access token")
	if err != nil || p.RevokedAt != nil {
		return false, err
	}
	p = clonePAT(p)
	p.RevokedAt, p.RevokeReason = &at, reason
	setKey(r.t, r.t.s.pats, id, p)
	return true, nil
}

func (r pats) RevokeByUser(_ context.Context, realmID, userID string, at time.Time, reason string) (int, error) {
	var keys []string
	for k, x := range r.t.s.pats {
		if x.RealmID == realmID && x.UserID == userID && x.RevokedAt == nil {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		p := clonePAT(r.t.s.pats[k])
		p.RevokedAt, p.RevokeReason = &at, reason
		setKey(r.t, r.t.s.pats, k, p)
	}
	return len(keys), nil
}

func (r pats) DeleteByUser(_ context.Context, realmID, userID string) (int, error) {
	var keys []string
	for k, x := range r.t.s.pats {
		if x.RealmID == realmID && x.UserID == userID {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.pats, k)
	}
	return len(keys), nil
}

func (r pats) GetPolicy(_ context.Context, realmID string) (port.PersonalAccessTokenPolicy, error) {
	p, ok := r.t.s.patPolicies[realmID]
	if !ok {
		return port.PersonalAccessTokenPolicy{}, errs.New(errs.KindNotFound, "personal access token policy %s", realmID)
	}
	p.AllowedScopes = slices.Clone(p.AllowedScopes)
	return p, nil
}

func (r pats) PutPolicy(_ context.Context, p port.PersonalAccessTokenPolicy) error {
	p.AllowedScopes = slices.Clone(p.AllowedScopes)
	if len(p.AllowedScopes) == 0 {
		p.AllowedScopes = nil
	}
	setKey(r.t, r.t.s.patPolicies, p.RealmID, p)
	return nil
}

func (r pats) Count(context.Context) (int, error) {
	return len(r.t.s.pats) + len(r.t.s.patPolicies), nil
}

func (r pats) Purge(_ context.Context, limit int) (int, error) {
	n := purgeSorted(r.t, r.t.s.pats, limit)
	return n + purgeSorted(r.t, r.t.s.patPolicies, limit-n), nil
}

// purgeSorted はキーの順に最大 limit 件消す。
func purgeSorted[V any](t *tx, m map[string]V, limit int) int {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:max(limit, 0)]
	}
	for _, k := range keys {
		deleteKey(t, m, k)
	}
	return len(keys)
}
