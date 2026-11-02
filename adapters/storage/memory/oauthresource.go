package memory

import (
	"context"
	"slices"
	"sort"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 自前の API（リソースサーバー）の登録（RFC 8707、ADR 0112）。

type oauthResources struct{ t *tx }

func oauthResourceKey(realmID, id string) string { return realmID + "\x00" + id }

func cloneOAuthResource(r port.OAuthResource) port.OAuthResource {
	r.Scopes, r.Clients, r.ServiceAccounts = nonNilList(r.Scopes), nonNilList(r.Clients), nonNilList(r.ServiceAccounts)
	return r
}

func nonNilList(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

func (r oauthResources) conflict(x port.OAuthResource) bool {
	for _, o := range r.t.s.oauthResources {
		if o.RealmID == x.RealmID && o.URI == x.URI && o.ID != x.ID {
			return true
		}
	}
	return false
}

func (r oauthResources) Create(_ context.Context, x port.OAuthResource) error {
	for _, o := range r.t.s.oauthResources {
		if o.ID == x.ID {
			return errs.New(errs.KindConflict, "oauth resource exists")
		}
	}
	if r.conflict(x) {
		return errs.New(errs.KindConflict, "oauth resource exists")
	}
	setKey(r.t, r.t.s.oauthResources, oauthResourceKey(x.RealmID, x.ID), cloneOAuthResource(x))
	return nil
}

func (r oauthResources) Get(_ context.Context, realmID, id string) (port.OAuthResource, error) {
	x, ok := r.t.s.oauthResources[oauthResourceKey(realmID, id)]
	if !ok {
		return port.OAuthResource{}, errs.New(errs.KindNotFound, "oauth resource")
	}
	return cloneOAuthResource(x), nil
}

func (r oauthResources) GetByURI(_ context.Context, realmID, uri string) (port.OAuthResource, error) {
	for _, x := range r.t.s.oauthResources {
		if x.RealmID == realmID && x.URI == uri {
			return cloneOAuthResource(x), nil
		}
	}
	return port.OAuthResource{}, errs.New(errs.KindNotFound, "oauth resource")
}

func (r oauthResources) List(_ context.Context, realmID string) ([]port.OAuthResource, error) {
	out := []port.OAuthResource{}
	for _, x := range r.t.s.oauthResources {
		if x.RealmID == realmID {
			out = append(out, cloneOAuthResource(x))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (r oauthResources) Update(_ context.Context, x port.OAuthResource) error {
	k := oauthResourceKey(x.RealmID, x.ID)
	old, ok := r.t.s.oauthResources[k]
	if !ok {
		return errs.New(errs.KindNotFound, "oauth resource")
	}
	if r.conflict(x) {
		return errs.New(errs.KindConflict, "oauth resource exists")
	}
	x.CreatedAt = old.CreatedAt
	setKey(r.t, r.t.s.oauthResources, k, cloneOAuthResource(x))
	return nil
}

func (r oauthResources) Delete(_ context.Context, realmID, id string) error {
	k := oauthResourceKey(realmID, id)
	if _, ok := r.t.s.oauthResources[k]; !ok {
		return errs.New(errs.KindNotFound, "oauth resource")
	}
	deleteKey(r.t, r.t.s.oauthResources, k)
	return nil
}

func (r oauthResources) Count(context.Context) (int, error) { return len(r.t.s.oauthResources), nil }

func (r oauthResources) Purge(_ context.Context, limit int) (int, error) {
	return purgeKeys(r.t, r.t.s.oauthResources, limit), nil
}
