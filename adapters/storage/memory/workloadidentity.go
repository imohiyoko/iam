package memory

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Workload Identity Federation の発行者と結び付け（ADR 0116）。

type workloadIdentity struct{ t *tx }

// wiTokenPrefix は結び付けで発行したアクセストークンの CredentialID の接頭辞。
const wiTokenPrefix = string(id.WorkloadIdentityBinding) + "_"

func cloneWIProvider(p port.WorkloadIdentityProvider) port.WorkloadIdentityProvider {
	p.Config = bytes.Clone(p.Config)
	if p.Config == nil {
		p.Config = []byte{}
	}
	return p
}

func cloneWIBinding(b port.WorkloadIdentityBinding) port.WorkloadIdentityBinding {
	b.Conditions = bytes.Clone(b.Conditions)
	if b.Conditions == nil {
		b.Conditions = []byte{}
	}
	return b
}

func (r workloadIdentity) CreateProvider(_ context.Context, p port.WorkloadIdentityProvider) error {
	for _, x := range r.t.s.wiProviders {
		if x.ID == p.ID || (x.RealmID == p.RealmID && x.Issuer == p.Issuer) {
			return errs.New(errs.KindConflict, "workload identity provider exists")
		}
	}
	setKey(r.t, r.t.s.wiProviders, wsfedRPKey(p.RealmID, p.ID), cloneWIProvider(p))
	return nil
}

func (r workloadIdentity) GetProvider(_ context.Context, realmID, id string) (port.WorkloadIdentityProvider, error) {
	x, ok := r.t.s.wiProviders[wsfedRPKey(realmID, id)]
	if !ok {
		return port.WorkloadIdentityProvider{}, errs.New(errs.KindNotFound, "workload identity provider")
	}
	return cloneWIProvider(x), nil
}

func (r workloadIdentity) GetProviderByIssuer(_ context.Context, realmID, issuer string) (port.WorkloadIdentityProvider, error) {
	for _, x := range r.t.s.wiProviders {
		if x.RealmID == realmID && x.Issuer == issuer {
			return cloneWIProvider(x), nil
		}
	}
	return port.WorkloadIdentityProvider{}, errs.New(errs.KindNotFound, "workload identity provider")
}

func (r workloadIdentity) ListProviders(_ context.Context, realmID string) ([]port.WorkloadIdentityProvider, error) {
	out := []port.WorkloadIdentityProvider{}
	for _, x := range r.t.s.wiProviders {
		if x.RealmID == realmID {
			out = append(out, cloneWIProvider(x))
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

func (r workloadIdentity) UpdateProvider(_ context.Context, p port.WorkloadIdentityProvider) error {
	k := wsfedRPKey(p.RealmID, p.ID)
	old, ok := r.t.s.wiProviders[k]
	if !ok {
		return errs.New(errs.KindNotFound, "workload identity provider")
	}
	for _, x := range r.t.s.wiProviders {
		if x.ID != p.ID && x.RealmID == p.RealmID && x.Issuer == p.Issuer {
			return errs.New(errs.KindConflict, "workload identity provider exists")
		}
	}
	p = cloneWIProvider(p)
	p.CreatedAt = old.CreatedAt
	setKey(r.t, r.t.s.wiProviders, k, p)
	return nil
}

func (r workloadIdentity) DeleteProvider(_ context.Context, realmID, id string) error {
	k := wsfedRPKey(realmID, id)
	if _, ok := r.t.s.wiProviders[k]; !ok {
		return errs.New(errs.KindNotFound, "workload identity provider")
	}
	for bk, b := range r.t.s.wiBindings {
		if b.RealmID == realmID && b.ProviderID == id {
			deleteKey(r.t, r.t.s.wiBindings, bk)
		}
	}
	deleteKey(r.t, r.t.s.wiProviders, k)
	return nil
}

func (r workloadIdentity) CreateBinding(_ context.Context, b port.WorkloadIdentityBinding) error {
	for _, x := range r.t.s.wiBindings {
		if x.ID == b.ID {
			return errs.New(errs.KindConflict, "workload identity binding exists")
		}
	}
	setKey(r.t, r.t.s.wiBindings, wsfedRPKey(b.RealmID, b.ID), cloneWIBinding(b))
	return nil
}

func (r workloadIdentity) GetBinding(_ context.Context, realmID, id string) (port.WorkloadIdentityBinding, error) {
	x, ok := r.t.s.wiBindings[wsfedRPKey(realmID, id)]
	if !ok {
		return port.WorkloadIdentityBinding{}, errs.New(errs.KindNotFound, "workload identity binding")
	}
	return cloneWIBinding(x), nil
}

func (r workloadIdentity) ListBindings(_ context.Context, realmID, providerID string) ([]port.WorkloadIdentityBinding, error) {
	out := []port.WorkloadIdentityBinding{}
	for _, x := range r.t.s.wiBindings {
		if x.RealmID == realmID && x.ProviderID == providerID {
			out = append(out, cloneWIBinding(x))
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

func (r workloadIdentity) DeleteBinding(_ context.Context, realmID, id string) error {
	k := wsfedRPKey(realmID, id)
	if _, ok := r.t.s.wiBindings[k]; !ok {
		return errs.New(errs.KindNotFound, "workload identity binding")
	}
	deleteKey(r.t, r.t.s.wiBindings, k)
	return nil
}

// tokenIDs は結び付けで発行したアクセストークンの ID を順に返す。
func (r workloadIdentity) tokenIDs() []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(r.t.s.saTokens)) {
		if strings.HasPrefix(r.t.s.saTokens[k].CredentialID, wiTokenPrefix) {
			out = append(out, k)
		}
	}
	return out
}

func (r workloadIdentity) Count(context.Context) (int, error) {
	return len(r.tokenIDs()) + len(r.t.s.wiBindings) + len(r.t.s.wiProviders), nil
}

func (r workloadIdentity) Purge(_ context.Context, limit int) (int, error) {
	n := 0
	for _, k := range r.tokenIDs() {
		if n >= limit {
			return n, nil
		}
		deleteKey(r.t, r.t.s.saTokens, k)
		n++
	}
	n += purgeKeys(r.t, r.t.s.wiBindings, limit-n)
	if n >= limit {
		return n, nil
	}
	return n + purgeKeys(r.t, r.t.s.wiProviders, limit-n), nil
}
