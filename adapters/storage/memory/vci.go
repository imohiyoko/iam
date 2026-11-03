package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID4VCI の資格情報の定義と発行の記録（ADR 0119）。

type vci struct{ t *tx }

func cloneVCIConfig(c port.VCICredentialConfiguration) port.VCICredentialConfiguration {
	c.Config = bytes.Clone(c.Config)
	if c.Config == nil {
		c.Config = []byte{}
	}
	return c
}

func cloneVCICred(c port.VCIIssuedCredential) port.VCIIssuedCredential {
	if c.RevokedAt != nil {
		at := *c.RevokedAt
		c.RevokedAt = &at
	}
	return c
}

func (r vci) CreateConfiguration(_ context.Context, c port.VCICredentialConfiguration) error {
	for _, x := range r.t.s.vciConfigs {
		if x.ID == c.ID || (x.RealmID == c.RealmID && x.ConfigurationID == c.ConfigurationID) {
			return errs.New(errs.KindConflict, "vci credential configuration exists")
		}
	}
	setKey(r.t, r.t.s.vciConfigs, wsfedRPKey(c.RealmID, c.ID), cloneVCIConfig(c))
	return nil
}

func (r vci) GetConfiguration(_ context.Context, realmID, id string) (port.VCICredentialConfiguration, error) {
	x, ok := r.t.s.vciConfigs[wsfedRPKey(realmID, id)]
	if !ok {
		return port.VCICredentialConfiguration{}, errs.New(errs.KindNotFound, "vci credential configuration")
	}
	return cloneVCIConfig(x), nil
}

func (r vci) GetConfigurationByConfigurationID(_ context.Context, realmID, configurationID string) (port.VCICredentialConfiguration, error) {
	for _, x := range r.t.s.vciConfigs {
		if x.RealmID == realmID && x.ConfigurationID == configurationID {
			return cloneVCIConfig(x), nil
		}
	}
	return port.VCICredentialConfiguration{}, errs.New(errs.KindNotFound, "vci credential configuration")
}

func (r vci) ListConfigurations(_ context.Context, realmID string) ([]port.VCICredentialConfiguration, error) {
	out := []port.VCICredentialConfiguration{}
	for _, x := range r.t.s.vciConfigs {
		if x.RealmID == realmID {
			out = append(out, cloneVCIConfig(x))
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

func (r vci) UpdateConfiguration(_ context.Context, c port.VCICredentialConfiguration) error {
	k := wsfedRPKey(c.RealmID, c.ID)
	old, ok := r.t.s.vciConfigs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "vci credential configuration")
	}
	for _, x := range r.t.s.vciConfigs {
		if x.ID != c.ID && x.RealmID == c.RealmID && x.ConfigurationID == c.ConfigurationID {
			return errs.New(errs.KindConflict, "vci credential configuration exists")
		}
	}
	c = cloneVCIConfig(c)
	c.CreatedAt = old.CreatedAt
	setKey(r.t, r.t.s.vciConfigs, k, c)
	return nil
}

func (r vci) DeleteConfiguration(_ context.Context, realmID, id string) error {
	k := wsfedRPKey(realmID, id)
	if _, ok := r.t.s.vciConfigs[k]; !ok {
		return errs.New(errs.KindNotFound, "vci credential configuration")
	}
	deleteKey(r.t, r.t.s.vciConfigs, k)
	return nil
}

func (r vci) CreateCredential(_ context.Context, c port.VCIIssuedCredential) error {
	for _, x := range r.t.s.vciCreds {
		if x.ID == c.ID || (x.RealmID == c.RealmID && x.StatusIndex == c.StatusIndex) {
			return errs.New(errs.KindConflict, "vci issued credential exists")
		}
	}
	setKey(r.t, r.t.s.vciCreds, wsfedRPKey(c.RealmID, c.ID), cloneVCICred(c))
	return nil
}

func (r vci) GetCredential(_ context.Context, realmID, id string) (port.VCIIssuedCredential, error) {
	x, ok := r.t.s.vciCreds[wsfedRPKey(realmID, id)]
	if !ok {
		return port.VCIIssuedCredential{}, errs.New(errs.KindNotFound, "vci issued credential")
	}
	return cloneVCICred(x), nil
}

func (r vci) ListCredentialsByUser(_ context.Context, realmID, userID string) ([]port.VCIIssuedCredential, error) {
	out := []port.VCIIssuedCredential{}
	for _, x := range r.t.s.vciCreds {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneVCICred(x))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].IssuedAt.After(out[j].IssuedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (r vci) RevokeCredential(_ context.Context, realmID, id string, at time.Time) error {
	k := wsfedRPKey(realmID, id)
	x, ok := r.t.s.vciCreds[k]
	if !ok {
		return errs.New(errs.KindNotFound, "vci issued credential")
	}
	if x.RevokedAt != nil {
		return nil
	}
	x.RevokedAt = &at
	setKey(r.t, r.t.s.vciCreds, k, x)
	return nil
}

func (r vci) RevokeCredentialsByUser(_ context.Context, realmID, userID string, at time.Time) error {
	for k, x := range r.t.s.vciCreds {
		if x.RealmID == realmID && x.UserID == userID && x.RevokedAt == nil {
			x.RevokedAt = &at
			setKey(r.t, r.t.s.vciCreds, k, x)
		}
	}
	return nil
}

func (r vci) ListRevokedIndexes(_ context.Context, realmID string, now time.Time) ([]int, error) {
	out := []int{}
	for _, x := range r.t.s.vciCreds {
		if x.RealmID == realmID && x.RevokedAt != nil && x.ExpiresAt.After(now) {
			out = append(out, x.StatusIndex)
		}
	}
	return out, nil
}

func (r vci) DeleteExpiredCredentials(_ context.Context, realmID string, now time.Time, limit int) (int, error) {
	var keys []string
	for k, x := range r.t.s.vciCreds {
		if x.RealmID == realmID && !x.ExpiresAt.After(now) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if limit >= 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.vciCreds, k)
	}
	return len(keys), nil
}

func (r vci) Count(context.Context) (int, error) {
	return len(r.t.s.vciConfigs) + len(r.t.s.vciCreds), nil
}

func (r vci) Purge(_ context.Context, limit int) (int, error) {
	n := purgeKeys(r.t, r.t.s.vciConfigs, limit)
	if limit >= 0 && n >= limit {
		return n, nil
	}
	rest := -1
	if limit >= 0 {
		rest = limit - n
	}
	return n + purgeKeys(r.t, r.t.s.vciCreds, rest), nil
}
