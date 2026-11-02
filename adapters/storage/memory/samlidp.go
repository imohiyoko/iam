package memory

import (
	"bytes"
	"context"
	"sort"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// SAML の SP の登録と IdP の署名の証明書（ADR 0115）。

type samlIdP struct{ t *tx }

func cloneSAMLSP(sp port.SAMLServiceProvider) port.SAMLServiceProvider {
	sp.Config = bytes.Clone(sp.Config)
	if sp.Config == nil {
		sp.Config = []byte{}
	}
	return sp
}

func (r samlIdP) CreateServiceProvider(_ context.Context, sp port.SAMLServiceProvider) error {
	for _, x := range r.t.s.samlSPs {
		if x.ID == sp.ID || (x.RealmID == sp.RealmID && x.EntityID == sp.EntityID) {
			return errs.New(errs.KindConflict, "saml service provider exists")
		}
	}
	setKey(r.t, r.t.s.samlSPs, wsfedRPKey(sp.RealmID, sp.ID), cloneSAMLSP(sp))
	return nil
}

func (r samlIdP) GetServiceProvider(_ context.Context, realmID, id string) (port.SAMLServiceProvider, error) {
	x, ok := r.t.s.samlSPs[wsfedRPKey(realmID, id)]
	if !ok {
		return port.SAMLServiceProvider{}, errs.New(errs.KindNotFound, "saml service provider")
	}
	return cloneSAMLSP(x), nil
}

func (r samlIdP) GetServiceProviderByEntityID(_ context.Context, realmID, entityID string) (port.SAMLServiceProvider, error) {
	for _, x := range r.t.s.samlSPs {
		if x.RealmID == realmID && x.EntityID == entityID {
			return cloneSAMLSP(x), nil
		}
	}
	return port.SAMLServiceProvider{}, errs.New(errs.KindNotFound, "saml service provider")
}

func (r samlIdP) ListServiceProviders(_ context.Context, realmID string) ([]port.SAMLServiceProvider, error) {
	out := []port.SAMLServiceProvider{}
	for _, x := range r.t.s.samlSPs {
		if x.RealmID == realmID {
			out = append(out, cloneSAMLSP(x))
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

func (r samlIdP) UpdateServiceProvider(_ context.Context, sp port.SAMLServiceProvider) error {
	k := wsfedRPKey(sp.RealmID, sp.ID)
	old, ok := r.t.s.samlSPs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "saml service provider")
	}
	for _, x := range r.t.s.samlSPs {
		if x.ID != sp.ID && x.RealmID == sp.RealmID && x.EntityID == sp.EntityID {
			return errs.New(errs.KindConflict, "saml service provider exists")
		}
	}
	sp = cloneSAMLSP(sp)
	sp.CreatedAt = old.CreatedAt
	setKey(r.t, r.t.s.samlSPs, k, sp)
	return nil
}

func (r samlIdP) DeleteServiceProvider(_ context.Context, realmID, id string) error {
	k := wsfedRPKey(realmID, id)
	if _, ok := r.t.s.samlSPs[k]; !ok {
		return errs.New(errs.KindNotFound, "saml service provider")
	}
	deleteKey(r.t, r.t.s.samlSPs, k)
	return nil
}

func (r samlIdP) CreateCertificate(_ context.Context, c port.SAMLIdPCertificate) error {
	k := wsfedCertKey(c.RealmID, c.KeyID)
	if _, ok := r.t.s.samlCerts[k]; ok {
		return errs.New(errs.KindConflict, "saml idp certificate exists")
	}
	c.DER = bytes.Clone(c.DER)
	if c.DER == nil {
		c.DER = []byte{}
	}
	setKey(r.t, r.t.s.samlCerts, k, c)
	return nil
}

func (r samlIdP) ListCertificates(_ context.Context, realmID string) ([]port.SAMLIdPCertificate, error) {
	out := []port.SAMLIdPCertificate{}
	for _, x := range r.t.s.samlCerts {
		if x.RealmID == realmID {
			x.DER = bytes.Clone(x.DER)
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out, nil
}

func (r samlIdP) DeleteCertificate(_ context.Context, realmID, keyID string) error {
	k := wsfedCertKey(realmID, keyID)
	if _, ok := r.t.s.samlCerts[k]; !ok {
		return errs.New(errs.KindNotFound, "saml idp certificate")
	}
	deleteKey(r.t, r.t.s.samlCerts, k)
	return nil
}

func (r samlIdP) Count(context.Context) (int, error) {
	return len(r.t.s.samlSPs) + len(r.t.s.samlCerts), nil
}

func (r samlIdP) Purge(_ context.Context, limit int) (int, error) {
	n := purgeKeys(r.t, r.t.s.samlSPs, limit)
	if limit >= 0 && n >= limit {
		return n, nil
	}
	rest := -1
	if limit >= 0 {
		rest = limit - n
	}
	return n + purgeKeys(r.t, r.t.s.samlCerts, rest), nil
}
