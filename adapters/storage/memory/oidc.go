package memory

import (
	"context"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OIDC Provider（design.md 3.1、5.5、9.3）。

type clients struct{ t *tx }

func cloneClient(c port.Client) port.Client {
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	c.PostLogoutRedirectURIs = slices.Clone(c.PostLogoutRedirectURIs)
	c.SecretHash = slices.Clone(c.SecretHash)
	c.JWKS = slices.Clone(c.JWKS)
	return c
}

func (r clients) Create(_ context.Context, c port.Client) error {
	if _, ok := r.t.s.clients[c.ID]; ok {
		return errs.New(errs.KindConflict, "client %s exists", c.ID)
	}
	for _, x := range r.t.s.clients {
		if x.RealmID == c.RealmID && x.PublicID == c.PublicID {
			return errs.New(errs.KindConflict, "client id exists in realm")
		}
	}
	setKey(r.t, r.t.s.clients, c.ID, cloneClient(c))
	return nil
}

func (r clients) Get(_ context.Context, realmID, id string) (port.Client, error) {
	c, err := get(r.t.s.clients, realmID, id, func(c port.Client) string { return c.RealmID }, "client")
	return cloneClient(c), err
}

func (r clients) GetByPublicID(_ context.Context, realmID, publicID string) (port.Client, error) {
	for _, c := range r.t.s.clients {
		if c.RealmID == realmID && c.PublicID == publicID {
			return cloneClient(c), nil
		}
	}
	return port.Client{}, errs.New(errs.KindNotFound, "client")
}

func (r clients) List(_ context.Context, realmID string) ([]port.Client, error) {
	var out []port.Client
	for _, c := range r.t.s.clients {
		if c.RealmID == realmID {
			out = append(out, cloneClient(c))
		}
	}
	sortByCreated(out, func(c port.Client) (time.Time, string) { return c.CreatedAt, c.ID })
	return out, nil
}

func (r clients) Update(_ context.Context, c port.Client) error {
	cur, err := get(r.t.s.clients, c.RealmID, c.ID, func(c port.Client) string { return c.RealmID }, "client")
	if err != nil {
		return err
	}
	c.PublicID, c.CreatedAt = cur.PublicID, cur.CreatedAt
	setKey(r.t, r.t.s.clients, c.ID, cloneClient(c))
	return nil
}

func (r clients) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.clients, realmID, id, func(c port.Client) string { return c.RealmID }, "client"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.clients, id)
	return nil
}

// ---------------------------------------------------------------------------

type signingKeys struct{ t *tx }

func cloneSigningKey(k port.SigningKey) port.SigningKey {
	k.Public, k.Private = slices.Clone(k.Public), slices.Clone(k.Private)
	if k.RetiredAt != nil {
		at := *k.RetiredAt
		k.RetiredAt = &at
	}
	return k
}

func (r signingKeys) Create(_ context.Context, k port.SigningKey) error {
	if _, ok := r.t.s.signingKeys[k.ID]; ok {
		return errs.New(errs.KindConflict, "signing key %s exists", k.ID)
	}
	setKey(r.t, r.t.s.signingKeys, k.ID, cloneSigningKey(k))
	return nil
}

func (r signingKeys) List(_ context.Context, realmID string) ([]port.SigningKey, error) {
	var out []port.SigningKey
	for _, k := range r.t.s.signingKeys {
		if k.RealmID == realmID {
			out = append(out, cloneSigningKey(k))
		}
	}
	sortByCreated(out, func(k port.SigningKey) (time.Time, string) { return k.CreatedAt, k.ID })
	return out, nil
}

func (r signingKeys) Retire(_ context.Context, realmID, id string, at time.Time) error {
	k, err := get(r.t.s.signingKeys, realmID, id, func(k port.SigningKey) string { return k.RealmID }, "signing key")
	if err != nil {
		return err
	}
	k.RetiredAt = &at
	setKey(r.t, r.t.s.signingKeys, id, cloneSigningKey(k))
	return nil
}

func (r signingKeys) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.signingKeys, realmID, id, func(k port.SigningKey) string { return k.RealmID }, "signing key"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.signingKeys, id)
	return nil
}
