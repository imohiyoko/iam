package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/port"
)

// OIDC Provider（design.md 3.1、5.5、9.3）。

type clients struct{ q *db.Queries }

func stringsJSON(ss []string) (string, error) {
	if ss == nil {
		ss = []string{}
	}
	b, err := json.Marshal(ss)
	return string(b), err
}

func toClient(r db.AuthnClient) (port.Client, error) {
	var p times
	c := port.Client{ID: r.ID, PublicID: r.PublicID, RealmID: r.RealmID, Name: r.Name, TrustLevel: r.TrustLevel, AuthMethod: r.AuthMethod,
		SecretHash: r.SecretHash, JWKS: r.Jwks, IDTokenAlg: r.IDTokenAlg, BackchannelLogoutURI: r.BackchannelLogoutUri,
		CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	if p.err != nil {
		return port.Client{}, p.err
	}
	if err := json.Unmarshal([]byte(r.RedirectUris), &c.RedirectURIs); err != nil {
		return port.Client{}, err
	}
	return c, json.Unmarshal([]byte(r.PostLogoutRedirectUris), &c.PostLogoutRedirectURIs)
}

func (r clients) Create(ctx context.Context, c port.Client) error {
	redirect, err := stringsJSON(c.RedirectURIs)
	if err != nil {
		return err
	}
	logout, err := stringsJSON(c.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}
	return mapErr(r.q.CreateClient(ctx, db.CreateClientParams{ID: c.ID, PublicID: c.PublicID, RealmID: c.RealmID, Name: c.Name,
		TrustLevel: c.TrustLevel, RedirectUris: redirect, PostLogoutRedirectUris: logout, AuthMethod: c.AuthMethod, SecretHash: c.SecretHash,
		Jwks: c.JWKS, IDTokenAlg: c.IDTokenAlg, BackchannelLogoutUri: c.BackchannelLogoutURI, CreatedAt: formatTime(c.CreatedAt),
		UpdatedAt: formatTime(c.UpdatedAt)}))
}

func (r clients) Get(ctx context.Context, realmID, id string) (port.Client, error) {
	row, err := r.q.GetClient(ctx, db.GetClientParams{RealmID: realmID, ID: id})
	return one(row, err, toClient)
}

func (r clients) GetByPublicID(ctx context.Context, realmID, publicID string) (port.Client, error) {
	row, err := r.q.GetClientByPublicID(ctx, db.GetClientByPublicIDParams{RealmID: realmID, PublicID: publicID})
	return one(row, err, toClient)
}

func (r clients) List(ctx context.Context, realmID string) ([]port.Client, error) {
	rs, err := r.q.ListClients(ctx, realmID)
	return rows(rs, err, toClient)
}

func (r clients) Update(ctx context.Context, c port.Client) error {
	redirect, err := stringsJSON(c.RedirectURIs)
	if err != nil {
		return err
	}
	logout, err := stringsJSON(c.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}
	n, err := r.q.UpdateClient(ctx, db.UpdateClientParams{Name: c.Name, TrustLevel: c.TrustLevel, RedirectUris: redirect,
		PostLogoutRedirectUris: logout, AuthMethod: c.AuthMethod, SecretHash: c.SecretHash, Jwks: c.JWKS, IDTokenAlg: c.IDTokenAlg,
		BackchannelLogoutUri: c.BackchannelLogoutURI, UpdatedAt: formatTime(c.UpdatedAt), RealmID: c.RealmID, ID: c.ID})
	return affected(n, err, "client")
}

func (r clients) Delete(ctx context.Context, realmID, id string) error {
	n, err := r.q.DeleteClient(ctx, db.DeleteClientParams{RealmID: realmID, ID: id})
	return affected(n, err, "client")
}

// ---------------------------------------------------------------------------

type signingKeys struct{ q *db.Queries }

func toSigningKey(r db.AuthnSigningKey) (port.SigningKey, error) {
	var p times
	k := port.SigningKey{ID: r.ID, RealmID: r.RealmID, Alg: r.Alg, Public: r.PublicKey, Private: r.PrivateKey, CreatedAt: p.at(r.CreatedAt),
		RetiredAt: p.null(r.RetiredAt)}
	return k, p.err
}

func (r signingKeys) Create(ctx context.Context, k port.SigningKey) error {
	return mapErr(r.q.CreateSigningKey(ctx, db.CreateSigningKeyParams{ID: k.ID, RealmID: k.RealmID, Alg: k.Alg, PublicKey: k.Public,
		PrivateKey: k.Private, CreatedAt: formatTime(k.CreatedAt), RetiredAt: nullTime(k.RetiredAt)}))
}

func (r signingKeys) List(ctx context.Context, realmID string) ([]port.SigningKey, error) {
	rs, err := r.q.ListSigningKeys(ctx, realmID)
	return rows(rs, err, toSigningKey)
}

func (r signingKeys) Retire(ctx context.Context, realmID, id string, at time.Time) error {
	n, err := r.q.RetireSigningKey(ctx, db.RetireSigningKeyParams{RetiredAt: nullTime(&at), RealmID: realmID, ID: id})
	return affected(n, err, "signing key")
}

func (r signingKeys) Delete(ctx context.Context, realmID, id string) error {
	n, err := r.q.DeleteSigningKey(ctx, db.DeleteSigningKeyParams{RealmID: realmID, ID: id})
	return affected(n, err, "signing key")
}
