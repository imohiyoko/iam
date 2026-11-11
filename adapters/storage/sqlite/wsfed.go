package sqlite

import (
	"context"
	"encoding/json"

	"github.com/imohiyoko/iam/adapters/storage/sqlite/db"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// wsfed は WS-Federation の RP と署名の証明書（authn_wsfed_relying_parties・authn_wsfed_certificates。ADR 0110）。
type wsfed struct{ q *db.Queries }

func toWSFedRelyingParty(r db.AuthnWsfedRelyingParty) (port.WSFedRelyingParty, error) {
	var p times
	rp := port.WSFedRelyingParty{ID: r.ID, RealmID: r.RealmID, Realm: r.Realm, Name: r.Name, TokenType: r.TokenType, Claims: r.Claims,
		TokenLifetime: int(r.TokenLifetime), SigningAlg: r.SigningAlg, CreatedAt: p.at(r.CreatedAt), UpdatedAt: p.at(r.UpdatedAt)}
	if p.err != nil {
		return port.WSFedRelyingParty{}, p.err
	}
	return rp, json.Unmarshal([]byte(r.ReplyUrls), &rp.ReplyURLs)
}

func toWSFedCertificate(r db.AuthnWsfedCertificate) (port.WSFedCertificate, error) {
	var p times
	c := port.WSFedCertificate{RealmID: r.RealmID, KeyID: r.KeyID, DER: r.Der, CreatedAt: p.at(r.CreatedAt)}
	return c, p.err
}

func (r wsfed) CreateRelyingParty(ctx context.Context, rp port.WSFedRelyingParty) error {
	reply, err := stringsJSON(rp.ReplyURLs)
	if err != nil {
		return err
	}
	return mapErr(r.q.CreateWSFedRelyingParty(ctx, db.CreateWSFedRelyingPartyParams{ID: rp.ID, RealmID: rp.RealmID, Realm: rp.Realm, Name: rp.Name,
		ReplyUrls: reply, TokenType: rp.TokenType, Claims: nonNil(rp.Claims), TokenLifetime: int64(rp.TokenLifetime),
		SigningAlg: signingAlg(rp.SigningAlg), CreatedAt: formatTime(rp.CreatedAt), UpdatedAt: formatTime(rp.UpdatedAt)}))
}

func (r wsfed) GetRelyingParty(ctx context.Context, realmID, id string) (port.WSFedRelyingParty, error) {
	x, err := r.q.GetWSFedRelyingParty(ctx, db.GetWSFedRelyingPartyParams{RealmID: realmID, ID: id})
	if err != nil {
		return port.WSFedRelyingParty{}, mapErr(err)
	}
	return toWSFedRelyingParty(x)
}

func (r wsfed) GetRelyingPartyByRealm(ctx context.Context, realmID, wtrealm string) (port.WSFedRelyingParty, error) {
	x, err := r.q.GetWSFedRelyingPartyByRealm(ctx, db.GetWSFedRelyingPartyByRealmParams{RealmID: realmID, Realm: wtrealm})
	if err != nil {
		return port.WSFedRelyingParty{}, mapErr(err)
	}
	return toWSFedRelyingParty(x)
}

func (r wsfed) ListRelyingParties(ctx context.Context, realmID string) ([]port.WSFedRelyingParty, error) {
	rs, err := r.q.ListWSFedRelyingParties(ctx, realmID)
	return rows(rs, err, toWSFedRelyingParty)
}

func (r wsfed) UpdateRelyingParty(ctx context.Context, rp port.WSFedRelyingParty) error {
	reply, err := stringsJSON(rp.ReplyURLs)
	if err != nil {
		return err
	}
	n, err := r.q.UpdateWSFedRelyingParty(ctx, db.UpdateWSFedRelyingPartyParams{Realm: rp.Realm, Name: rp.Name, ReplyUrls: reply, TokenType: rp.TokenType,
		Claims: nonNil(rp.Claims), TokenLifetime: int64(rp.TokenLifetime), SigningAlg: signingAlg(rp.SigningAlg), UpdatedAt: formatTime(rp.UpdatedAt), RealmID: rp.RealmID, ID: rp.ID})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "wsfed relying party")
	}
	return nil
}

func (r wsfed) DeleteRelyingParty(ctx context.Context, realmID, id string) error {
	n, err := r.q.DeleteWSFedRelyingParty(ctx, db.DeleteWSFedRelyingPartyParams{RealmID: realmID, ID: id})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "wsfed relying party")
	}
	return nil
}

func (r wsfed) CreateCertificate(ctx context.Context, c port.WSFedCertificate) error {
	return mapErr(r.q.CreateWSFedCertificate(ctx, db.CreateWSFedCertificateParams{RealmID: c.RealmID, KeyID: c.KeyID, Der: nonNil(c.DER),
		CreatedAt: formatTime(c.CreatedAt)}))
}

func (r wsfed) ListCertificates(ctx context.Context, realmID string) ([]port.WSFedCertificate, error) {
	rs, err := r.q.ListWSFedCertificates(ctx, realmID)
	return rows(rs, err, toWSFedCertificate)
}

func (r wsfed) DeleteCertificate(ctx context.Context, realmID, keyID string) error {
	n, err := r.q.DeleteWSFedCertificate(ctx, db.DeleteWSFedCertificateParams{RealmID: realmID, KeyID: keyID})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return errs.New(errs.KindNotFound, "wsfed certificate")
	}
	return nil
}

func (r wsfed) Count(ctx context.Context) (int, error) {
	n, err := r.q.CountWSFedRelyingParties(ctx)
	if err != nil {
		return 0, mapErr(err)
	}
	c, err := r.q.CountWSFedCertificates(ctx)
	return int(n + c), mapErr(err)
}

func (r wsfed) Purge(ctx context.Context, limit int) (int, error) {
	n, err := r.q.PurgeWSFedRelyingParties(ctx, int64(limit))
	if err != nil || int(n) >= limit {
		return int(n), mapErr(err)
	}
	c, err := r.q.PurgeWSFedCertificates(ctx, int64(limit)-n)
	return int(n + c), mapErr(err)
}

// signingAlg は RP の署名のアルゴリズム（空なら ES256。ADR 0125）。
func signingAlg(alg string) string {
	if alg == "" {
		return port.AlgES256
	}
	return alg
}
