package memory

import (
	"context"
	"slices"
	"sort"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// WS-Federation の RP と署名の証明書（ADR 0110）。

type wsfed struct{ t *tx }

func wsfedRPKey(realmID, id string) string      { return realmID + "\x00" + id }
func wsfedCertKey(realmID, keyID string) string { return realmID + "\x00" + keyID }

func cloneRP(rp port.WSFedRelyingParty) port.WSFedRelyingParty {
	rp.ReplyURLs = slices.Clone(rp.ReplyURLs)
	rp.Claims = slices.Clone(rp.Claims)
	return rp
}

func (r wsfed) CreateRelyingParty(_ context.Context, rp port.WSFedRelyingParty) error {
	for _, x := range r.t.s.wsfedRPs {
		if x.ID == rp.ID || (x.RealmID == rp.RealmID && x.Realm == rp.Realm) {
			return errs.New(errs.KindConflict, "wsfed relying party exists")
		}
	}
	rp = cloneRP(rp)
	if rp.Claims == nil {
		rp.Claims = []byte{}
	}
	if rp.ReplyURLs == nil {
		rp.ReplyURLs = []string{}
	}
	setKey(r.t, r.t.s.wsfedRPs, wsfedRPKey(rp.RealmID, rp.ID), rp)
	return nil
}

func (r wsfed) GetRelyingParty(_ context.Context, realmID, id string) (port.WSFedRelyingParty, error) {
	x, ok := r.t.s.wsfedRPs[wsfedRPKey(realmID, id)]
	if !ok {
		return port.WSFedRelyingParty{}, errs.New(errs.KindNotFound, "wsfed relying party")
	}
	return cloneRP(x), nil
}

func (r wsfed) GetRelyingPartyByRealm(_ context.Context, realmID, wtrealm string) (port.WSFedRelyingParty, error) {
	for _, x := range r.t.s.wsfedRPs {
		if x.RealmID == realmID && x.Realm == wtrealm {
			return cloneRP(x), nil
		}
	}
	return port.WSFedRelyingParty{}, errs.New(errs.KindNotFound, "wsfed relying party")
}

func (r wsfed) ListRelyingParties(_ context.Context, realmID string) ([]port.WSFedRelyingParty, error) {
	out := []port.WSFedRelyingParty{}
	for _, x := range r.t.s.wsfedRPs {
		if x.RealmID == realmID {
			out = append(out, cloneRP(x))
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

func (r wsfed) UpdateRelyingParty(_ context.Context, rp port.WSFedRelyingParty) error {
	k := wsfedRPKey(rp.RealmID, rp.ID)
	old, ok := r.t.s.wsfedRPs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "wsfed relying party")
	}
	for _, x := range r.t.s.wsfedRPs {
		if x.ID != rp.ID && x.RealmID == rp.RealmID && x.Realm == rp.Realm {
			return errs.New(errs.KindConflict, "wsfed relying party exists")
		}
	}
	rp = cloneRP(rp)
	rp.CreatedAt = old.CreatedAt
	if rp.Claims == nil {
		rp.Claims = []byte{}
	}
	if rp.ReplyURLs == nil {
		rp.ReplyURLs = []string{}
	}
	setKey(r.t, r.t.s.wsfedRPs, k, rp)
	return nil
}

func (r wsfed) DeleteRelyingParty(_ context.Context, realmID, id string) error {
	k := wsfedRPKey(realmID, id)
	if _, ok := r.t.s.wsfedRPs[k]; !ok {
		return errs.New(errs.KindNotFound, "wsfed relying party")
	}
	deleteKey(r.t, r.t.s.wsfedRPs, k)
	return nil
}

func (r wsfed) CreateCertificate(_ context.Context, c port.WSFedCertificate) error {
	k := wsfedCertKey(c.RealmID, c.KeyID)
	if _, ok := r.t.s.wsfedCerts[k]; ok {
		return errs.New(errs.KindConflict, "wsfed certificate exists")
	}
	c.DER = slices.Clone(c.DER)
	if c.DER == nil {
		c.DER = []byte{}
	}
	setKey(r.t, r.t.s.wsfedCerts, k, c)
	return nil
}

func (r wsfed) ListCertificates(_ context.Context, realmID string) ([]port.WSFedCertificate, error) {
	out := []port.WSFedCertificate{}
	for _, x := range r.t.s.wsfedCerts {
		if x.RealmID == realmID {
			x.DER = slices.Clone(x.DER)
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out, nil
}

func (r wsfed) DeleteCertificate(_ context.Context, realmID, keyID string) error {
	k := wsfedCertKey(realmID, keyID)
	if _, ok := r.t.s.wsfedCerts[k]; !ok {
		return errs.New(errs.KindNotFound, "wsfed certificate")
	}
	deleteKey(r.t, r.t.s.wsfedCerts, k)
	return nil
}

func (r wsfed) Count(context.Context) (int, error) {
	return len(r.t.s.wsfedRPs) + len(r.t.s.wsfedCerts), nil
}

func (r wsfed) Purge(_ context.Context, limit int) (int, error) {
	n := purgeKeys(r.t, r.t.s.wsfedRPs, limit)
	if limit >= 0 && n >= limit {
		return n, nil
	}
	rest := -1
	if limit >= 0 {
		rest = limit - n
	}
	return n + purgeKeys(r.t, r.t.s.wsfedCerts, rest), nil
}

// purgeKeys は m のキーを小さい順に最大 limit 個（負なら全部）消し、その数を返す。
func purgeKeys[V any](t *tx, m map[string]V, limit int) int {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if limit >= 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	for _, k := range keys {
		deleteKey(t, m, k)
	}
	return len(keys)
}
