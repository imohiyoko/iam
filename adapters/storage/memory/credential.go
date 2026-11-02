package memory

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type authnCredentials struct{ t *tx }

func cloneAuthnCredential(c port.Credential) port.Credential {
	c.Lookup, c.Data = bytes.Clone(c.Lookup), bytes.Clone(c.Data)
	if len(c.Lookup) == 0 {
		c.Lookup = nil
	}
	c.LastUsedAt, c.RevokedAt = cloneTime(c.LastUsedAt), cloneTime(c.RevokedAt)
	return c
}

func credentialRealm(c port.Credential) string { return c.RealmID }

func (r authnCredentials) Create(_ context.Context, c port.Credential) error {
	if _, ok := r.t.s.authnCreds[c.ID]; ok {
		return errs.New(errs.KindConflict, "credential %s exists", c.ID)
	}
	for _, x := range r.t.s.authnCreds {
		if x.RealmID != c.RealmID {
			continue
		}
		if x.PublicID == c.PublicID {
			return errs.New(errs.KindConflict, "credential public id exists in realm")
		}
		if len(c.Lookup) > 0 && c.RevokedAt == nil && x.Method == c.Method && x.RevokedAt == nil && bytes.Equal(x.Lookup, c.Lookup) {
			return errs.New(errs.KindConflict, "credential lookup exists in realm")
		}
	}
	if len(c.Lookup) > 0 && c.RevokedAt == nil {
		if _, ok := r.t.s.retiredLookups[retiredKey(c.RealmID, c.Method, c.Lookup)]; ok {
			return errs.New(errs.KindConflict, "credential lookup retired")
		}
	}
	setKey(r.t, r.t.s.authnCreds, c.ID, cloneAuthnCredential(c))
	return nil
}

func (r authnCredentials) Get(_ context.Context, realmID, id string) (port.Credential, error) {
	c, err := get(r.t.s.authnCreds, realmID, id, credentialRealm, "credential")
	if err != nil {
		return port.Credential{}, err
	}
	return cloneAuthnCredential(c), nil
}

func (r authnCredentials) GetByPublicID(_ context.Context, realmID, publicID string) (port.Credential, error) {
	for _, x := range r.t.s.authnCreds {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneAuthnCredential(x), nil
		}
	}
	return port.Credential{}, errs.New(errs.KindNotFound, "credential")
}

func (r authnCredentials) GetByLookup(_ context.Context, realmID, method string, lookup []byte) (port.Credential, error) {
	if len(lookup) > 0 {
		for _, x := range r.t.s.authnCreds {
			if x.RealmID == realmID && x.Method == method && x.RevokedAt == nil && bytes.Equal(x.Lookup, lookup) {
				return cloneAuthnCredential(x), nil
			}
		}
	}
	return port.Credential{}, errs.New(errs.KindNotFound, "credential")
}

func (r authnCredentials) LookupKeyIDs(_ context.Context, realmID, method string) ([]string, error) {
	var out []string
	for _, x := range r.t.s.authnCreds {
		if x.RealmID == realmID && x.Method == method && len(x.Lookup) > 0 && x.RevokedAt == nil && !slices.Contains(out, x.LookupKeyID) {
			out = append(out, x.LookupKeyID)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (r authnCredentials) ListByUser(_ context.Context, realmID, userID, method string) ([]port.Credential, error) {
	var out []port.Credential
	for _, x := range r.t.s.authnCreds {
		if x.RealmID == realmID && x.UserID == userID && (method == "" || x.Method == method) {
			out = append(out, cloneAuthnCredential(x))
		}
	}
	sortByCreated(out, func(x port.Credential) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r authnCredentials) UpdateData(_ context.Context, realmID, id string, old, data []byte, dataVersion int) error {
	c, err := get(r.t.s.authnCreds, realmID, id, credentialRealm, "credential")
	if err != nil {
		return err
	}
	if c.RevokedAt != nil || !bytes.Equal(c.Data, old) {
		return errs.New(errs.KindConflict, "credential data changed")
	}
	c = cloneAuthnCredential(c)
	c.Data, c.DataVersion = bytes.Clone(data), dataVersion
	setKey(r.t, r.t.s.authnCreds, id, c)
	return nil
}

func (r authnCredentials) Used(_ context.Context, realmID, id string, at time.Time) error {
	c, err := get(r.t.s.authnCreds, realmID, id, credentialRealm, "credential")
	if err != nil {
		return err
	}
	c = cloneAuthnCredential(c)
	c.LastUsedAt = &at
	setKey(r.t, r.t.s.authnCreds, id, c)
	return nil
}

func (r authnCredentials) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	c, err := get(r.t.s.authnCreds, realmID, id, credentialRealm, "credential")
	if err != nil || c.RevokedAt != nil {
		return err
	}
	c = cloneAuthnCredential(c)
	c.RevokedAt, c.RevokeReason = &at, reason
	setKey(r.t, r.t.s.authnCreds, id, c)
	if c.ReserveLookup && len(c.Lookup) > 0 {
		return r.retire(port.RetiredLookup{RealmID: realmID, Method: c.Method, Lookup: c.Lookup, LookupKeyID: c.LookupKeyID, RetiredAt: at})
	}
	return nil
}

func (r authnCredentials) SetPreferredOrg(_ context.Context, realmID, id, orgID string) error {
	c, err := get(r.t.s.authnCreds, realmID, id, credentialRealm, "credential")
	if err != nil {
		return err
	}
	c = cloneAuthnCredential(c)
	c.PreferredOrgID = orgID
	setKey(r.t, r.t.s.authnCreds, id, c)
	return nil
}

func retiredKey(realmID, method string, lookup []byte) string {
	return realmID + "\x00" + method + "\x00" + string(lookup)
}

// retire は検索キーを退役済みに加える（既にあれば何もしない）。
func (r authnCredentials) retire(x port.RetiredLookup) error {
	if len(x.Lookup) == 0 {
		return errs.New(errs.KindInvalid, "retired lookup is empty")
	}
	k := retiredKey(x.RealmID, x.Method, x.Lookup)
	if _, ok := r.t.s.retiredLookups[k]; ok {
		return nil
	}
	x.Lookup = bytes.Clone(x.Lookup)
	setKey(r.t, r.t.s.retiredLookups, k, x)
	return nil
}

func (r authnCredentials) LookupRetired(_ context.Context, realmID, method string, lookup []byte) (bool, error) {
	if len(lookup) == 0 {
		return false, nil
	}
	_, ok := r.t.s.retiredLookups[retiredKey(realmID, method, lookup)]
	return ok, nil
}

func (r authnCredentials) RetiredLookupKeyIDs(_ context.Context, realmID, method string) ([]string, error) {
	var out []string
	for _, x := range r.t.s.retiredLookups {
		if x.RealmID == realmID && x.Method == method && !slices.Contains(out, x.LookupKeyID) {
			out = append(out, x.LookupKeyID)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (r authnCredentials) MoveUser(_ context.Context, realmID, fromUserID, toUserID string) (int, error) {
	var keys []string
	for k, x := range r.t.s.authnCreds {
		if x.RealmID == realmID && x.UserID == fromUserID {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		x := cloneAuthnCredential(r.t.s.authnCreds[k])
		x.UserID = toUserID
		setKey(r.t, r.t.s.authnCreds, k, x)
	}
	return len(keys), nil
}

func (r authnCredentials) Count(_ context.Context, method string) (int, error) {
	n := 0
	for _, x := range r.t.s.authnCreds {
		if x.Method == method {
			n++
		}
	}
	return n, nil
}

func (r authnCredentials) Purge(_ context.Context, method string, limit int) (int, error) {
	var keys []string
	for k, x := range r.t.s.authnCreds {
		if len(keys) >= limit {
			break
		}
		if x.Method == method {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.authnCreds, k)
	}
	return len(keys), nil
}
