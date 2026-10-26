package memory

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type passkeys struct{ t *tx }

func clonePasskey(p port.Passkey) port.Passkey {
	p.CredentialID, p.PublicKey, p.AAGUID = bytes.Clone(p.CredentialID), bytes.Clone(p.PublicKey), bytes.Clone(p.AAGUID)
	p.Transports = slices.Clone(p.Transports)
	p.LastUsedAt, p.RevokedAt = cloneTime(p.LastUsedAt), cloneTime(p.RevokedAt)
	return p
}

func revokedKey(realmID string, credentialID []byte) string {
	return realmID + "\x00" + string(credentialID)
}

func (r passkeys) Create(_ context.Context, p port.Passkey) error {
	if _, ok := r.t.s.passkeys[p.ID]; ok {
		return errs.New(errs.KindConflict, "passkey %s exists", p.ID)
	}
	if _, ok := r.t.s.revokedPasskeys[revokedKey(p.RealmID, p.CredentialID)]; ok {
		return errs.New(errs.KindConflict, "passkey credential revoked")
	}
	for _, x := range r.t.s.passkeys {
		if x.RealmID == p.RealmID && (bytes.Equal(x.CredentialID, p.CredentialID) || x.PublicID == p.PublicID) {
			return errs.New(errs.KindConflict, "passkey exists in realm")
		}
	}
	setKey(r.t, r.t.s.passkeys, p.ID, clonePasskey(p))
	return nil
}

func (r passkeys) GetByCredentialID(_ context.Context, realmID string, credentialID []byte) (port.Passkey, error) {
	for _, x := range r.t.s.passkeys {
		if x.RealmID == realmID && bytes.Equal(x.CredentialID, credentialID) && x.RevokedAt == nil {
			return clonePasskey(x), nil
		}
	}
	return port.Passkey{}, errs.New(errs.KindNotFound, "passkey")
}

func (r passkeys) GetByPublicID(_ context.Context, realmID, publicID string) (port.Passkey, error) {
	for _, x := range r.t.s.passkeys {
		if x.RealmID == realmID && x.PublicID == publicID {
			return clonePasskey(x), nil
		}
	}
	return port.Passkey{}, errs.New(errs.KindNotFound, "passkey")
}

func (r passkeys) ListByUser(_ context.Context, realmID, userID string) ([]port.Passkey, error) {
	var out []port.Passkey
	for _, x := range r.t.s.passkeys {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, clonePasskey(x))
		}
	}
	sortByCreated(out, func(x port.Passkey) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r passkeys) update(realmID, id string, fn func(*port.Passkey)) error {
	p, err := get(r.t.s.passkeys, realmID, id, func(p port.Passkey) string { return p.RealmID }, "passkey")
	if err != nil {
		return err
	}
	p = clonePasskey(p)
	fn(&p)
	setKey(r.t, r.t.s.passkeys, id, p)
	return nil
}

func (r passkeys) Used(_ context.Context, realmID, id string, signCount uint32, flags uint8, at time.Time) error {
	return r.update(realmID, id, func(p *port.Passkey) { p.SignCount, p.Flags, p.LastUsedAt = signCount, flags, &at })
}

func (r passkeys) Rename(_ context.Context, realmID, id, name string) error {
	return r.update(realmID, id, func(p *port.Passkey) { p.Name = name })
}

func (r passkeys) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	p, err := get(r.t.s.passkeys, realmID, id, func(p port.Passkey) string { return p.RealmID }, "passkey")
	if err != nil || p.RevokedAt != nil {
		return err
	}
	setKey(r.t, r.t.s.revokedPasskeys, revokedKey(realmID, p.CredentialID), at)
	return r.update(realmID, id, func(p *port.Passkey) { p.RevokedAt, p.RevokeReason = &at, reason })
}
