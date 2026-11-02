package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// passkeys は方式専用の表（authn_credentials への移行でだけ使う。ADR 0106）。
type passkeys struct{ t *tx }

func clonePasskey(p port.Passkey) port.Passkey {
	p.CredentialID, p.PublicKey, p.AAGUID, p.UserHandle = bytes.Clone(p.CredentialID), bytes.Clone(p.PublicKey), bytes.Clone(p.AAGUID), bytes.Clone(p.UserHandle)
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
	for _, x := range r.t.s.passkeys {
		if x.RealmID == p.RealmID && (bytes.Equal(x.CredentialID, p.CredentialID) || x.PublicID == p.PublicID) {
			return errs.New(errs.KindConflict, "passkey exists in realm")
		}
	}
	setKey(r.t, r.t.s.passkeys, p.ID, clonePasskey(p))
	return nil
}

func (r passkeys) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	p, err := get(r.t.s.passkeys, realmID, id, func(p port.Passkey) string { return p.RealmID }, "passkey")
	if err != nil || p.RevokedAt != nil {
		return err
	}
	setKey(r.t, r.t.s.revokedPasskeys, revokedKey(realmID, p.CredentialID), port.RevokedPasskeyCredential{RealmID: realmID,
		CredentialID: bytes.Clone(p.CredentialID), RevokedAt: at})
	p = clonePasskey(p)
	p.RevokedAt, p.RevokeReason = &at, reason
	setKey(r.t, r.t.s.passkeys, id, p)
	return nil
}

func (r passkeys) ListAll(_ context.Context, limit int) ([]port.Passkey, error) {
	var out []port.Passkey
	for _, x := range r.t.s.passkeys {
		out = append(out, clonePasskey(x))
	}
	slices.SortFunc(out, func(a, b port.Passkey) int { return strings.Compare(a.ID, b.ID) })
	return out[:min(limit, len(out))], nil
}

func (r passkeys) Delete(_ context.Context, realmID, id string) error {
	if p, ok := r.t.s.passkeys[id]; ok && p.RealmID == realmID {
		deleteKey(r.t, r.t.s.passkeys, id)
	}
	return nil
}

func (r passkeys) ListRevoked(_ context.Context, limit int) ([]port.RevokedPasskeyCredential, error) {
	keys := make([]string, 0, len(r.t.s.revokedPasskeys))
	for k := range r.t.s.revokedPasskeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []port.RevokedPasskeyCredential
	for _, k := range keys[:min(limit, len(keys))] {
		x := r.t.s.revokedPasskeys[k]
		x.CredentialID = bytes.Clone(x.CredentialID)
		out = append(out, x)
	}
	return out, nil
}

func (r passkeys) DeleteRevoked(_ context.Context, realmID string, credentialID []byte) error {
	deleteKey(r.t, r.t.s.revokedPasskeys, revokedKey(realmID, credentialID))
	return nil
}
