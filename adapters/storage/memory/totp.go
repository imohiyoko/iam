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

type totps struct{ t *tx }

func cloneTOTP(c port.TOTPCredential) port.TOTPCredential {
	c.SecretCiphertext, c.RevokedAt = bytes.Clone(c.SecretCiphertext), cloneTime(c.RevokedAt)
	return c
}

func (r totps) Create(_ context.Context, c port.TOTPCredential) error {
	if _, ok := r.t.s.totps[c.ID]; ok {
		return errs.New(errs.KindConflict, "totp %s exists", c.ID)
	}
	for _, x := range r.t.s.totps {
		if x.RealmID == c.RealmID && x.PublicID == c.PublicID {
			return errs.New(errs.KindConflict, "totp public id exists in realm")
		}
	}
	setKey(r.t, r.t.s.totps, c.ID, cloneTOTP(c))
	return nil
}

func (r totps) GetByPublicID(_ context.Context, realmID, publicID string) (port.TOTPCredential, error) {
	for _, x := range r.t.s.totps {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneTOTP(x), nil
		}
	}
	return port.TOTPCredential{}, errs.New(errs.KindNotFound, "totp")
}

func (r totps) ListByUser(_ context.Context, realmID, userID string) ([]port.TOTPCredential, error) {
	var out []port.TOTPCredential
	for _, x := range r.t.s.totps {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneTOTP(x))
		}
	}
	sortByCreated(out, func(x port.TOTPCredential) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r totps) Use(_ context.Context, realmID, id string, step int64) error {
	c, err := get(r.t.s.totps, realmID, id, func(c port.TOTPCredential) string { return c.RealmID }, "totp")
	if err != nil {
		return err
	}
	if c.LastUsedStep >= step {
		return errs.New(errs.KindConflict, "totp step already used")
	}
	c = cloneTOTP(c)
	c.LastUsedStep = step
	setKey(r.t, r.t.s.totps, id, c)
	return nil
}

func (r totps) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	c, err := get(r.t.s.totps, realmID, id, func(c port.TOTPCredential) string { return c.RealmID }, "totp")
	if err != nil || c.RevokedAt != nil {
		return err
	}
	c = cloneTOTP(c)
	c.RevokedAt, c.RevokeReason = &at, reason
	setKey(r.t, r.t.s.totps, id, c)
	return nil
}

func (r totps) ListAll(_ context.Context, limit int) ([]port.TOTPCredential, error) {
	var out []port.TOTPCredential
	for _, x := range r.t.s.totps {
		out = append(out, cloneTOTP(x))
	}
	slices.SortFunc(out, func(a, b port.TOTPCredential) int { return strings.Compare(a.ID, b.ID) })
	return out[:min(limit, len(out))], nil
}

func (r totps) Delete(_ context.Context, realmID, id string) error {
	if c, ok := r.t.s.totps[id]; ok && c.RealmID == realmID {
		deleteKey(r.t, r.t.s.totps, id)
	}
	return nil
}
