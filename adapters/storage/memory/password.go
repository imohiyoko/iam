package memory

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type passwords struct{ t *tx }

func clonePassword(c port.PasswordCredential) port.PasswordCredential {
	c.RevokedAt = cloneTime(c.RevokedAt)
	return c
}

func (r passwords) Create(_ context.Context, c port.PasswordCredential) error {
	if _, ok := r.t.s.passwords[c.ID]; ok {
		return errs.New(errs.KindConflict, "password %s exists", c.ID)
	}
	for _, x := range r.t.s.passwords {
		if x.RealmID == c.RealmID && x.UserID == c.UserID && x.RevokedAt == nil && c.RevokedAt == nil {
			return errs.New(errs.KindConflict, "user already has a password")
		}
	}
	setKey(r.t, r.t.s.passwords, c.ID, clonePassword(c))
	return nil
}

func (r passwords) Get(_ context.Context, realmID, id string) (port.PasswordCredential, error) {
	c, err := get(r.t.s.passwords, realmID, id, func(c port.PasswordCredential) string { return c.RealmID }, "password")
	return clonePassword(c), err
}

func (r passwords) GetActive(_ context.Context, realmID, userID string) (port.PasswordCredential, error) {
	for _, x := range r.t.s.passwords {
		if x.RealmID == realmID && x.UserID == userID && x.RevokedAt == nil {
			return clonePassword(x), nil
		}
	}
	return port.PasswordCredential{}, errs.New(errs.KindNotFound, "password")
}

func (r passwords) UpdateHash(_ context.Context, realmID, id, hash string) error {
	c, err := get(r.t.s.passwords, realmID, id, func(c port.PasswordCredential) string { return c.RealmID }, "password")
	if err != nil {
		return err
	}
	if c.RevokedAt != nil {
		return errs.New(errs.KindNotFound, "password")
	}
	c = clonePassword(c)
	c.Hash = hash
	setKey(r.t, r.t.s.passwords, id, c)
	return nil
}

func (r passwords) Count(context.Context) (int, error) { return len(r.t.s.passwords), nil }

func (r passwords) Purge(_ context.Context, limit int) (int, error) {
	n := 0
	for id := range r.t.s.passwords {
		if n >= limit {
			break
		}
		deleteKey(r.t, r.t.s.passwords, id)
		n++
	}
	return n, nil
}

func (r passwords) Revoke(_ context.Context, realmID, id string, at time.Time, reason string) error {
	c, err := get(r.t.s.passwords, realmID, id, func(c port.PasswordCredential) string { return c.RealmID }, "password")
	if err != nil || c.RevokedAt != nil {
		return err
	}
	c = clonePassword(c)
	c.RevokedAt, c.RevokeReason = &at, reason
	setKey(r.t, r.t.s.passwords, id, c)
	return nil
}
