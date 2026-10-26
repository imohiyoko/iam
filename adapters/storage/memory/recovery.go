package memory

import (
	"context"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type recoveryCodes struct{ t *tx }

func cloneRecoveryCode(c port.RecoveryCode) port.RecoveryCode {
	c.UsedAt = cloneTime(c.UsedAt)
	return c
}

func (r recoveryCodes) Replace(_ context.Context, realmID, userID string, codes []port.RecoveryCode) error {
	for id, c := range r.t.s.recoveryCodes {
		if c.RealmID == realmID && c.UserID == userID {
			deleteKey(r.t, r.t.s.recoveryCodes, id)
		}
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if _, ok := r.t.s.recoveryCodes[c.ID]; ok || seen[c.Lookup] || c.RealmID != realmID || c.UserID != userID {
			return errs.New(errs.KindConflict, "recovery code %s", c.ID)
		}
		seen[c.Lookup] = true
		setKey(r.t, r.t.s.recoveryCodes, c.ID, cloneRecoveryCode(c))
	}
	return nil
}

func (r recoveryCodes) ListByUser(_ context.Context, realmID, userID string) ([]port.RecoveryCode, error) {
	var out []port.RecoveryCode
	for _, c := range r.t.s.recoveryCodes {
		if c.RealmID == realmID && c.UserID == userID {
			out = append(out, cloneRecoveryCode(c))
		}
	}
	sortByCreated(out, func(c port.RecoveryCode) (time.Time, string) { return time.Time{}, c.ID })
	return out, nil
}

func (r recoveryCodes) MarkUsed(_ context.Context, realmID, id string, at time.Time) (bool, error) {
	c, ok := r.t.s.recoveryCodes[id]
	if !ok || c.RealmID != realmID || c.UsedAt != nil {
		return false, nil
	}
	c = cloneRecoveryCode(c)
	c.UsedAt = &at
	setKey(r.t, r.t.s.recoveryCodes, id, c)
	return true, nil
}
