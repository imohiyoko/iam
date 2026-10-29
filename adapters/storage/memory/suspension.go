package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type suspensions struct{ t *tx }

func cloneSuspension(s port.Suspension) port.Suspension {
	s.EndsAt, s.LiftedAt = cloneTime(s.EndsAt), cloneTime(s.LiftedAt)
	return s
}

func (r suspensions) Create(_ context.Context, s port.Suspension) error {
	if _, ok := r.t.s.suspensions[s.ID]; ok {
		return errs.New(errs.KindConflict, "suspension %s exists", s.ID)
	}
	for _, x := range r.t.s.suspensions {
		if x.RealmID != s.RealmID {
			continue
		}
		if x.PublicID == s.PublicID {
			return errs.New(errs.KindConflict, "suspension public id exists in realm")
		}
		if s.ExternalRef != "" && x.ExternalRef == s.ExternalRef && x.TargetType == s.TargetType && x.TargetID == s.TargetID && x.Category == s.Category {
			return errs.New(errs.KindConflict, "suspension external ref exists")
		}
	}
	setKey(r.t, r.t.s.suspensions, s.ID, cloneSuspension(s))
	return nil
}

func (r suspensions) GetByPublicID(_ context.Context, realmID, publicID string) (port.Suspension, error) {
	for _, x := range r.t.s.suspensions {
		if x.RealmID == realmID && x.PublicID == publicID {
			return cloneSuspension(x), nil
		}
	}
	return port.Suspension{}, errs.New(errs.KindNotFound, "suspension")
}

func (r suspensions) ListByTarget(_ context.Context, realmID string, t port.SuspensionTarget, targetID string) ([]port.Suspension, error) {
	var out []port.Suspension
	for _, x := range r.t.s.suspensions {
		if x.RealmID == realmID && x.TargetType == t && x.TargetID == targetID {
			out = append(out, cloneSuspension(x))
		}
	}
	sortByCreated(out, func(x port.Suspension) (time.Time, string) { return x.StartsAt, x.ID })
	return out, nil
}

func (r suspensions) Lift(_ context.Context, realmID, id string, at time.Time, by string) error {
	s, err := get(r.t.s.suspensions, realmID, id, func(s port.Suspension) string { return s.RealmID }, "suspension")
	if err != nil || s.LiftedAt != nil {
		return err
	}
	s = cloneSuspension(s)
	s.LiftedAt, s.LiftedBy = &at, by
	setKey(r.t, r.t.s.suspensions, id, s)
	return nil
}

// ---------------------------------------------------------------------------

type scheduledEvents struct{ t *tx }

func cloneScheduled(e port.ScheduledEvent) port.ScheduledEvent {
	e.Payload, e.FiredAt = bytes.Clone(e.Payload), cloneTime(e.FiredAt)
	return e
}

func (r scheduledEvents) Schedule(_ context.Context, e port.ScheduledEvent) error {
	if _, ok := r.t.s.scheduled[e.ID]; ok {
		return errs.New(errs.KindConflict, "scheduled event %s exists", e.ID)
	}
	setKey(r.t, r.t.s.scheduled, e.ID, cloneScheduled(e))
	return nil
}

func (r scheduledEvents) Due(_ context.Context, now time.Time, limit int) ([]port.ScheduledEvent, error) {
	var out []port.ScheduledEvent
	for _, e := range r.t.s.scheduled {
		if e.FiredAt == nil && !e.FireAt.After(now) {
			out = append(out, cloneScheduled(e))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FireAt.Equal(out[j].FireAt) {
			return out[i].FireAt.Before(out[j].FireAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r scheduledEvents) MarkFired(_ context.Context, realmID, id string, at time.Time) (bool, error) {
	e, ok := r.t.s.scheduled[id]
	if !ok || e.RealmID != realmID || e.FiredAt != nil {
		return false, nil
	}
	e = cloneScheduled(e)
	e.FiredAt = &at
	setKey(r.t, r.t.s.scheduled, id, e)
	return true, nil
}

func (r scheduledEvents) DeleteFired(_ context.Context, before time.Time, limit int) (int, error) {
	n := 0
	for id, e := range r.t.s.scheduled {
		if n < limit && e.FiredAt != nil && e.FiredAt.Before(before) {
			deleteKey(r.t, r.t.s.scheduled, id)
			n++
		}
	}
	return n, nil
}

func (r scheduledEvents) CancelByRef(_ context.Context, realmID, ref string) error {
	for id, e := range r.t.s.scheduled {
		if e.RealmID == realmID && e.Ref == ref && e.FiredAt == nil {
			deleteKey(r.t, r.t.s.scheduled, id)
		}
	}
	return nil
}
