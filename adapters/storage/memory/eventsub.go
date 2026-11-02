package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// イベントの Webhook の購読（ADR 0100）。

type eventSubs struct{ t *tx }

func eventSubKey(realmID, id string) string { return realmID + "\x00" + id }

func cloneEventSub(s port.EventSubscription) port.EventSubscription {
	s.EventTypes = slices.Clone(s.EventTypes)
	if s.EventTypes == nil {
		s.EventTypes = []string{}
	}
	s.SecretCiphertext = bytes.Clone(s.SecretCiphertext)
	s.NextAttemptAt, s.LastDeliveredAt = cloneTimePtr(s.NextAttemptAt), cloneTimePtr(s.LastDeliveredAt)
	return s
}

func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func (r eventSubs) Create(_ context.Context, s port.EventSubscription) error {
	for _, e := range r.t.s.eventSubs {
		if e.ID == s.ID {
			return errs.New(errs.KindConflict, "event subscription exists")
		}
	}
	setKey(r.t, r.t.s.eventSubs, eventSubKey(s.RealmID, s.ID), cloneEventSub(s))
	return nil
}

func (r eventSubs) Get(_ context.Context, realmID, id string) (port.EventSubscription, error) {
	s, ok := r.t.s.eventSubs[eventSubKey(realmID, id)]
	if !ok {
		return port.EventSubscription{}, errs.New(errs.KindNotFound, "event subscription")
	}
	return cloneEventSub(s), nil
}

func (r eventSubs) List(_ context.Context, realmID string) ([]port.EventSubscription, error) {
	out := []port.EventSubscription{}
	for _, s := range r.t.s.eventSubs {
		if s.RealmID == realmID {
			out = append(out, cloneEventSub(s))
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

func (r eventSubs) Update(_ context.Context, s port.EventSubscription) error {
	k := eventSubKey(s.RealmID, s.ID)
	cur, ok := r.t.s.eventSubs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "event subscription")
	}
	cur.URL, cur.EventTypes, cur.PII, cur.Enabled = s.URL, s.EventTypes, s.PII, s.Enabled
	cur.SecretCiphertext, cur.UpdatedAt = s.SecretCiphertext, s.UpdatedAt
	setKey(r.t, r.t.s.eventSubs, k, cloneEventSub(cur))
	return nil
}

func (r eventSubs) SetDelivery(_ context.Context, realmID, id string, d port.EventSubscriptionDelivery) error {
	k := eventSubKey(realmID, id)
	cur, ok := r.t.s.eventSubs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "event subscription")
	}
	cursor := max(cur.CursorSeq, d.CursorSeq)
	cur.EventSubscriptionDelivery = d
	cur.CursorSeq = cursor
	setKey(r.t, r.t.s.eventSubs, k, cloneEventSub(cur))
	return nil
}

func (r eventSubs) Delete(_ context.Context, realmID, id string) error {
	k := eventSubKey(realmID, id)
	if _, ok := r.t.s.eventSubs[k]; !ok {
		return errs.New(errs.KindNotFound, "event subscription")
	}
	deleteKey(r.t, r.t.s.eventSubs, k)
	return nil
}

func (r eventSubs) Due(_ context.Context, now time.Time, limit int) ([]port.EventSubscription, error) {
	out := []port.EventSubscription{}
	for _, s := range r.t.s.eventSubs {
		if s.Enabled && (s.NextAttemptAt == nil || !s.NextAttemptAt.After(now)) {
			out = append(out, cloneEventSub(s))
		}
	}
	// 試す時刻の無いもの（新しい購読・成功の後）を先に、あとは早い順。同じなら ID の順。
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].NextAttemptAt, out[j].NextAttemptAt
		switch {
		case a == nil && b != nil:
			return true
		case a != nil && b == nil:
			return false
		case a != nil && !a.Equal(*b):
			return a.Before(*b)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r eventSubs) Count(context.Context) (int, error) { return len(r.t.s.eventSubs), nil }

func (r eventSubs) Purge(_ context.Context, limit int) ([]string, error) {
	keys := make([]string, 0, len(r.t.s.eventSubs))
	for k := range r.t.s.eventSubs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []string{}
	for _, k := range keys {
		if len(out) >= limit {
			break
		}
		out = append(out, r.t.s.eventSubs[k].ID)
		deleteKey(r.t, r.t.s.eventSubs, k)
	}
	return out, nil
}
