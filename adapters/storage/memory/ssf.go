package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID Shared Signals Framework（ADR 0118）。

type ssfSubject struct {
	RealmID, StreamID, Subject string
	CreatedAt                  time.Time
}

type ssfStreams struct{ t *tx }

func ssfKey(a, b string) string { return a + "\x00" + b }

func cloneSSFStream(s port.SSFStream) port.SSFStream {
	s.EventsRequested, s.EventsDelivered = nonNilList(s.EventsRequested), nonNilList(s.EventsDelivered)
	s.AuthorizationCiphertext = bytes.Clone(s.AuthorizationCiphertext)
	if len(s.AuthorizationCiphertext) == 0 {
		s.AuthorizationCiphertext = nil
	}
	s.NextAttemptAt, s.LastDeliveredAt = cloneTimePtr(s.NextAttemptAt), cloneTimePtr(s.LastDeliveredAt)
	return s
}

func (r ssfStreams) Create(_ context.Context, s port.SSFStream) error {
	for _, x := range r.t.s.ssfStreams {
		if x.ID == s.ID {
			return errs.New(errs.KindConflict, "ssf stream exists")
		}
	}
	setKey(r.t, r.t.s.ssfStreams, ssfKey(s.RealmID, s.ID), cloneSSFStream(s))
	return nil
}

func (r ssfStreams) Get(_ context.Context, realmID, id string) (port.SSFStream, error) {
	s, ok := r.t.s.ssfStreams[ssfKey(realmID, id)]
	if !ok {
		return port.SSFStream{}, errs.New(errs.KindNotFound, "ssf stream")
	}
	return cloneSSFStream(s), nil
}

func (r ssfStreams) List(_ context.Context, realmID string) ([]port.SSFStream, error) {
	out := []port.SSFStream{}
	for _, s := range r.t.s.ssfStreams {
		if s.RealmID == realmID {
			out = append(out, cloneSSFStream(s))
		}
	}
	sortByCreated(out, func(s port.SSFStream) (time.Time, string) { return s.CreatedAt, s.ID })
	return out, nil
}

func (r ssfStreams) Update(_ context.Context, s port.SSFStream) error {
	k := ssfKey(s.RealmID, s.ID)
	cur, ok := r.t.s.ssfStreams[k]
	if !ok {
		return errs.New(errs.KindNotFound, "ssf stream")
	}
	cur.DeliveryMethod, cur.EndpointURL, cur.AuthorizationCiphertext = s.DeliveryMethod, s.EndpointURL, s.AuthorizationCiphertext
	cur.EventsRequested, cur.EventsDelivered, cur.Description = s.EventsRequested, s.EventsDelivered, s.Description
	cur.Status, cur.StatusReason, cur.UpdatedAt = s.Status, s.StatusReason, s.UpdatedAt
	setKey(r.t, r.t.s.ssfStreams, k, cloneSSFStream(cur))
	return nil
}

func (r ssfStreams) SetDelivery(_ context.Context, realmID, id string, d port.SSFStreamDelivery) error {
	k := ssfKey(realmID, id)
	cur, ok := r.t.s.ssfStreams[k]
	if !ok {
		return errs.New(errs.KindNotFound, "ssf stream")
	}
	cursor := max(cur.CursorSeq, d.CursorSeq)
	cur.SSFStreamDelivery = d
	cur.CursorSeq = cursor
	setKey(r.t, r.t.s.ssfStreams, k, cloneSSFStream(cur))
	return nil
}

func (r ssfStreams) Delete(_ context.Context, realmID, id string) error {
	k := ssfKey(realmID, id)
	if _, ok := r.t.s.ssfStreams[k]; !ok {
		return errs.New(errs.KindNotFound, "ssf stream")
	}
	deleteKey(r.t, r.t.s.ssfStreams, k)
	r.dropChildren(id)
	return nil
}

func (r ssfStreams) dropChildren(streamID string) {
	for k, x := range r.t.s.ssfSubjects {
		if x.StreamID == streamID {
			deleteKey(r.t, r.t.s.ssfSubjects, k)
		}
	}
	for k, x := range r.t.s.ssfPoll {
		if x.StreamID == streamID {
			deleteKey(r.t, r.t.s.ssfPoll, k)
		}
	}
}

func (r ssfStreams) DuePush(_ context.Context, now time.Time, limit int) ([]port.SSFStream, error) {
	out := []port.SSFStream{}
	for _, s := range r.t.s.ssfStreams {
		if s.DeliveryMethod == port.SSFDeliveryPush && s.Status == port.SSFStatusEnabled && (s.NextAttemptAt == nil || !s.NextAttemptAt.After(now)) {
			out = append(out, cloneSSFStream(s))
		}
	}
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

func (r ssfStreams) AddSubject(_ context.Context, realmID, streamID, subject string, at time.Time) error {
	k := ssfKey(streamID, subject)
	if _, ok := r.t.s.ssfSubjects[k]; ok {
		return nil
	}
	setKey(r.t, r.t.s.ssfSubjects, k, ssfSubject{RealmID: realmID, StreamID: streamID, Subject: subject, CreatedAt: at})
	return nil
}

func (r ssfStreams) RemoveSubject(_ context.Context, realmID, streamID, subject string) error {
	k := ssfKey(streamID, subject)
	if x, ok := r.t.s.ssfSubjects[k]; !ok || x.RealmID != realmID {
		return errs.New(errs.KindNotFound, "ssf subject")
	}
	deleteKey(r.t, r.t.s.ssfSubjects, k)
	return nil
}

func (r ssfStreams) HasSubject(_ context.Context, realmID, streamID, subject string) (bool, error) {
	x, ok := r.t.s.ssfSubjects[ssfKey(streamID, subject)]
	return ok && x.RealmID == realmID, nil
}

func (r ssfStreams) CountSubjects(_ context.Context, realmID, streamID string) (int, error) {
	n := 0
	for _, x := range r.t.s.ssfSubjects {
		if x.RealmID == realmID && x.StreamID == streamID {
			n++
		}
	}
	return n, nil
}

func (r ssfStreams) RemoveSubjectEverywhere(_ context.Context, realmID, subject string) (int, error) {
	n := 0
	for k, x := range r.t.s.ssfSubjects {
		if x.RealmID == realmID && x.Subject == subject {
			deleteKey(r.t, r.t.s.ssfSubjects, k)
			n++
		}
	}
	return n, nil
}

func (r ssfStreams) AddPollEvents(_ context.Context, evs []port.SSFPollEvent) error {
	for _, e := range evs {
		k := ssfKey(e.StreamID, e.JTI)
		if _, ok := r.t.s.ssfPoll[k]; ok {
			continue
		}
		setKey(r.t, r.t.s.ssfPoll, k, e)
	}
	return nil
}

func (r ssfStreams) ListPollEvents(_ context.Context, realmID, streamID string, limit int) ([]port.SSFPollEvent, error) {
	out := []port.SSFPollEvent{}
	for _, e := range r.t.s.ssfPoll {
		if e.RealmID == realmID && e.StreamID == streamID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].JTI < out[j].JTI
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r ssfStreams) CountPollEvents(_ context.Context, realmID, streamID string) (int, error) {
	n := 0
	for _, e := range r.t.s.ssfPoll {
		if e.RealmID == realmID && e.StreamID == streamID {
			n++
		}
	}
	return n, nil
}

func (r ssfStreams) AckPollEvents(_ context.Context, realmID, streamID string, jtis []string) (int, error) {
	n := 0
	for _, j := range jtis {
		k := ssfKey(streamID, j)
		if e, ok := r.t.s.ssfPoll[k]; ok && e.RealmID == realmID {
			deleteKey(r.t, r.t.s.ssfPoll, k)
			n++
		}
	}
	return n, nil
}

func (r ssfStreams) Count(context.Context) (int, error) { return len(r.t.s.ssfStreams), nil }

func (r ssfStreams) Purge(_ context.Context, limit int) ([]string, error) {
	keys := make([]string, 0, len(r.t.s.ssfStreams))
	for k := range r.t.s.ssfStreams {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return r.t.s.ssfStreams[keys[i]].ID < r.t.s.ssfStreams[keys[j]].ID })
	ids := []string{}
	for _, k := range keys {
		if len(ids) >= limit {
			break
		}
		id := r.t.s.ssfStreams[k].ID
		deleteKey(r.t, r.t.s.ssfStreams, k)
		r.dropChildren(id)
		ids = append(ids, id)
	}
	return ids, nil
}

type ssfTransmitters struct{ t *tx }

func cloneSSFTransmitter(x port.SSFTransmitter) port.SSFTransmitter {
	x.Config, x.PushTokenHash = bytes.Clone(x.Config), bytes.Clone(x.PushTokenHash)
	return x
}

func (r ssfTransmitters) conflict(x port.SSFTransmitter) bool {
	for _, o := range r.t.s.ssfTransmitters {
		if o.RealmID == x.RealmID && o.Issuer == x.Issuer && o.ID != x.ID {
			return true
		}
	}
	return false
}

func (r ssfTransmitters) Create(_ context.Context, x port.SSFTransmitter) error {
	for _, o := range r.t.s.ssfTransmitters {
		if o.ID == x.ID {
			return errs.New(errs.KindConflict, "ssf transmitter exists")
		}
	}
	if r.conflict(x) {
		return errs.New(errs.KindConflict, "ssf transmitter exists")
	}
	setKey(r.t, r.t.s.ssfTransmitters, ssfKey(x.RealmID, x.ID), cloneSSFTransmitter(x))
	return nil
}

func (r ssfTransmitters) Get(_ context.Context, realmID, id string) (port.SSFTransmitter, error) {
	x, ok := r.t.s.ssfTransmitters[ssfKey(realmID, id)]
	if !ok {
		return port.SSFTransmitter{}, errs.New(errs.KindNotFound, "ssf transmitter")
	}
	return cloneSSFTransmitter(x), nil
}

func (r ssfTransmitters) List(_ context.Context, realmID string) ([]port.SSFTransmitter, error) {
	out := []port.SSFTransmitter{}
	for _, x := range r.t.s.ssfTransmitters {
		if x.RealmID == realmID {
			out = append(out, cloneSSFTransmitter(x))
		}
	}
	sortByCreated(out, func(x port.SSFTransmitter) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r ssfTransmitters) Update(_ context.Context, x port.SSFTransmitter) error {
	k := ssfKey(x.RealmID, x.ID)
	cur, ok := r.t.s.ssfTransmitters[k]
	if !ok {
		return errs.New(errs.KindNotFound, "ssf transmitter")
	}
	if r.conflict(x) {
		return errs.New(errs.KindConflict, "ssf transmitter exists")
	}
	x.CreatedAt = cur.CreatedAt
	setKey(r.t, r.t.s.ssfTransmitters, k, cloneSSFTransmitter(x))
	return nil
}

func (r ssfTransmitters) Delete(_ context.Context, realmID, id string) error {
	k := ssfKey(realmID, id)
	if _, ok := r.t.s.ssfTransmitters[k]; !ok {
		return errs.New(errs.KindNotFound, "ssf transmitter")
	}
	deleteKey(r.t, r.t.s.ssfTransmitters, k)
	return nil
}

func (r ssfTransmitters) Count(context.Context) (int, error) { return len(r.t.s.ssfTransmitters), nil }

func (r ssfTransmitters) Purge(_ context.Context, limit int) (int, error) {
	return purgeSorted(r.t, r.t.s.ssfTransmitters, limit), nil
}

type devicePostures struct{ t *tx }

func devicePostureKey(realmID, userID, deviceID string) string {
	return realmID + "\x00" + userID + "\x00" + deviceID
}

func (r devicePostures) Set(_ context.Context, p port.DevicePosture) (bool, error) {
	k := devicePostureKey(p.RealmID, p.UserID, p.DeviceID)
	if cur, ok := r.t.s.devicePostures[k]; ok && cur.EventAt.After(p.EventAt) {
		return false, nil
	}
	setKey(r.t, r.t.s.devicePostures, k, p)
	return true, nil
}

func (r devicePostures) Get(_ context.Context, realmID, userID, deviceID string) (port.DevicePosture, error) {
	p, ok := r.t.s.devicePostures[devicePostureKey(realmID, userID, deviceID)]
	if !ok {
		return port.DevicePosture{}, errs.New(errs.KindNotFound, "device posture")
	}
	return p, nil
}

func (r devicePostures) ListByUser(_ context.Context, realmID, userID string) ([]port.DevicePosture, error) {
	out := []port.DevicePosture{}
	for _, p := range r.t.s.devicePostures {
		if p.RealmID == realmID && p.UserID == userID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (r devicePostures) deleteWhere(match func(port.DevicePosture) bool) int {
	n := 0
	for k, p := range r.t.s.devicePostures {
		if match(p) {
			deleteKey(r.t, r.t.s.devicePostures, k)
			n++
		}
	}
	return n
}

func (r devicePostures) DeleteByUser(_ context.Context, realmID, userID string) (int, error) {
	return r.deleteWhere(func(p port.DevicePosture) bool { return p.RealmID == realmID && p.UserID == userID }), nil
}

func (r devicePostures) DeleteBySource(_ context.Context, realmID, source string) (int, error) {
	return r.deleteWhere(func(p port.DevicePosture) bool { return p.RealmID == realmID && p.Source == source }), nil
}

func (r devicePostures) Count(context.Context) (int, error) { return len(r.t.s.devicePostures), nil }

func (r devicePostures) Purge(_ context.Context, limit int) (int, error) {
	return purgeSorted(r.t, r.t.s.devicePostures, limit), nil
}
