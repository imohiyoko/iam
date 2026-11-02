package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// knownDevices は本人がログインした端末（ADR 0105）。
type knownDevices struct{ t *tx }

func cloneDevice(d port.KnownDevice) port.KnownDevice {
	d.Lookup, d.Data = bytes.Clone(d.Lookup), bytes.Clone(d.Data)
	return d
}

func (r knownDevices) Create(_ context.Context, d port.KnownDevice) error {
	if _, ok := r.t.s.devices[d.ID]; ok {
		return errs.New(errs.KindConflict, "device %s exists", d.ID)
	}
	for _, x := range r.t.s.devices {
		if x.RealmID != d.RealmID {
			continue
		}
		if x.PublicID == d.PublicID {
			return errs.New(errs.KindConflict, "device public id exists in realm")
		}
		if x.UserID == d.UserID && bytes.Equal(x.Lookup, d.Lookup) {
			return errs.New(errs.KindConflict, "device lookup exists for user")
		}
	}
	setKey(r.t, r.t.s.devices, d.ID, cloneDevice(d))
	return nil
}

func (r knownDevices) ListByUser(_ context.Context, realmID, userID string) ([]port.KnownDevice, error) {
	var out []port.KnownDevice
	for _, x := range r.t.s.devices {
		if x.RealmID == realmID && x.UserID == userID {
			out = append(out, cloneDevice(x))
		}
	}
	sortByCreated(out, func(x port.KnownDevice) (time.Time, string) { return x.CreatedAt, x.ID })
	return out, nil
}

func (r knownDevices) Seen(_ context.Context, realmID, id string, data []byte, at time.Time) error {
	d, err := get(r.t.s.devices, realmID, id, func(d port.KnownDevice) string { return d.RealmID }, "device")
	if err != nil {
		return err
	}
	d = cloneDevice(d)
	d.Data, d.LastSeenAt = bytes.Clone(data), at
	setKey(r.t, r.t.s.devices, id, d)
	return nil
}

func (r knownDevices) Delete(_ context.Context, realmID, id string) error {
	if _, err := get(r.t.s.devices, realmID, id, func(d port.KnownDevice) string { return d.RealmID }, "device"); err != nil {
		return err
	}
	deleteKey(r.t, r.t.s.devices, id)
	return nil
}

func (r knownDevices) DeleteByUser(_ context.Context, realmID, userID string) (int, error) {
	var keys []string
	for k, x := range r.t.s.devices {
		if x.RealmID == realmID && x.UserID == userID {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.devices, k)
	}
	return len(keys), nil
}

func (r knownDevices) Count(context.Context) (int, error) { return len(r.t.s.devices), nil }

func (r knownDevices) Purge(_ context.Context, limit int) (int, error) {
	keys := make([]string, 0, len(r.t.s.devices))
	for k := range r.t.s.devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:max(limit, 0)]
	}
	for _, k := range keys {
		deleteKey(r.t, r.t.s.devices, k)
	}
	return len(keys), nil
}
