package memory

import (
	"context"
	"slices"
	"sort"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type attributes struct{ t *tx }

func attrKey(parts ...string) string {
	k := ""
	for i, p := range parts {
		if i > 0 {
			k += "\x00"
		}
		k += p
	}
	return k
}

func cloneDef(d port.AttributeDef) port.AttributeDef {
	d.Values = slices.Clone(d.Values)
	if d.Values == nil {
		d.Values = []string{}
	}
	return d
}

func (r attributes) CreateDef(_ context.Context, d port.AttributeDef) error {
	k := attrKey(d.RealmID, d.Key)
	if _, ok := r.t.s.attrDefs[k]; ok {
		return errs.New(errs.KindConflict, "attribute exists")
	}
	setKey(r.t, r.t.s.attrDefs, k, cloneDef(d))
	return nil
}

func (r attributes) GetDef(_ context.Context, realmID, key string) (port.AttributeDef, error) {
	d, ok := r.t.s.attrDefs[attrKey(realmID, key)]
	if !ok {
		return port.AttributeDef{}, errs.New(errs.KindNotFound, "attribute")
	}
	return cloneDef(d), nil
}

func (r attributes) ListDefs(_ context.Context, realmID string) ([]port.AttributeDef, error) {
	out := []port.AttributeDef{}
	for _, d := range r.t.s.attrDefs {
		if d.RealmID == realmID {
			out = append(out, cloneDef(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (r attributes) UpdateDef(_ context.Context, d port.AttributeDef) error {
	k := attrKey(d.RealmID, d.Key)
	old, ok := r.t.s.attrDefs[k]
	if !ok {
		return errs.New(errs.KindNotFound, "attribute")
	}
	old.Values, old.MaxLength, old.UserEditable, old.InToken, old.UpdatedAt = d.Values, d.MaxLength, d.UserEditable, d.InToken, d.UpdatedAt
	setKey(r.t, r.t.s.attrDefs, k, cloneDef(old))
	return nil
}

func (r attributes) DeleteDef(_ context.Context, realmID, key string) error {
	k := attrKey(realmID, key)
	if _, ok := r.t.s.attrDefs[k]; !ok {
		return errs.New(errs.KindNotFound, "attribute")
	}
	eraseWhere(r.t, r.t.s.attrValues, func(a port.UserAttribute) bool { return a.RealmID == realmID && a.Key == key })
	deleteKey(r.t, r.t.s.attrDefs, k)
	return nil
}

func (r attributes) ListValues(_ context.Context, realmID, userID string) ([]port.UserAttribute, error) {
	out := []port.UserAttribute{}
	for _, a := range r.t.s.attrValues {
		if a.RealmID == realmID && a.UserID == userID {
			a.Value = slices.Clone(a.Value)
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (r attributes) SetValue(_ context.Context, a port.UserAttribute) error {
	a.Value = slices.Clone(a.Value)
	setKey(r.t, r.t.s.attrValues, attrKey(a.RealmID, a.UserID, a.Key), a)
	return nil
}

func (r attributes) DeleteValue(_ context.Context, realmID, userID, key string) error {
	deleteKey(r.t, r.t.s.attrValues, attrKey(realmID, userID, key))
	return nil
}

func (r attributes) Count(context.Context) (int, error) {
	return len(r.t.s.attrDefs) + len(r.t.s.attrValues), nil
}

func (r attributes) Purge(_ context.Context, limit int) (int, error) {
	n := 0
	for k := range r.t.s.attrValues {
		if n >= limit {
			return n, nil
		}
		deleteKey(r.t, r.t.s.attrValues, k)
		n++
	}
	for k := range r.t.s.attrDefs {
		if n >= limit {
			break
		}
		deleteKey(r.t, r.t.s.attrDefs, k)
		n++
	}
	return n, nil
}
