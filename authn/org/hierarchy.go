package org

import (
	"context"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 階層（design.md 11.4、ADR 0078）。親 Org のロールを子に効かせる（判定は authz/check）。
// 祖先の一覧は書き込み時に計算する（持ち方はアダプタが決める）。深さに上限があり、循環は作れない。

// HierarchyFeature は Org 階層の宣言（features/orghierarchy が登録する）。
var HierarchyFeature = feature.Feature{Name: feature.OrgHierarchy, DataVersion: 1, Requires: []string{feature.Org}}

// MaxDepth は階層の段数の上限（根を含む）。
const MaxDepth = 5

// 監査ログの出来事。
const (
	EventParentSet     = "org.parent_set"
	EventParentCleared = "org.parent_cleared"
)

// エラー。
var (
	ErrHierarchyCycle   = errs.WithCode(errs.KindFailedPrecondition, "hierarchy_cycle", "the org cannot be its own ancestor")
	ErrHierarchyTooDeep = errs.WithCode(errs.KindFailedPrecondition, "hierarchy_too_deep", "the org hierarchy would be too deep")
	ErrOrgDeleted       = errs.WithCode(errs.KindFailedPrecondition, "org_deleted", "the org is deleted")
)

// SetParent は o の親を parent にする（nil なら外す）。個人 Org と削除した Org は扱えない。
// 同じ親なら何もしない。parent が o か o の子孫なら ErrHierarchyCycle、段数が MaxDepth を超えるなら ErrHierarchyTooDeep。
func (s *Service) SetParent(ctx context.Context, tx port.Tx, o port.Org, parent *port.Org, actor audit.Actor, requestID string) (port.Org, error) {
	for _, x := range []*port.Org{&o, parent} {
		switch {
		case x == nil:
		case x.Kind == port.OrgPersonal:
			return port.Org{}, ErrPersonalOrg
		case x.DeletedAt != nil:
			return port.Org{}, ErrOrgDeleted
		}
	}
	parentID := ""
	if parent != nil {
		parentID = parent.ID
		if parent.ID == o.ID {
			return port.Org{}, ErrHierarchyCycle
		}
		up, err := tx.Orgs().Ancestors(ctx, o.RealmID, parent.ID)
		if err != nil {
			return port.Org{}, err
		}
		if slices.Contains(up, o.ID) {
			return port.Org{}, ErrHierarchyCycle
		}
		h, err := tx.Orgs().SubtreeHeight(ctx, o.RealmID, o.ID)
		if err != nil {
			return port.Org{}, err
		}
		// 段数：親の祖先 + 親 + o + o の下の段。
		if len(up)+2+h > MaxDepth {
			return port.Org{}, ErrHierarchyTooDeep
		}
	}
	if o.ParentID == parentID {
		return o, nil
	}
	now := s.Clock.Now()
	if err := tx.Orgs().SetParent(ctx, o.RealmID, o.ID, parentID, now); err != nil {
		return port.Org{}, err
	}
	typ, details := EventParentCleared, map[string]any{}
	if parent != nil {
		typ, details["parent_id"] = EventParentSet, parent.PublicID
	}
	if _, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID,
		Actor: actor, RequestID: requestID, Details: details}); err != nil {
		return port.Org{}, err
	}
	o.ParentID, o.UpdatedAt = parentID, now
	return o, nil
}

// detachHierarchy は Org の削除で、o を親から外し、子を根にする。
func (s *Service) detachHierarchy(ctx context.Context, tx port.Tx, o port.Org, now time.Time) error {
	cs, err := tx.Orgs().ListChildren(ctx, o.RealmID, o.ID)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if err := tx.Orgs().SetParent(ctx, c.RealmID, c.ID, "", now); err != nil {
			return err
		}
	}
	if o.ParentID == "" {
		return nil
	}
	return tx.Orgs().SetParent(ctx, o.RealmID, o.ID, "", now)
}

// ClearParent は Org の親を外す（フィーチャーの無効化の片付け。11.12）。外したら true。
func ClearParent(ctx context.Context, tx port.Tx, o port.Org, now time.Time) (bool, error) {
	if o.ParentID == "" {
		return false, nil
	}
	return true, tx.Orgs().SetParent(ctx, o.RealmID, o.ID, "", now)
}
