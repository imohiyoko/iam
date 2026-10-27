package manage

import (
	"context"
	"slices"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Group のネスト（design.md 11.5、ADR 0079）。Group を同じ範囲の Group の所属にでき、含む Group の付与が効く（判定は
// authz/check）。含む Group の一覧（閉包）は書き込み時にここで計算し、Repository に置く。段数に上限があり、循環は作れない。

// NestedGroupsFeature は Group のネストの宣言（features/nestedgroups が登録する）。
var NestedGroupsFeature = feature.Feature{Name: feature.NestedGroups, DataVersion: 1}

// MaxGroupDepth は入れ子の段数の上限（いちばん外の Group を含む）。
const MaxGroupDepth = 5

// エラー。
var (
	ErrGroupCycle   = errs.WithCode(errs.KindFailedPrecondition, "group_cycle", "the group cannot contain itself")
	ErrGroupTooDeep = errs.WithCode(errs.KindFailedPrecondition, "group_too_deep", "the groups would be nested too deeply")
)

// checkNesting は child を g に入れられるかを確かめる。child は g と同じ範囲の Group。
func checkNesting(ctx context.Context, tx port.Tx, realmID string, g, child port.Group) error {
	if child.OrgID != g.OrgID {
		return ErrInvalidPrincipal
	}
	if child.ID == g.ID {
		return ErrGroupCycle
	}
	down, err := tx.Groups().Descendants(ctx, realmID, child.ID)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(down, func(l port.GroupLink) bool { return l.GroupID == g.ID }) {
		return ErrGroupCycle
	}
	up, err := tx.Groups().Ancestors(ctx, realmID, g.ID)
	if err != nil {
		return err
	}
	// 段数：g の上の段 + g + child + child の下の段。
	if maxDepth(up)+2+maxDepth(down) > MaxGroupDepth {
		return ErrGroupTooDeep
	}
	return nil
}

func maxDepth(ls []port.GroupLink) int {
	d := 0
	for _, l := range ls {
		d = max(d, l.Depth)
	}
	return d
}

// rebuild は roots とその子孫の閉包を、Group としての所属から計算し直す。子孫は変更の前に集めて渡す。
func rebuild(ctx context.Context, tx port.Tx, realmID string, roots []string) error {
	parents := map[string][]string{}
	parentsOf := func(id string) ([]string, error) {
		if ps, ok := parents[id]; ok {
			return ps, nil
		}
		gs, err := tx.Groups().ListByMember(ctx, realmID, port.PrincipalGroup, id)
		if err != nil {
			return nil, err
		}
		ps := make([]string, 0, len(gs))
		for _, g := range gs {
			ps = append(ps, g.ID)
		}
		parents[id] = ps
		return ps, nil
	}
	for _, id := range roots {
		// 最も長い経路の段数。段数の上限があるので、たどる経路は限られる。
		depth := map[string]int{}
		var walk func(id string, d int) error
		walk = func(id string, d int) error {
			ps, err := parentsOf(id)
			if err != nil {
				return err
			}
			if d >= 2*MaxGroupDepth {
				return errs.New(errs.KindInternal, "group nesting has a cycle")
			}
			for _, p := range ps {
				if d+1 > depth[p] {
					depth[p] = d + 1
					if err := walk(p, d+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(id, 0); err != nil {
			return err
		}
		ls := make([]port.GroupLink, 0, len(depth))
		for g, d := range depth {
			ls = append(ls, port.GroupLink{GroupID: g, Depth: d})
		}
		if err := tx.Groups().SetAncestors(ctx, realmID, id, ls); err != nil {
			return err
		}
	}
	return nil
}

// subtree は id とその子孫。
func subtree(ctx context.Context, tx port.Tx, realmID, id string) ([]string, error) {
	down, err := tx.Groups().Descendants(ctx, realmID, id)
	if err != nil {
		return nil, err
	}
	out := []string{id}
	for _, l := range down {
		out = append(out, l.GroupID)
	}
	return out, nil
}
