package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// 操作の要件（ADR 0084）。realm の中の操作の名前空間ごとの要件（と段階の境界）と、Org の要件。どの付与で許されたかに
// 関係なく、操作に条件を求める。要件は attested() を暗黙に AND する（EvalRequirement）。

// ResourceActionNamespace は名前空間の設定を変える権限（requirements:manage）を、1つの名前空間に限って付与するときの
// リソースの種類（resource_id は名前空間の名前）。
const ResourceActionNamespace = "action_namespace"

// MaxRequirements は1つの名前空間・Org に書ける要件の数。
const MaxRequirements = 64

var namespaceRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// ValidNamespace は名前空間の名前の形（権限の `<リソース>` と同じ）かを返す。
func ValidNamespace(name string) bool { return namespaceRE.MatchString(name) }

// NamespaceOf は操作の名前空間（`payment:send` なら `payment`）。
func NamespaceOf(action string) string {
	ns, _, _ := strings.Cut(action, ":")
	return ns
}

// Requirements は要件（操作 → 条件）。操作はワイルドカード（`payment:*`）でもよい。同じ操作に当たる要件はすべて AND する。
type Requirements map[string]Condition

// matching は action に当たる要件を、操作の順に返す。
func (rs Requirements) matching(action string) []Condition {
	var out []Condition
	for _, k := range slices.Sorted(maps.Keys(rs)) {
		if role.Matches(k, action) {
			out = append(out, rs[k])
		}
	}
	return out
}

// RiskTypes は要件が見るリスクの種類（重複なし、整列）。
func (rs Requirements) RiskTypes() []string {
	var out []string
	for _, c := range rs {
		out = append(out, c.RiskTypes()...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Validate は要件を保存の前に確かめる。namespace が空でなければ、操作はその名前空間のものだけ（Org の要件は空で、
// どの名前空間でもよい）。外れていれば errs.KindInvalid（コード invalid_requirement か invalid_condition）。
func (rs Requirements) Validate(namespace string, riskType func(string) bool) error {
	if len(rs) > MaxRequirements {
		return errs.WithCode(errs.KindInvalid, "invalid_requirement", fmt.Sprintf("at most %d requirements", MaxRequirements))
	}
	for _, k := range slices.Sorted(maps.Keys(rs)) {
		if !role.ValidPermission(k) || (namespace != "" && NamespaceOf(k) != namespace) {
			return errs.WithCode(errs.KindInvalid, "invalid_requirement", "invalid action "+k)
		}
		if err := rs[k].Validate(riskType); err != nil {
			return err
		}
	}
	return nil
}

// Namespace は操作の名前空間の設定（realm の設定。ADR 0084）。
type Namespace struct {
	Requirements Requirements `json:"requirements,omitempty"`
	// Bands は種類ごとの段階の境界。realm の境界を厳しくする方向だけ変えられる。
	Bands map[string]risk.Band `json:"bands,omitempty"`
}

// Validate は名前空間の設定を保存の前に確かめる。cat は realm のリスクの種類の一覧。
func (n Namespace) Validate(name string, cat risk.Catalog) error {
	if !ValidNamespace(name) {
		return errs.WithCode(errs.KindInvalid, "invalid_namespace", "invalid action namespace")
	}
	if err := n.Requirements.Validate(name, cat.Enabled); err != nil {
		return err
	}
	for _, t := range slices.Sorted(maps.Keys(n.Bands)) {
		b := n.Bands[t]
		if !cat.Enabled(t) {
			return errs.WithCode(errs.KindInvalid, "invalid_band", "unknown or disabled risk type "+t)
		}
		if !b.Valid() || !b.Stricter(cat[t].Band) {
			return errs.WithCode(errs.KindInvalid, "invalid_band", "band of "+t+" must satisfy 1 <= medium < high <= 100 and be no looser than the realm's")
		}
	}
	return nil
}

// RiskTypes は設定が見るリスクの種類（要件と境界。重複なし、整列）。
func (n Namespace) RiskTypes() []string {
	out := append(n.Requirements.RiskTypes(), slices.Collect(maps.Keys(n.Bands))...)
	slices.Sort(out)
	return slices.Compact(out)
}

// ParseNamespace は保存した名前空間の設定を読む。空なら設定なし。
func ParseNamespace(raw []byte) (Namespace, error) {
	var n Namespace
	if len(raw) == 0 {
		return n, nil
	}
	return n, json.Unmarshal(raw, &n)
}

// OrgRequirements は Org の設定（JSON。authn/org が形を決める）の requirements を読む。
func OrgRequirements(settings []byte) (Requirements, error) {
	if len(settings) == 0 {
		return nil, nil
	}
	var st struct {
		Requirements Requirements `json:"requirements"`
	}
	if err := json.Unmarshal(settings, &st); err != nil {
		return nil, err
	}
	return st.Requirements, nil
}

// bandsWith は realm の境界に名前空間の境界を重ねる。
func bandsWith(realm Bands, ns map[string]risk.Band) Bands {
	if len(ns) == 0 {
		return realm
	}
	out := maps.Clone(realm)
	if out == nil {
		out = Bands{}
	}
	maps.Copy(out, ns)
	return out
}

// requirements は1つの判定に効く要件：操作の名前空間の設定と、判定の Org（階層がオンなら祖先も）の要件。
type requirements struct {
	namespace Namespace
	orgs      []Requirements
}

// matching は action に当たる要件（名前空間、Org の順）。
func (r requirements) matching(action string) []Condition {
	out := r.namespace.Requirements.matching(action)
	for _, o := range r.orgs {
		out = append(out, o.matching(action)...)
	}
	return out
}

// Requirements は名前空間 ns と Org（内部 ID。空なら realm の範囲）の要件を読む。保存したものが読めなければエラー（fail-closed）。
func (c *Checker) Requirements(ctx context.Context, tx port.Tx, realmID, ns, orgID string) (requirements, error) {
	var out requirements
	row, err := tx.ActionNamespaces().Get(ctx, realmID, ns)
	switch {
	case errors.Is(err, errs.NotFound):
	case err != nil:
		return out, err
	default:
		if out.namespace, err = ParseNamespace(row.Settings); err != nil {
			return out, fmt.Errorf("action namespace %s: %w", ns, err)
		}
	}
	if c.Members == nil || orgID == "" {
		return out, nil
	}
	scopes := []string{orgID}
	if c.Hierarchy {
		up, err := tx.Orgs().Ancestors(ctx, realmID, orgID)
		if err != nil {
			return out, err
		}
		scopes = append(scopes, up...)
	}
	for _, id := range scopes {
		o, err := tx.Orgs().Get(ctx, realmID, id)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return out, err
		}
		rs, err := OrgRequirements(o.Settings)
		if err != nil {
			return out, fmt.Errorf("org settings: %w", err)
		}
		if len(rs) > 0 {
			out.orgs = append(out.orgs, rs)
		}
	}
	return out, nil
}

type reqKey struct {
	realmID, ns, orgID string
}

type reqEntry struct {
	r   requirements
	exp time.Time
	gen uint64
}

// cachedRequirements は Requirements を TTL の間キャッシュする（realm・Org ごと。Invalidate で捨てる）。
func (c *Checker) cachedRequirements(ctx context.Context, realmID, ns, orgID string) (requirements, error) {
	load := func() (requirements, error) {
		var r requirements
		err := c.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			r, err = c.Requirements(ctx, tx, realmID, ns, orgID)
			return err
		})
		return r, err
	}
	if c.TTL <= 0 {
		return load()
	}
	k := reqKey{realmID, ns, orgID}
	now := c.Clock.Now()
	c.mu.Lock()
	e, hit := c.reqs[k]
	gen := c.gen[realmID]
	c.mu.Unlock()
	if hit && e.gen == gen && now.Before(e.exp) {
		return e.r, nil
	}
	r, err := load()
	if err != nil {
		return r, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen[realmID] != gen {
		return r, nil
	}
	limit := c.MaxEntries
	if limit <= 0 {
		limit = 100000
	}
	if c.reqs == nil || len(c.reqs) >= limit {
		c.reqs = map[reqKey]reqEntry{}
	}
	c.reqs[k] = reqEntry{r: r, exp: now.Add(c.TTL), gen: gen}
	return r, nil
}
