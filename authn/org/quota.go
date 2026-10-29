package org

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Quota（design.md 11.14、フィーチャー quota、ADR 0070）。
//
// 上限は期間つきの付与の合算で、時刻ごとに決まる。時刻 t の上限 = 有効な override があればその値（新しいもの）、
// なければ有効な base（新しいもの）+ Σ addon。有効な付与が無ければ無制限。
// 判定は Membership の追加・招待・有効期間の変更・付与の変更のときに、同じトランザクションで行う（ホットパスでは判定しない）。
// 新しい人の有効期間のすべての時点で「その時点の人数 + 1 ≤ 上限」を満たすこと（区切りの時刻だけを調べる）。

func init() {
	feature.Register(feature.Feature{Name: feature.Quota, DataVersion: 1, Requires: []string{feature.Org}})
}

// QuotaMembers は Membership の数の Quota。
const QuotaMembers = "members"

// EventQuotaExceeded は IAM が拒否できない経路（外部の付与の上書き）で上限を下回ったときの監査ログ。既存のメンバーは外さない。
const EventQuotaExceeded = "org.quota.exceeded"

// MaxQuotaQuantity は付与の量の上限。
const MaxQuotaQuantity = 1 << 31

// QuotaCount は数えるもの（realm で設定）。active な Membership は必ず数える。
type QuotaCount struct {
	// Invited は受け入れ待ちの招待（期限内）を、受け入れて作る Membership の有効期間で数える。
	Invited bool
	// Future は有効期間がまだ始まっていない Membership を数える。
	Future bool
	// Suspended は停止中の Membership を、停止の間も数える。
	Suspended bool
}

// QuotaError は Quota が足りないこと。From から Until（nil は無期限）の間、上限 Limit に対して Count 人がいる。
// Adding は1人を足そうとした（追加・招待・有効期間の変更）。
type QuotaError struct {
	From   time.Time
	Until  *time.Time
	Limit  int64
	Count  int64
	Adding bool
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("org: quota exceeded from %s (limit %d, count %d)", e.From.Format(time.RFC3339), e.Limit, e.Count)
}

func (e *QuotaError) Unwrap() error {
	return &errs.Error{Kind: errs.KindConflict, Code: errs.CodeQuotaExceeded, Msg: "quota exceeded"}
}

// Shortage は足りない人数。
func (e *QuotaError) Shortage() int64 {
	n := e.Count - e.Limit
	if e.Adding {
		n++
	}
	return n
}

// 時刻は UnixNano で扱う。無期限は math.MinInt64 / math.MaxInt64。
const (
	minusInf = math.MinInt64
	plusInf  = math.MaxInt64
)

type span struct{ from, until int64 }

func spanOf(from, until *time.Time) span {
	s := span{minusInf, plusInf}
	if from != nil {
		s.from = from.UnixNano()
	}
	if until != nil {
		s.until = until.UnixNano()
	}
	return s
}

func (s span) covers(t int64) bool { return s.from <= t && t < s.until }

func toTime(t int64) *time.Time {
	if t == plusInf {
		return nil
	}
	v := time.Unix(0, t).UTC()
	return &v
}

// subtract は s から cut を除いた区間を返す。
func subtract(spans []span, cut span) []span {
	var out []span
	for _, s := range spans {
		if cut.until <= s.from || s.until <= cut.from {
			out = append(out, s)
			continue
		}
		if s.from < cut.from {
			out = append(out, span{s.from, cut.from})
		}
		if cut.until < s.until {
			out = append(out, span{cut.until, s.until})
		}
	}
	return out
}

// usage は Org の Quota の材料（数える人の区間と、付与）。
type usage struct {
	occupants map[string][]span // Membership・招待の内部 ID → 区間
	grants    []port.QuotaGrant
}

// quotasOn は Quota を判定するか（フィーチャー quota が active で、共有 Org）。
func (s *Service) quotasOn(o port.Org) bool {
	return s.Quotas && o.Kind == port.OrgShared
}

func (s *Service) usage(ctx context.Context, tx port.Tx, o port.Org) (usage, error) {
	now := s.Clock.Now()
	u := usage{occupants: map[string][]span{}}
	var err error
	if u.grants, err = tx.QuotaGrants().ListByOrg(ctx, o.RealmID, o.ID, QuotaMembers); err != nil {
		return usage{}, err
	}
	after := ""
	for {
		ms, err := tx.Memberships().ListByOrg(ctx, o.RealmID, o.ID, after, 500)
		if err != nil {
			return usage{}, err
		}
		for _, m := range ms {
			if m.Status == port.MembershipEnded {
				continue
			}
			if !s.QuotaCount.Future && m.ValidFrom != nil && now.Before(*m.ValidFrom) {
				continue
			}
			spans := []span{spanOf(m.ValidFrom, m.ValidUntil)}
			if !s.QuotaCount.Suspended {
				ss, err := tx.Suspensions().ListByTarget(ctx, o.RealmID, port.SuspensionTargetMembership, m.ID)
				if err != nil {
					return usage{}, err
				}
				for _, sp := range ss {
					end := sp.EndsAt
					if sp.LiftedAt != nil && (end == nil || sp.LiftedAt.Before(*end)) {
						end = sp.LiftedAt
					}
					spans = subtract(spans, spanOf(&sp.StartsAt, end))
				}
			}
			u.occupants[m.ID] = spans
		}
		if len(ms) < 500 {
			break
		}
		after = ms[len(ms)-1].PublicID
	}
	if s.QuotaCount.Invited {
		is, err := tx.Invitations().ListByOrg(ctx, o.RealmID, o.ID)
		if err != nil {
			return usage{}, err
		}
		for _, i := range is {
			if i.Status == port.InvitationPending && now.Before(i.ExpiresAt) {
				u.occupants[i.ID] = []span{spanOf(i.ValidFrom, i.ValidUntil)}
			}
		}
	}
	return u, nil
}

// limitAt は時刻 t の上限を返す。無制限なら -1。
func limitAt(gs []port.QuotaGrant, t int64) int64 {
	var base, override *port.QuotaGrant
	var addons int64
	any := false
	for i := range gs {
		g := &gs[i]
		if !spanOf(&g.StartsAt, g.EndsAt).covers(t) {
			continue
		}
		any = true
		switch g.Kind {
		case port.QuotaOverride:
			if override == nil || newer(*g, *override) {
				override = g
			}
		case port.QuotaBase:
			if base == nil || newer(*g, *base) {
				base = g
			}
		case port.QuotaAddon:
			addons += g.Quantity
		}
	}
	switch {
	case !any:
		return -1
	case override != nil:
		return override.Quantity
	case base != nil:
		return base.Quantity + addons
	}
	return addons
}

func newer(a, b port.QuotaGrant) bool {
	return a.CreatedAt.After(b.CreatedAt) || (a.CreatedAt.Equal(b.CreatedAt) && a.ID > b.ID)
}

func (u usage) countAt(t int64, exclude string) int64 {
	var n int64
	for k, spans := range u.occupants {
		if k == exclude {
			continue
		}
		if slices.ContainsFunc(spans, func(s span) bool { return s.covers(t) }) {
			n++
		}
	}
	return n
}

// points は [from, until) の区切りの時刻（from を含む）を昇順に返す。
func (u usage) points(from, until int64, extra ...[]port.QuotaGrant) []int64 {
	pts := []int64{from}
	add := func(t int64) {
		if from < t && t < until {
			pts = append(pts, t)
		}
	}
	for _, spans := range u.occupants {
		for _, s := range spans {
			add(s.from)
			add(s.until)
		}
	}
	for _, gs := range append(extra, u.grants) {
		for _, g := range gs {
			s := spanOf(&g.StartsAt, g.EndsAt)
			add(s.from)
			add(s.until)
		}
	}
	slices.Sort(pts)
	return slices.Compact(pts)
}

// checkAdd は、exclude（入れ替わる本人。無ければ空）を除いた人数に1人足しても、区間 want の今以降のすべての時点で
// 上限を超えないことを確かめる。足りなければ *QuotaError。
func (s *Service) checkAdd(ctx context.Context, tx port.Tx, o port.Org, want span, exclude string) error {
	if !s.quotasOn(o) {
		return nil
	}
	u, err := s.usage(ctx, tx, o)
	if err != nil {
		return err
	}
	from := max(want.from, s.Clock.Now().UnixNano())
	if from >= want.until {
		return nil
	}
	err = firstShortage(u.points(from, want.until), want.until, func(t int64) (int64, int64, bool) {
		lim, n := limitAt(u.grants, t), u.countAt(t, exclude)
		return lim, n, lim >= 0 && n+1 > lim
	})
	if qe, ok := err.(*QuotaError); ok {
		qe.Adding = true
	}
	return err
}

// firstShortage は区切りの時刻 pts（昇順）のうち、最初に bad となる区間（続く bad の区間をまとめる）を *QuotaError で返す。
func firstShortage(pts []int64, until int64, bad func(t int64) (limit, count int64, bad bool)) error {
	for i, t := range pts {
		lim, n, b := bad(t)
		if !b {
			continue
		}
		end := until
		for _, t2 := range pts[i+1:] {
			if _, _, b2 := bad(t2); !b2 {
				end = t2
				break
			}
		}
		return &QuotaError{From: *toTime(t), Until: toTime(end), Limit: lim, Count: n}
	}
	return nil
}

// checkGrants は付与を before から after に変えても、今以降に既存の予約が新たに上限を超えないことを確かめる。
func (s *Service) checkGrants(u usage, before, after []port.QuotaGrant) error {
	now := s.Clock.Now().UnixNano()
	return firstShortage(u.points(now, plusInf, before, after), plusInf, func(t int64) (int64, int64, bool) {
		lim, old, n := limitAt(after, t), limitAt(before, t), u.countAt(t, "")
		return lim, n, lim >= 0 && n > lim && (old < 0 || n <= old)
	})
}

// exceeded は今以降に上限を超える時点があれば、その *QuotaError を返す。
func (s *Service) exceeded(u usage) *QuotaError {
	now := s.Clock.Now().UnixNano()
	err := firstShortage(u.points(now, plusInf), plusInf, func(t int64) (int64, int64, bool) {
		lim, n := limitAt(u.grants, t), u.countAt(t, "")
		return lim, n, lim >= 0 && n > lim
	})
	if err == nil {
		return nil
	}
	return err.(*QuotaError)
}

// QuotaView は今の上限と人数。Limit が nil なら無制限。
type QuotaView struct {
	Limit  *int64
	Count  int64
	Grants []port.QuotaGrant
}

// Quota は Org の今の Quota を返す。
func (s *Service) Quota(ctx context.Context, tx port.Tx, o port.Org) (QuotaView, error) {
	if o.Kind != port.OrgShared {
		return QuotaView{}, ErrPersonalOrg
	}
	u, err := s.usage(ctx, tx, o)
	if err != nil {
		return QuotaView{}, err
	}
	now := s.Clock.Now().UnixNano()
	v := QuotaView{Count: u.countAt(now, ""), Grants: u.grants}
	if lim := limitAt(u.grants, now); lim >= 0 {
		v.Limit = &lim
	}
	return v, nil
}

// QuotaGrantInput は付与の登録・変更。
type QuotaGrantInput struct {
	Kind     port.QuotaGrantKind
	Quantity int64
	StartsAt *time.Time // nil は今
	EndsAt   *time.Time
	// ExternalRef は外部（課金など）の付与の参照。同じものがあれば上書きする（冪等）。外部の付与は上限を下回っても拒否しない。
	ExternalRef string
}

// ErrQuotaGrantInvalid は付与の内容が正しくない。
var ErrQuotaGrantInvalid = errs.WithCode(errs.KindInvalid, "quota_grant_invalid", "invalid quota grant")

// ErrQuotaGrantExternal は外部の付与を手で変えようとした（外部の付与は external_ref での上書きで変える）。
var ErrQuotaGrantExternal = errs.WithCode(errs.KindFailedPrecondition, "quota_grant_external", "external quota grants are changed by external_ref")

func (in QuotaGrantInput) check(now time.Time) (time.Time, error) {
	if in.Kind != port.QuotaBase && in.Kind != port.QuotaAddon && in.Kind != port.QuotaOverride {
		return time.Time{}, ErrQuotaGrantInvalid
	}
	if in.Quantity < 0 || in.Quantity > MaxQuotaQuantity || len(in.ExternalRef) > 200 {
		return time.Time{}, ErrQuotaGrantInvalid
	}
	start := now
	if in.StartsAt != nil {
		start = in.StartsAt.UTC()
	}
	if in.EndsAt != nil && !start.Before(*in.EndsAt) {
		return time.Time{}, ErrQuotaGrantInvalid
	}
	return start, nil
}

// PutQuotaGrant は付与を登録する。ExternalRef が同じ付与があれば上書きし、created は false。
// 手動の付与で既存の予約が上限を超えるなら *QuotaError。外部の付与は拒否せず、超えれば org.quota.exceeded を残す。
func (s *Service) PutQuotaGrant(ctx context.Context, tx port.Tx, o port.Org, in QuotaGrantInput, actor audit.Actor, requestID string) (port.QuotaGrant, bool, error) {
	if o.Kind != port.OrgShared {
		return port.QuotaGrant{}, false, ErrPersonalOrg
	}
	now := s.Clock.Now()
	start, err := in.check(now)
	if err != nil {
		return port.QuotaGrant{}, false, err
	}
	g := port.QuotaGrant{ID: id.New(id.QuotaGrant), PublicID: id.NewExternal(id.QuotaGrant), RealmID: o.RealmID, OrgID: o.ID,
		QuotaKey: QuotaMembers, Kind: in.Kind, Quantity: in.Quantity, StartsAt: start, EndsAt: utc(in.EndsAt), Source: port.QuotaSourceManual,
		ExternalRef: in.ExternalRef, CreatedBy: actor.ID, CreatedAt: now, UpdatedAt: now}
	created := true
	if in.ExternalRef != "" {
		g.Source = port.QuotaSourceExternal
		cur, err := tx.QuotaGrants().GetByExternalRef(ctx, o.RealmID, o.ID, QuotaMembers, in.ExternalRef)
		switch {
		case err == nil:
			created = false
			cur.Kind, cur.Quantity, cur.StartsAt, cur.EndsAt, cur.UpdatedAt = g.Kind, g.Quantity, g.StartsAt, g.EndsAt, now
			g = cur
		case !errors.Is(err, errs.NotFound):
			return port.QuotaGrant{}, false, err
		}
	}
	u, err := s.usage(ctx, tx, o)
	if err != nil {
		return port.QuotaGrant{}, false, err
	}
	after := replaceGrant(u.grants, g)
	if g.Source == port.QuotaSourceManual {
		if err := s.checkGrants(u, u.grants, after); err != nil {
			return port.QuotaGrant{}, false, err
		}
	}
	if created {
		err = tx.QuotaGrants().Create(ctx, g)
	} else {
		err = tx.QuotaGrants().Update(ctx, g)
	}
	if err != nil {
		return port.QuotaGrant{}, false, err
	}
	typ := "org.quota_grant.created"
	if !created {
		typ = "org.quota_grant.updated"
	}
	if err := s.recordGrant(ctx, tx, o, typ, g, actor, requestID); err != nil {
		return port.QuotaGrant{}, false, err
	}
	u.grants = after
	return g, created, s.recordExceeded(ctx, tx, o, u, requestID)
}

// UpdateQuotaGrant は手動の付与の種類・量・期間を変える。既存の予約が上限を超えるなら *QuotaError。
func (s *Service) UpdateQuotaGrant(ctx context.Context, tx port.Tx, o port.Org, g port.QuotaGrant, in QuotaGrantInput, actor audit.Actor, requestID string) (port.QuotaGrant, error) {
	if g.Source != port.QuotaSourceManual {
		return port.QuotaGrant{}, ErrQuotaGrantExternal
	}
	in.ExternalRef = ""
	now := s.Clock.Now()
	if in.StartsAt == nil {
		in.StartsAt = &g.StartsAt
	}
	start, err := in.check(now)
	if err != nil {
		return port.QuotaGrant{}, err
	}
	g.Kind, g.Quantity, g.StartsAt, g.EndsAt, g.UpdatedAt = in.Kind, in.Quantity, start, utc(in.EndsAt), now
	u, err := s.usage(ctx, tx, o)
	if err != nil {
		return port.QuotaGrant{}, err
	}
	if err := s.checkGrants(u, u.grants, replaceGrant(u.grants, g)); err != nil {
		return port.QuotaGrant{}, err
	}
	if err := tx.QuotaGrants().Update(ctx, g); err != nil {
		return port.QuotaGrant{}, err
	}
	return g, s.recordGrant(ctx, tx, o, "org.quota_grant.updated", g, actor, requestID)
}

// DeleteQuotaGrant は付与を消す。手動の付与で既存の予約が上限を超えるなら *QuotaError（外部の付与は拒否しない）。
func (s *Service) DeleteQuotaGrant(ctx context.Context, tx port.Tx, o port.Org, g port.QuotaGrant, actor audit.Actor, requestID string) error {
	u, err := s.usage(ctx, tx, o)
	if err != nil {
		return err
	}
	after := slices.DeleteFunc(slices.Clone(u.grants), func(x port.QuotaGrant) bool { return x.ID == g.ID })
	if g.Source == port.QuotaSourceManual {
		if err := s.checkGrants(u, u.grants, after); err != nil {
			return err
		}
	}
	if err := tx.QuotaGrants().Delete(ctx, o.RealmID, g.ID); err != nil {
		return err
	}
	if err := s.recordGrant(ctx, tx, o, "org.quota_grant.deleted", g, actor, requestID); err != nil {
		return err
	}
	u.grants = after
	return s.recordExceeded(ctx, tx, o, u, requestID)
}

func replaceGrant(gs []port.QuotaGrant, g port.QuotaGrant) []port.QuotaGrant {
	out := slices.Clone(gs)
	if i := slices.IndexFunc(out, func(x port.QuotaGrant) bool { return x.ID == g.ID }); i >= 0 {
		out[i] = g
		return out
	}
	return append(out, g)
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

func (s *Service) recordGrant(ctx context.Context, tx port.Tx, o port.Org, typ string, g port.QuotaGrant, actor audit.Actor, requestID string) error {
	d := map[string]any{"grant_id": g.PublicID, "quota_key": g.QuotaKey, "kind": string(g.Kind), "quantity": g.Quantity,
		"starts_at": g.StartsAt.Format(time.RFC3339), "source": string(g.Source)}
	if g.EndsAt != nil {
		d["ends_at"] = g.EndsAt.Format(time.RFC3339)
	}
	if g.ExternalRef != "" {
		d["external_ref"] = g.ExternalRef
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID,
		Actor: actor, RequestID: requestID, Details: d})
	return err
}

// recordExceeded は今以降に上限を超える時点があれば org.quota.exceeded を残す（既存のメンバーは外さず、新規を止める）。
func (s *Service) recordExceeded(ctx context.Context, tx port.Tx, o port.Org, u usage, requestID string) error {
	e := s.exceeded(u)
	if e == nil {
		return nil
	}
	d := map[string]any{"quota_key": QuotaMembers, "from": e.From.Format(time.RFC3339), "limit": e.Limit, "count": e.Count}
	if e.Until != nil {
		d["until"] = e.Until.Format(time.RFC3339)
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventQuotaExceeded, Result: audit.ResultFailure, RealmID: o.RealmID,
		OrgID: o.PublicID, Actor: audit.Actor{Type: "system"}, RequestID: requestID, Details: d})
	return err
}
