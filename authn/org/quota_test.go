package org

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Quota の判定（design.md 11.14）。

var day = 24 * time.Hour

func at(d time.Duration) *time.Time { t := testkit.T0.Add(d); return &t }

func grant(o port.Org, kind port.QuotaGrantKind, n int64, from time.Duration, until *time.Time, created time.Duration) port.QuotaGrant {
	return port.QuotaGrant{ID: id.New(id.QuotaGrant), PublicID: id.NewExternal(id.QuotaGrant), RealmID: o.RealmID, OrgID: o.ID, QuotaKey: QuotaMembers,
		Kind: kind, Quantity: n, StartsAt: testkit.T0.Add(from), EndsAt: until, Source: port.QuotaSourceManual, CreatedAt: testkit.T0.Add(created)}
}

func TestLimitAt(t *testing.T) {
	o := port.Org{ID: "org", RealmID: "rlm"}
	gs := []port.QuotaGrant{
		grant(o, port.QuotaBase, 5, 0, nil, 0),
		grant(o, port.QuotaBase, 8, 10*day, nil, time.Second), // 新しい base が優先
		grant(o, port.QuotaAddon, 2, 0, at(20*day), 0),
		grant(o, port.QuotaOverride, 1, 30*day, at(31*day), 0),
	}
	for _, c := range []struct {
		at   time.Duration
		want int64
	}{
		{-time.Second, -1}, // 付与が無ければ無制限
		{0, 7}, {10 * day, 10}, {20 * day, 8}, {30 * day, 1}, {31 * day, 8},
	} {
		if got := limitAt(gs, testkit.T0.Add(c.at).UnixNano()); got != c.want {
			t.Errorf("limit at %v = %d, want %d", c.at, got, c.want)
		}
	}
}

type quotaKit struct {
	*testkit.Kit
	s *Service
	o port.Org
}

func newQuotaKit(t *testing.T, count QuotaCount) quotaKit {
	k := testkit.New(t)
	s := &Service{Clock: k.Clock, Crypter: k.Crypter, Quotas: true, QuotaCount: count}
	owner := k.SeedUser(t)
	var o port.Org
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		o, _, err = s.Create(ctx, tx, owner, "Acme", false, audit.Actor{Type: "user", ID: owner.PublicID}, "")
		return err
	})
	return quotaKit{k, s, o}
}

func (q quotaKit) member(t *testing.T, from, until *time.Time) port.Membership {
	t.Helper()
	u := q.SeedUser(t)
	m := port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: q.o.RealmID, UserID: u.ID, OrgID: q.o.ID,
		Status: port.MembershipActive, Role: port.OrgMember, ValidFrom: from, ValidUntil: until, CreatedAt: q.Clock.Now(), UpdatedAt: q.Clock.Now()}
	q.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Memberships().Create(ctx, m) })
	return m
}

func (q quotaKit) put(t *testing.T, in QuotaGrantInput) (port.QuotaGrant, error) {
	t.Helper()
	var g port.QuotaGrant
	err := q.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		g, _, err = q.s.PutQuotaGrant(ctx, tx, q.o, in, audit.Actor{Type: "operator", ID: "usr_op"}, "")
		return err
	})
	return g, err
}

func (q quotaKit) check(want span) error {
	return q.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error { return q.s.checkAdd(ctx, tx, q.o, want, "") })
}

func TestQuotaTimeSharing(t *testing.T) {
	q := newQuotaKit(t, QuotaCount{Invited: true, Future: true, Suspended: true})
	// オーナー（無期限）+ 1月の人。上限 2。
	q.member(t, nil, at(30*day))
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 2}); err != nil {
		t.Fatal(err)
	}
	// 期間が重なる人は入れない。不足する期間は今から30日。
	err := q.check(spanOf(nil, nil))
	var qe *QuotaError
	if !errors.As(err, &qe) || !qe.From.Equal(testkit.T0) || qe.Until == nil || !qe.Until.Equal(*at(30 * day)) || qe.Limit != 2 || qe.Count != 2 {
		t.Fatalf("overlapping = %v %+v", err, qe)
	}
	if !errors.Is(err, errs.Conflict) {
		t.Fatalf("quota error must be a conflict: %v", err)
	}
	// 重ならない人とは枠を共有できる。
	if err := q.check(spanOf(at(30*day), nil)); err != nil {
		t.Fatalf("after the other ends: %v", err)
	}
	// 将来の減少：60日目からは override 1（オーナーだけ）。30日目からの人は入れない。
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaOverride, Quantity: 1, StartsAt: at(60 * day)}); err != nil {
		t.Fatal(err)
	}
	if err := q.check(spanOf(at(30*day), nil)); !errors.As(err, &qe) || !qe.From.Equal(*at(60 * day)) || qe.Until != nil {
		t.Fatalf("future decrease = %v %+v", err, qe)
	}
	if err := q.check(spanOf(at(30*day), at(60*day))); err != nil {
		t.Fatalf("until the decrease: %v", err)
	}
}

func TestQuotaGrantChanges(t *testing.T) {
	q := newQuotaKit(t, QuotaCount{Invited: true, Future: true, Suspended: true})
	q.member(t, nil, nil)
	q.member(t, at(10*day), nil) // 将来有効の人も数える
	base, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 3})
	if err != nil {
		t.Fatal(err)
	}
	// 既存の予約（3人）が成り立たなくなる手動の変更は拒む。
	_, err = q.put(t, QuotaGrantInput{Kind: port.QuotaOverride, Quantity: 2, StartsAt: at(20 * day)})
	var qe *QuotaError
	if !errors.As(err, &qe) || !qe.From.Equal(*at(20 * day)) || qe.Count != 3 {
		t.Fatalf("manual override below usage = %v %+v", err, qe)
	}
	err = q.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		_, err := q.s.UpdateQuotaGrant(ctx, tx, q.o, base, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 2}, audit.Actor{}, "")
		return err
	})
	if !errors.As(err, &qe) {
		t.Fatalf("reducing the base = %v", err)
	}
	err = q.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return q.s.DeleteQuotaGrant(ctx, tx, q.o, base, audit.Actor{}, "") // 消すと無制限になるので通る
	})
	if err != nil {
		t.Fatalf("delete the only grant: %v", err)
	}
	// 外部の付与は拒まず、上限を下回れば org.quota.exceeded を残す。同じ external_ref は上書き。
	g, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 2, ExternalRef: "sub_1"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 1, ExternalRef: "sub_1"})
	if err != nil || again.ID != g.ID || again.Quantity != 1 {
		t.Fatalf("upsert = %+v, %v", again, err)
	}
	n := 0
	q.Tx(t, func(ctx context.Context, tx port.Tx) error {
		recs, err := tx.Audit().Scan(ctx, 1, 1000)
		for _, r := range recs {
			if bytes.Contains(r.Payload, []byte(EventQuotaExceeded)) {
				n++
			}
		}
		return err
	})
	if n != 2 {
		t.Fatalf("quota.exceeded events = %d", n)
	}
	// 外部の付与は手で変えられない。
	err = q.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		_, err := q.s.UpdateQuotaGrant(ctx, tx, q.o, again, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 9}, audit.Actor{}, "")
		return err
	})
	if !errors.Is(err, ErrQuotaGrantExternal) {
		t.Fatalf("manual update of an external grant = %v", err)
	}
}

func TestQuotaCountOptions(t *testing.T) {
	q := newQuotaKit(t, QuotaCount{})
	q.member(t, at(10*day), nil)
	suspended := q.member(t, nil, nil)
	q.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Suspensions().Create(ctx, port.Suspension{ID: id.New(id.Suspension), PublicID: id.NewExternal(id.Suspension), RealmID: q.o.RealmID,
			TargetType: port.SuspensionTargetMembership, TargetID: suspended.ID, Category: "billing", StartsAt: testkit.T0, EndsAt: at(5 * day),
			CreatedAt: testkit.T0})
	})
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 2}); err != nil {
		t.Fatal(err)
	}
	// オーナーだけを数える（将来有効・停止中は数えない）。停止が終わる5日目からは2人。
	if err := q.check(spanOf(nil, at(5*day))); err != nil {
		t.Fatalf("while suspended: %v", err)
	}
	var qe *QuotaError
	if err := q.check(spanOf(nil, nil)); !errors.As(err, &qe) || !qe.From.Equal(*at(5 * day)) {
		t.Fatalf("after suspension = %v %+v", err, qe)
	}
}

func TestQuotaPersonalOrgAndOff(t *testing.T) {
	q := newQuotaKit(t, QuotaCount{})
	// 手動で既存の人数（オーナー）を下回る付与は拒む。外部の付与なら入る。
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 0}); err == nil {
		t.Fatal("manual grant below usage must be rejected")
	}
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 0, ExternalRef: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := q.check(spanOf(nil, nil)); err == nil {
		t.Fatal("limit 0 must reject")
	}
	q.s.Quotas = false
	if err := q.check(spanOf(nil, nil)); err != nil {
		t.Fatalf("feature off must not check: %v", err)
	}
	q.s.Quotas = true
	q.o.Kind = port.OrgPersonal
	if err := q.check(spanOf(nil, nil)); err != nil {
		t.Fatalf("personal org must not check: %v", err)
	}
	if _, err := q.put(t, QuotaGrantInput{Kind: port.QuotaBase, Quantity: 1}); !errors.Is(err, ErrPersonalOrg) {
		t.Fatalf("grant on a personal org = %v", err)
	}
	if _, err := q.put(t, QuotaGrantInput{Kind: "nope", Quantity: 1}); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}
