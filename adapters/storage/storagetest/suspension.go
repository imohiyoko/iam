package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func testUserValidity(t *testing.T, h Harness) {
	s, _ := open(t, h)
	u := newUser(id.New(id.Realm))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		from, until, at := T0.Add(time.Hour), T0.Add(48*time.Hour), T0.Add(time.Minute)
		if err := tx.Users().SetValidity(ctx, u.RealmID, u.ID, &from, &until, at); err != nil {
			return err
		}
		got, err := tx.Users().Get(ctx, u.RealmID, u.ID)
		if err != nil || got.ValidFrom == nil || !got.ValidFrom.Equal(from) || !got.ValidUntil.Equal(until) || !got.UpdatedAt.Equal(at) {
			return fmt.Errorf("after SetValidity = %+v, %v", got, err)
		}
		if err := tx.Users().SetValidity(ctx, u.RealmID, u.ID, nil, nil, at); err != nil {
			return err
		}
		if got, _ := tx.Users().Get(ctx, u.RealmID, u.ID); got.ValidFrom != nil || got.ValidUntil != nil {
			return fmt.Errorf("after clearing = %+v", got)
		}
		return notFound("set validity in another realm", tx.Users().SetValidity(ctx, id.New(id.Realm), u.ID, nil, nil, at))
	})
}

func newSuspension(realmID, userID string) port.Suspension {
	return port.Suspension{ID: id.New(id.Suspension), PublicID: id.NewExternal(id.Suspension), RealmID: realmID,
		TargetType: port.SuspensionTargetUser, TargetID: userID, Category: "tos_violation", Reason: "spam", StartsAt: T0,
		CreatedBy: "usr_operator", CreatedAt: T0}
}

func testSuspensions(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, u := id.New(id.Realm), id.New(id.User)
	a := newSuspension(r, u)
	a.EndsAt = ptr(T0.Add(time.Hour))
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Suspensions()
		if err := repo.Create(ctx, a); err != nil {
			return err
		}
		got, err := repo.GetByPublicID(ctx, r, a.PublicID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("suspensions.GetByPublicID = %+v, %v", got, err)
		}
		dup := newSuspension(r, u)
		dup.PublicID = a.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		// external_ref は対象と種別ごとに一意（冪等な停止）。空なら重ねられる。
		b := newSuspension(r, u)
		b.Category, b.ExternalRef, b.StartsAt = "billing", "inv-1", T0.Add(-time.Hour)
		if err := repo.Create(ctx, b); err != nil {
			return err
		}
		again := newSuspension(r, u)
		again.Category, again.ExternalRef = "billing", "inv-1"
		if err := conflict("same external ref", repo.Create(ctx, again)); err != nil {
			return err
		}
		other := newSuspension(r, id.New(id.User))
		other.Category, other.ExternalRef = "billing", "inv-1"
		if err := repo.Create(ctx, other); err != nil {
			return err
		}
		if err := repo.Create(ctx, newSuspension(r, u)); err != nil {
			return err
		}
		list, err := repo.ListByTarget(ctx, r, port.SuspensionTargetUser, u)
		if err != nil || len(list) != 3 || list[0].ID != b.ID {
			return fmt.Errorf("suspensions.ListByTarget = %+v, %v", list, err)
		}
		at := T0.Add(time.Minute)
		if err := repo.Lift(ctx, r, a.ID, at, "usr_security"); err != nil {
			return err
		}
		if err := repo.Lift(ctx, r, a.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		got, _ = repo.GetByPublicID(ctx, r, a.PublicID)
		if got.LiftedAt == nil || !got.LiftedAt.Equal(at) || got.LiftedBy != "usr_security" {
			return fmt.Errorf("lifted = %+v", got)
		}
		return notFound("lift in another realm", repo.Lift(ctx, id.New(id.Realm), a.ID, at, "x"))
	})
}

func newScheduled(realmID, ref string, at time.Time) port.ScheduledEvent {
	return port.ScheduledEvent{ID: id.New(id.Event), RealmID: realmID, Ref: ref, Type: "user.suspension_started",
		Payload: []byte(`{"k":"v"}`), FireAt: at, CreatedAt: T0}
}

func testScheduledEvents(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	early, late, other := newScheduled(r, "a", T0.Add(time.Minute)), newScheduled(r, "a", T0.Add(time.Hour)), newScheduled(id.New(id.Realm), "b", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.ScheduledEvents()
		for _, e := range []port.ScheduledEvent{late, early, other} {
			if err := repo.Schedule(ctx, e); err != nil {
				return err
			}
		}
		due, err := repo.Due(ctx, T0.Add(time.Minute), 10)
		if err != nil || len(due) != 2 || due[0].ID != other.ID || due[1].ID != early.ID || !reflect.DeepEqual(due[1], early) {
			return fmt.Errorf("due = %+v, %v", due, err)
		}
		if due, _ := repo.Due(ctx, T0.Add(time.Hour), 1); len(due) != 1 {
			return fmt.Errorf("limit: %d", len(due))
		}
		if ok, err := repo.MarkFired(ctx, r, early.ID, T0.Add(2*time.Minute)); !ok || err != nil {
			return fmt.Errorf("mark fired = %v, %v", ok, err)
		}
		if ok, err := repo.MarkFired(ctx, r, early.ID, T0.Add(3*time.Minute)); ok || err != nil {
			return fmt.Errorf("mark fired twice = %v, %v", ok, err)
		}
		if ok, _ := repo.MarkFired(ctx, id.New(id.Realm), late.ID, T0); ok {
			return fmt.Errorf("mark fired in another realm")
		}
		// 取り消しは未発火のものだけ。
		if err := repo.CancelByRef(ctx, r, "a"); err != nil {
			return err
		}
		due, err = repo.Due(ctx, T0.Add(24*time.Hour), 10)
		if err != nil || len(due) != 1 || due[0].ID != other.ID {
			return fmt.Errorf("due after cancel = %+v, %v", due, err)
		}
		if ok, _ := repo.MarkFired(ctx, r, late.ID, T0); ok {
			return fmt.Errorf("canceled event fired")
		}
		return nil
	})
}

// testScheduledFireConcurrent は同じ出来事を同時に発火しようとしても1つしか通らないことを確かめる。
func testScheduledFireConcurrent(t *testing.T, h Harness) {
	s, _ := open(t, h)
	e := newScheduled(id.New(id.Realm), "x", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error { return tx.ScheduledEvents().Schedule(ctx, e) })
	ExactlyOneSucceeds(t, Concurrent(16, func(int) error {
		return s.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			ok, err := tx.ScheduledEvents().MarkFired(ctx, e.RealmID, e.ID, T0)
			if err == nil && !ok {
				return errs.New(errs.KindConflict, "already fired")
			}
			return err
		})
	}))
}

var suspensionIsolationCase = IsolationCase{
	Name: "Suspensions.GetByPublicID+ListByTarget",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		x := newSuspension(r, isoUser)
		x.PublicID = isoSuspension
		return tx.Suspensions().Create(ctx, x)
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		n, err := countOne(tx.Suspensions().GetByPublicID(ctx, r, isoSuspension))
		if err != nil {
			return 0, err
		}
		m, err := count(tx.Suspensions().ListByTarget(ctx, r, port.SuspensionTargetUser, isoUser))
		return n + m, err
	},
}

const isoSuspension = "sus_00000000000000000000000009"
