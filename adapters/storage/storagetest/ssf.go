package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID Shared Signals Framework（ADR 0118）の契約：送信側のストリーム・対象・poll の待ち、受信側の送信側の登録、端末の準拠状態。

func testSSFStreams(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	stream := func(realm, method string, at time.Time) port.SSFStream {
		x := port.SSFStream{ID: id.NewExternal(id.SSFStream), RealmID: realm, ServiceAccountID: "sa_1", DeliveryMethod: method,
			EventsRequested: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
			EventsDelivered: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
			Description:     "d", Status: port.SSFStatusEnabled, CreatedAt: at, UpdatedAt: at,
			SSFStreamDelivery: port.SSFStreamDelivery{CursorSeq: 5}}
		if method == port.SSFDeliveryPush {
			x.EndpointURL, x.AuthorizationCiphertext = "https://rx.example/events", []byte{1, 2, 3}
		}
		return x
	}
	push, poll := stream(r, port.SSFDeliveryPush, T0.Add(time.Second)), stream(r, port.SSFDeliveryPoll, T0)
	o := stream(other, port.SSFDeliveryPush, T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.SSFStreams()
		for _, x := range []port.SSFStream{push, poll, o} {
			if err := w.Create(ctx, x); err != nil {
				return fmt.Errorf("create: %w", err)
			}
		}
		if err := conflict("same id", w.Create(ctx, push)); err != nil {
			return err
		}
		got, err := w.Get(ctx, r, push.ID)
		if err != nil || !reflect.DeepEqual(got, push) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("other realm", second(w.Get(ctx, other, push.ID))); err != nil {
			return err
		}
		list, err := w.List(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.SSFStream{poll, push}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		// 設定の更新は配送の状態を変えない。
		up := push
		up.Status, up.StatusReason, up.EventsDelivered, up.AuthorizationCiphertext = port.SSFStatusPaused, "maintenance", []string{}, nil
		up.UpdatedAt, up.CursorSeq = T0.Add(time.Hour), 99
		if err := w.Update(ctx, up); err != nil {
			return err
		}
		got, _ = w.Get(ctx, r, push.ID)
		up.CursorSeq = 5
		if !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v", got)
		}
		push = up
		// 位置は戻らない。
		next := T0.Add(time.Minute)
		if err := w.SetDelivery(ctx, r, push.ID, port.SSFStreamDelivery{CursorSeq: 3, Failures: 2, NextAttemptAt: &next, LastError: "timeout"}); err != nil {
			return err
		}
		got, _ = w.Get(ctx, r, push.ID)
		if got.CursorSeq != 5 || got.Failures != 2 || got.NextAttemptAt == nil || !got.NextAttemptAt.Equal(next) || got.LastError != "timeout" {
			return fmt.Errorf("delivery = %+v", got.SSFStreamDelivery)
		}
		if err := w.SetDelivery(ctx, r, push.ID, port.SSFStreamDelivery{CursorSeq: 9}); err != nil {
			return err
		}
		if got, _ = w.Get(ctx, r, push.ID); got.CursorSeq != 9 || got.NextAttemptAt != nil {
			return fmt.Errorf("delivery forward = %+v", got.SSFStreamDelivery)
		}
		if err := notFound("set delivery other realm", w.SetDelivery(ctx, other, push.ID, port.SSFStreamDelivery{})); err != nil {
			return err
		}
		// DuePush は enabled の push だけ。
		due, err := w.DuePush(ctx, T0, 10)
		if err != nil || len(due) != 1 || due[0].ID != o.ID {
			return fmt.Errorf("due (paused) = %+v, %v", due, err)
		}
		push.Status = port.SSFStatusEnabled
		if err := w.Update(ctx, push); err != nil {
			return err
		}
		later := T0.Add(time.Hour)
		if err := w.SetDelivery(ctx, other, o.ID, port.SSFStreamDelivery{CursorSeq: 5, NextAttemptAt: &later}); err != nil {
			return err
		}
		due, err = w.DuePush(ctx, T0, 10)
		if err != nil || len(due) != 1 || due[0].ID != push.ID {
			return fmt.Errorf("due = %+v, %v", due, err)
		}
		if due, _ = w.DuePush(ctx, later, 1); len(due) != 1 || due[0].ID != push.ID {
			return fmt.Errorf("due limit = %+v", due)
		}

		// 対象。
		for _, sub := range []string{"usr_a", "usr_b", "usr_a"} {
			if err := w.AddSubject(ctx, r, push.ID, sub, T0); err != nil {
				return err
			}
		}
		if err := w.AddSubject(ctx, r, poll.ID, "usr_a", T0); err != nil {
			return err
		}
		if n, err := w.CountSubjects(ctx, r, push.ID); err != nil || n != 2 {
			return fmt.Errorf("count subjects = %d, %v", n, err)
		}
		if ok, err := w.HasSubject(ctx, r, push.ID, "usr_b"); err != nil || !ok {
			return fmt.Errorf("has = %v, %v", ok, err)
		}
		if ok, _ := w.HasSubject(ctx, other, push.ID, "usr_b"); ok {
			return fmt.Errorf("has in other realm")
		}
		if err := w.RemoveSubject(ctx, r, push.ID, "usr_b"); err != nil {
			return err
		}
		if err := notFound("remove twice", w.RemoveSubject(ctx, r, push.ID, "usr_b")); err != nil {
			return err
		}
		if n, err := w.RemoveSubjectEverywhere(ctx, r, "usr_a"); err != nil || n != 2 {
			return fmt.Errorf("remove everywhere = %d, %v", n, err)
		}

		// poll の待ち。
		ev := func(jti string, seq int64) port.SSFPollEvent {
			return port.SSFPollEvent{RealmID: r, StreamID: poll.ID, JTI: jti, Seq: seq, SET: "set-" + jti, CreatedAt: T0}
		}
		if err := w.AddPollEvents(ctx, []port.SSFPollEvent{ev("b", 2), ev("a", 2), ev("c", 1)}); err != nil {
			return err
		}
		dup := ev("a", 7)
		dup.SET = "other"
		if err := w.AddPollEvents(ctx, []port.SSFPollEvent{dup}); err != nil {
			return err
		}
		evs, err := w.ListPollEvents(ctx, r, poll.ID, 10)
		if err != nil || !reflect.DeepEqual(evs, []port.SSFPollEvent{ev("c", 1), ev("a", 2), ev("b", 2)}) {
			return fmt.Errorf("poll = %+v, %v", evs, err)
		}
		if evs, _ = w.ListPollEvents(ctx, r, poll.ID, 1); len(evs) != 1 || evs[0].JTI != "c" {
			return fmt.Errorf("poll limit = %+v", evs)
		}
		if n, _ := w.CountPollEvents(ctx, r, poll.ID); n != 3 {
			return fmt.Errorf("count poll = %d", n)
		}
		if n, err := w.AckPollEvents(ctx, r, poll.ID, []string{"a", "zz"}); err != nil || n != 1 {
			return fmt.Errorf("ack = %d, %v", n, err)
		}
		if n, _ := w.AckPollEvents(ctx, other, poll.ID, []string{"b"}); n != 0 {
			return fmt.Errorf("ack other realm = %d", n)
		}

		// 削除は対象と待ちも消す。
		if err := w.AddSubject(ctx, r, poll.ID, "usr_c", T0); err != nil {
			return err
		}
		if err := w.Delete(ctx, r, poll.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", w.Delete(ctx, r, poll.ID)); err != nil {
			return err
		}
		if n, _ := w.CountPollEvents(ctx, r, poll.ID); n != 0 {
			return fmt.Errorf("poll events left = %d", n)
		}
		if n, _ := w.CountSubjects(ctx, r, poll.ID); n != 0 {
			return fmt.Errorf("subjects left = %d", n)
		}
		if n, err := w.Count(ctx); err != nil || n != 2 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if err := w.AddSubject(ctx, r, push.ID, "usr_d", T0); err != nil {
			return err
		}
		ids, err := w.Purge(ctx, 1)
		if err != nil || len(ids) != 1 {
			return fmt.Errorf("purge = %v, %v", ids, err)
		}
		ids2, err := w.Purge(ctx, 10)
		if err != nil || len(ids2) != 1 {
			return fmt.Errorf("purge rest = %v, %v", ids2, err)
		}
		all := append(ids, ids2...)
		slices.Sort(all)
		want := []string{push.ID, o.ID}
		slices.Sort(want)
		if !slices.Equal(all, want) {
			return fmt.Errorf("purged = %v", all)
		}
		if n, _ := w.CountSubjects(ctx, r, push.ID); n != 0 {
			return fmt.Errorf("subjects left after purge = %d", n)
		}
		return nil
	})
}

func testSSFReceiver(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r, other := id.New(id.Realm), id.New(id.Realm)
	tr := func(realm, iss string, at time.Time) port.SSFTransmitter {
		return port.SSFTransmitter{ID: id.NewExternal(id.SSFTransmitter), RealmID: realm, Name: "T " + iss, Issuer: iss,
			Config: []byte(`{"audience":"x"}`), PushTokenHash: []byte{9, 9}, Enabled: true, CreatedAt: at, UpdatedAt: at}
	}
	a, b, o := tr(r, "https://b.example", T0.Add(time.Second)), tr(r, "https://a.example", T0), tr(other, "https://a.example", T0)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		w := tx.SSFTransmitters()
		for _, x := range []port.SSFTransmitter{a, b, o} {
			if err := w.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("same issuer", w.Create(ctx, tr(r, "https://a.example", T0))); err != nil {
			return err
		}
		got, err := w.Get(ctx, r, a.ID)
		if err != nil || !reflect.DeepEqual(got, a) {
			return fmt.Errorf("get = %+v, %v", got, err)
		}
		if err := notFound("other realm", second(w.Get(ctx, other, a.ID))); err != nil {
			return err
		}
		list, err := w.List(ctx, r)
		if err != nil || !reflect.DeepEqual(list, []port.SSFTransmitter{b, a}) {
			return fmt.Errorf("list = %+v, %v", list, err)
		}
		up := a
		up.Issuer, up.Enabled, up.UpdatedAt = "https://a.example", false, T0.Add(time.Hour)
		if err := conflict("update to taken issuer", w.Update(ctx, up)); err != nil {
			return err
		}
		up.Issuer, up.Name, up.Config = "https://c.example", "renamed", []byte(`{}`)
		if err := w.Update(ctx, up); err != nil {
			return err
		}
		if got, _ = w.Get(ctx, r, a.ID); !reflect.DeepEqual(got, up) {
			return fmt.Errorf("after update = %+v", got)
		}
		if err := w.Delete(ctx, r, b.ID); err != nil {
			return err
		}
		if err := notFound("delete twice", w.Delete(ctx, r, b.ID)); err != nil {
			return err
		}
		if n, err := w.Count(ctx); err != nil || n != 2 {
			return fmt.Errorf("count = %d, %v", n, err)
		}
		if n, err := w.Purge(ctx, 10); err != nil || n != 2 {
			return fmt.Errorf("purge = %d, %v", n, err)
		}

		// 端末の準拠状態。
		d := tx.DevicePostures()
		p := port.DevicePosture{RealmID: r, UserID: "u1", DeviceID: "dev-1", Status: port.DeviceNotCompliant, Source: "stx_1",
			EventAt: T0.Add(time.Minute), UpdatedAt: T0.Add(time.Minute)}
		if ok, err := d.Set(ctx, p); err != nil || !ok {
			return fmt.Errorf("set = %v, %v", ok, err)
		}
		older := p
		older.Status, older.EventAt, older.UpdatedAt = port.DeviceCompliant, T0, T0.Add(2*time.Minute)
		if ok, err := d.Set(ctx, older); err != nil || ok {
			return fmt.Errorf("set older = %v, %v", ok, err)
		}
		gp, err := d.Get(ctx, r, "u1", "dev-1")
		if err != nil || !reflect.DeepEqual(gp, p) {
			return fmt.Errorf("get posture = %+v, %v", gp, err)
		}
		newer := p
		newer.Status, newer.EventAt, newer.UpdatedAt, newer.Source = port.DeviceCompliant, T0.Add(time.Hour), T0.Add(time.Hour), "stx_2"
		if ok, err := d.Set(ctx, newer); err != nil || !ok {
			return fmt.Errorf("set newer = %v, %v", ok, err)
		}
		first := port.DevicePosture{RealmID: r, UserID: "u1", DeviceID: "dev-0", Status: port.DeviceCompliant, Source: "stx_1",
			EventAt: T0, UpdatedAt: T0}
		if _, err := d.Set(ctx, first); err != nil {
			return err
		}
		if _, err := d.Set(ctx, port.DevicePosture{RealmID: other, UserID: "u1", DeviceID: "dev-0", Status: port.DeviceCompliant,
			Source: "stx_1", EventAt: T0, UpdatedAt: T0}); err != nil {
			return err
		}
		ps, err := d.ListByUser(ctx, r, "u1")
		if err != nil || !reflect.DeepEqual(ps, []port.DevicePosture{first, newer}) {
			return fmt.Errorf("list postures = %+v, %v", ps, err)
		}
		if err := notFound("posture missing", second(d.Get(ctx, r, "u2", "dev-1"))); err != nil {
			return err
		}
		if n, err := d.DeleteBySource(ctx, r, "stx_1"); err != nil || n != 1 {
			return fmt.Errorf("delete by source = %d, %v", n, err)
		}
		if n, err := d.DeleteByUser(ctx, r, "u1"); err != nil || n != 1 {
			return fmt.Errorf("delete by user = %d, %v", n, err)
		}
		if n, err := d.Count(ctx); err != nil || n != 1 {
			return fmt.Errorf("count postures = %d, %v", n, err)
		}
		if n, err := d.Purge(ctx, 10); err != nil || n != 1 {
			return fmt.Errorf("purge postures = %d, %v", n, err)
		}
		return nil
	})
}
