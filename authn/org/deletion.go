package org

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// Org の削除（design.md 4.10、ADR 0060）。

// EventOrgDeleted は猶予期間の後の削除の出来事（Scheduler の Handler は PurgeDue）。
const EventOrgDeleted = "org.deleted"

// CodeDeletionScheduled は削除の予定がある Org に入れない理由（4.9）。
const CodeDeletionScheduled = "deletion_scheduled"

var (
	// ErrDeletionScheduled は既に削除の予定があること。
	ErrDeletionScheduled = errs.WithCode(errs.KindConflict, CodeDeletionScheduled, "org deletion already scheduled")
	// ErrDeletionNotScheduled は取り消す削除の予定が無いこと。
	ErrDeletionNotScheduled = errs.WithCode(errs.KindConflict, "deletion_not_scheduled", "org deletion is not scheduled")
)

func deletionRef(o port.Org) string { return "org_deletion:" + o.PublicID }

// ScheduleDeletion は共有 Org の削除を予約する。猶予期間の間はメンバーが入れず（deletion_scheduled）、取り消せる。
// grace が 0 以下なら今削除する（運営者だけが選べる。権限は呼び出し側が見る）。
func (s *Service) ScheduleDeletion(ctx context.Context, tx port.Tx, o port.Org, grace time.Duration, actor audit.Actor, requestID string) (port.Org, error) {
	if err := Suspendable(o); err != nil {
		return port.Org{}, err
	}
	if o.DeletedAt != nil {
		return port.Org{}, errs.New(errs.KindNotFound, "org")
	}
	if o.DeletionScheduledAt != nil {
		return port.Org{}, ErrDeletionScheduled
	}
	now := s.Clock.Now()
	if grace <= 0 {
		o.DeletionScheduledAt = new(now)
		if err := s.purge(ctx, tx, o, actor, requestID); err != nil {
			return port.Org{}, err
		}
		o.DeletedAt, o.UpdatedAt = new(now), now
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: EventOrgDeleted, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
			Details: map[string]any{"org_id": o.PublicID},
		})
		return o, err
	}
	at := now.Add(grace)
	if err := tx.Orgs().SetDeletion(ctx, o.RealmID, o.ID, &at, nil, now); err != nil {
		return port.Org{}, err
	}
	if err := eventlog.Schedule(ctx, tx, s.Clock, o.RealmID, deletionRef(o), EventOrgDeleted, at, map[string]any{"org_id": o.PublicID}); err != nil {
		return port.Org{}, err
	}
	o.DeletionScheduledAt, o.UpdatedAt = &at, now
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.deletion_scheduled", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"org_id": o.PublicID, "deletes_at": at.UTC().Format(time.RFC3339Nano)},
	})
	return o, err
}

// CancelDeletion は猶予期間の間に削除の予定を取り消す。
func (s *Service) CancelDeletion(ctx context.Context, tx port.Tx, o port.Org, actor audit.Actor, requestID string) (port.Org, error) {
	if o.DeletedAt != nil {
		return port.Org{}, errs.New(errs.KindNotFound, "org")
	}
	if o.DeletionScheduledAt == nil {
		return port.Org{}, ErrDeletionNotScheduled
	}
	now := s.Clock.Now()
	if err := tx.Orgs().SetDeletion(ctx, o.RealmID, o.ID, nil, nil, now); err != nil {
		return port.Org{}, err
	}
	if err := tx.ScheduledEvents().CancelByRef(ctx, o.RealmID, deletionRef(o)); err != nil {
		return port.Org{}, err
	}
	o.DeletionScheduledAt, o.UpdatedAt = nil, now
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.deletion_cancelled", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"org_id": o.PublicID},
	})
	return o, err
}

// PurgeDue は猶予期間の終わった Org を削除する（eventlog.Handler）。取り消された・削除済みなら何もしない。
func (s *Service) PurgeDue(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	publicID, _ := details["org_id"].(string)
	o, err := tx.Orgs().GetByPublicID(ctx, e.RealmID, publicID)
	if errors.Is(err, errs.NotFound) {
		return eventlog.ErrSkip
	}
	if err != nil {
		return err
	}
	if o.DeletedAt != nil || o.DeletionScheduledAt == nil || o.DeletionScheduledAt.After(s.Clock.Now()) {
		return eventlog.ErrSkip
	}
	return s.purge(ctx, tx, o, audit.Actor{Type: "system"}, "")
}

// purge は全 Membership を org_deleted で終え（セッションは個人 Org に移る）、pending の招待を取り消して鍵を消し、
// 削除の時刻を記録する。行は墓標として残す。サービスアカウント・Group・ロール・Quota・ポリシーは、それぞれの段で足す。
func (s *Service) purge(ctx context.Context, tx port.Tx, o port.Org, actor audit.Actor, requestID string) error {
	after := ""
	for {
		ms, err := tx.Memberships().ListByOrg(ctx, o.RealmID, o.ID, after, 200)
		if err != nil {
			return err
		}
		for _, m := range ms {
			if m.Status == port.MembershipEnded {
				continue
			}
			if _, err := s.end(ctx, tx, o, m, EndedOrgDeleted, actor, requestID); err != nil {
				return err
			}
		}
		if len(ms) < 200 {
			break
		}
		after = ms[len(ms)-1].PublicID
	}
	invs, err := tx.Invitations().ListByOrg(ctx, o.RealmID, o.ID)
	if err != nil {
		return err
	}
	for _, inv := range invs {
		if inv.Status != port.InvitationPending {
			continue
		}
		if err := s.close(ctx, tx, inv, port.InvitationRevoked, actor.ID); err != nil {
			return err
		}
	}
	now := s.Clock.Now()
	// Org 専用 SSO の connection と、ドメインの所有証明を消す（ADR 0077。ドメインは別の Org が証明できるようになる）。
	if _, err := PurgeConnections(ctx, tx, o.RealmID, o.ID, now, -1); err != nil {
		return err
	}
	ds, err := tx.OrgDomains().ListByOrg(ctx, o.RealmID, o.ID)
	if err != nil {
		return err
	}
	for _, d := range ds {
		if err := tx.OrgDomains().Delete(ctx, o.RealmID, d.ID); err != nil {
			return err
		}
	}
	return tx.Orgs().SetDeletion(ctx, o.RealmID, o.ID, o.DeletionScheduledAt, &now, now)
}
