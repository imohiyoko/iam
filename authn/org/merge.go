package org

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウント統合の Org の側（design.md 11.6、ADR 0082）。

// EndedMerged は統合で終えた Membership の理由（統合先のユーザーの Membership に引き継いだ）。
const EndedMerged = "merged"

// MergedOrgName は統合で作る、統合元の個人 Org の中身を移す共有 Org の名前（後から owner が変えられる）。
const MergedOrgName = "Merged account"

// MergedOrgs は統合で Org の側に起きたこと。
type MergedOrgs struct {
	// Personal は統合元の個人 Org（内部 ID と公開 ID）。残したまま、中身を Shared に移した。無ければ空。
	Personal, PersonalPublic string
	// Shared は作った共有 Org（公開 ID）。統合元の個人 Org が無ければ空。
	Shared string
	// Memberships は統合先に引き継いだ Membership の数。
	Memberships int
}

// MergeUser は from の Membership を into に引き継ぐ（11.6）。from の個人 Org は残し、新しい共有 Org を作って into を
// owner にし、個人 Org の中身（ロールの付与を除く）を移す。into が既に所属する Org では、役割の高い方と、active を残す。
// from の Membership は EndedMerged で終える（個人 Org のものは残す）。どちらかが Org 管理ユーザーなら ErrManagedUser
// （Org の許可の流れは未実装）。
func (s *Service) MergeUser(ctx context.Context, tx port.Tx, from, into port.User, actor audit.Actor, requestID string) (MergedOrgs, error) {
	if from.ManagedOrgID != "" || into.ManagedOrgID != "" {
		return MergedOrgs{}, ErrManagedUser
	}
	ms, err := tx.Memberships().ListByUser(ctx, from.RealmID, from.ID)
	if err != nil {
		return MergedOrgs{}, err
	}
	now := s.Clock.Now()
	var out MergedOrgs
	for _, m := range ms {
		if m.Status == port.MembershipEnded {
			continue
		}
		o, err := tx.Orgs().Get(ctx, m.RealmID, m.OrgID)
		if err != nil {
			return MergedOrgs{}, err
		}
		if o.DeletedAt != nil {
			continue
		}
		if o.Kind == port.OrgPersonal {
			if o.PersonalOwnerID == from.ID {
				if out.Shared, err = s.adoptPersonal(ctx, tx, o, into, actor, requestID); err != nil {
					return MergedOrgs{}, err
				}
				out.Personal, out.PersonalPublic = o.ID, o.PublicID
			}
			continue
		}
		if err := s.takeOver(ctx, tx, m, into.ID, now); err != nil {
			return MergedOrgs{}, err
		}
		m.Status, m.EndedReason, m.ManagementRequestedAt, m.UpdatedAt = port.MembershipEnded, EndedMerged, nil, now
		if m.ValidUntil == nil || m.ValidUntil.After(now) {
			m.ValidUntil = new(now)
		}
		if err := tx.Memberships().Update(ctx, m); err != nil {
			return MergedOrgs{}, err
		}
		out.Memberships++
	}
	return out, nil
}

// adoptPersonal は into を owner にした共有 Org を作り、個人 Org p の設定と中身を移して、その公開 ID を返す。
func (s *Service) adoptPersonal(ctx context.Context, tx port.Tx, p port.Org, into port.User, actor audit.Actor, requestID string) (string, error) {
	now := s.Clock.Now()
	o := port.Org{ID: id.New(id.Org), PublicID: id.NewExternal(id.Org), RealmID: p.RealmID, Kind: port.OrgShared, Name: MergedOrgName,
		CreatedAt: now, UpdatedAt: now}
	if err := tx.Orgs().Create(ctx, o); err != nil {
		return "", err
	}
	if p.Settings != nil {
		if err := tx.Orgs().SetSettings(ctx, o.RealmID, o.ID, p.Settings, now); err != nil {
			return "", err
		}
	}
	if _, err := s.addMember(ctx, tx, o, into.ID, port.OrgOwner); err != nil {
		return "", err
	}
	if err := tx.Orgs().MoveContents(ctx, p.RealmID, p.ID, o.ID); err != nil {
		return "", err
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.created", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"kind": string(o.Kind), "user_id": into.PublicID, "merged_from_org_id": p.PublicID},
	})
	return o.PublicID, err
}

// takeOver は from の Membership m を、into の Membership に引き継ぐ。
func (s *Service) takeOver(ctx context.Context, tx port.Tx, m port.Membership, into string, now time.Time) error {
	cur, err := tx.Memberships().GetByUserOrg(ctx, m.RealmID, into, m.OrgID)
	if errors.Is(err, errs.NotFound) {
		// メール（EmailID）は統合で同じ ID のまま into に移る。
		return tx.Memberships().Create(ctx, port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: m.RealmID,
			UserID: into, OrgID: m.OrgID, Status: m.Status, Role: m.Role, EmailID: m.EmailID, ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil,
			CreatedAt: now, UpdatedAt: now})
	}
	if err != nil {
		return err
	}
	if cur.Status == port.MembershipEnded {
		cur.Status, cur.Role, cur.EmailID, cur.ValidFrom, cur.ValidUntil, cur.EndedReason = m.Status, m.Role, m.EmailID, m.ValidFrom, m.ValidUntil, ""
	} else {
		if rank(m.Role) > rank(cur.Role) {
			cur.Role = m.Role
		}
		if m.Status == port.MembershipActive {
			cur.Status = port.MembershipActive
		}
	}
	cur.UpdatedAt = now
	return tx.Memberships().Update(ctx, cur)
}

func rank(r port.OrgRole) int {
	switch r {
	case port.OrgOwner:
		return 2
	case port.OrgAdmin:
		return 1
	}
	return 0
}
