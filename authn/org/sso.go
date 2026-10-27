package org

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Org 専用 SSO（design.md 11.3、ADR 0077）。connection の中身（OIDC の設定、フロー）は authn/oauth が扱い、
// ここでは Org の側（connection の持ち主、登録した人を管理ユーザーにすること）を扱う。フィーチャー org_managed_users。

// 監査ログの出来事。
const (
	EventConnectionAdded   = "org.connection.added"
	EventConnectionRemoved = "org.connection.removed"
	// EventMemberJoinedSSO は Org 専用 SSO での登録でメンバーになったこと。
	EventMemberJoinedSSO = "org.member.joined_sso"
)

// 外部 ID を無効化した理由。
const (
	RevokeConnectionDeleted  = "connection_deleted"
	RevokeManagementReleased = "management_released"
)

// ErrConnectionNotFound は Org の connection が無いこと。
var ErrConnectionNotFound = errs.New(errs.KindNotFound, "connection not found")

// SSODomainVerified は email（正規化済み）のドメインを Org（内部 ID）が証明済みかを返す（oauth.OrgSSO）。
func (s *Service) SSODomainVerified(ctx context.Context, tx port.Tx, realmID, orgID, email string) (bool, error) {
	if !s.ManagedUsers {
		return false, nil
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false, nil
	}
	d, err := tx.OrgDomains().GetVerified(ctx, realmID, domain)
	if errors.Is(err, errs.NotFound) {
		return false, nil
	}
	return err == nil && d.OrgID == orgID, err
}

// AdmitSSO は Org 専用 SSO で登録したユーザーを、その Org の管理ユーザーとメンバー（メールを結び付ける）にする（oauth.OrgSSO）。
func (s *Service) AdmitSSO(ctx context.Context, tx port.Tx, orgID string, u port.User, emailID, requestID string) error {
	o, err := tx.Orgs().Get(ctx, u.RealmID, orgID)
	if err != nil {
		return err
	}
	if err := s.checkAdd(ctx, tx, o, spanOf(nil, nil), ""); err != nil {
		return err
	}
	now := s.Clock.Now()
	m := port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: u.RealmID, OrgID: o.ID, UserID: u.ID,
		Status: port.MembershipActive, Role: port.OrgMember, EmailID: emailID, CreatedAt: now, UpdatedAt: now}
	if err := tx.Memberships().Create(ctx, m); err != nil {
		return err
	}
	if err := tx.Users().SetManagedOrg(ctx, u.RealmID, u.ID, o.ID, now); err != nil {
		return err
	}
	actor := audit.Actor{Type: "user", ID: u.PublicID}
	if _, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventMemberJoinedSSO, Result: audit.ResultSuccess, RealmID: o.RealmID,
		OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"membership_id": m.PublicID, "user_id": u.PublicID, "role": string(m.Role)}}); err != nil {
		return err
	}
	return s.recordManaged(ctx, tx, o, EventUserManaged, m, u, actor, requestID)
}

// Connections は Org の connection を作成の順に返す。
func (s *Service) Connections(ctx context.Context, tx port.Tx, o port.Org) ([]port.Connection, error) {
	return tx.Connections().ListByOwner(ctx, o.RealmID, o.ID)
}

// Connection は Org の connection を返す。別の Org のものや realm 共通のものは ErrConnectionNotFound。
func (s *Service) Connection(ctx context.Context, tx port.Tx, o port.Org, publicID string) (port.Connection, error) {
	c, err := tx.Connections().Get(ctx, o.RealmID, publicID)
	if errors.Is(err, errs.NotFound) || (err == nil && c.OwnerOrgID != o.ID) {
		return port.Connection{}, ErrConnectionNotFound
	}
	return c, err
}

// AddConnection は oauth.Service.NewOrgConnection で作った Org の connection を置く。個人 Org には置けない。
func (s *Service) AddConnection(ctx context.Context, tx port.Tx, o port.Org, c port.Connection, max int, actor audit.Actor, requestID string) error {
	if !s.ManagedUsers {
		return ErrManagedUsersDisabled
	}
	if o.Kind == port.OrgPersonal {
		return ErrPersonalOrg
	}
	if c.OwnerOrgID != o.ID || c.RealmID != o.RealmID {
		return errors.New("org: connection belongs to another org")
	}
	cs, err := tx.Connections().ListByOwner(ctx, o.RealmID, o.ID)
	if err != nil {
		return err
	}
	if len(cs) >= max {
		return ErrConnectionLimit
	}
	if err := tx.Connections().Create(ctx, c); err != nil {
		return err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventConnectionAdded, Result: audit.ResultSuccess, RealmID: o.RealmID,
		OrgID: o.PublicID, Actor: actor, RequestID: requestID, Details: map[string]any{"connection_id": c.ID}})
	return err
}

// ErrConnectionLimit は Org の connection が上限にあること。
var ErrConnectionLimit = errs.WithCode(errs.KindFailedPrecondition, "connection_limit", "the org has too many connections")

// RemoveConnection は Org の connection を消し、紐付けた外部 ID を無効化する。
func (s *Service) RemoveConnection(ctx context.Context, tx port.Tx, o port.Org, c port.Connection, actor audit.Actor, requestID string) error {
	if c.OwnerOrgID != o.ID {
		return ErrConnectionNotFound
	}
	n, err := removeConnection(ctx, tx, c, s.Clock.Now())
	if err != nil {
		return err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: EventConnectionRemoved, Result: audit.ResultSuccess, RealmID: o.RealmID,
		OrgID: o.PublicID, Actor: actor, RequestID: requestID, Details: map[string]any{"connection_id": c.ID, "identities_revoked": n}})
	return err
}

func removeConnection(ctx context.Context, tx port.Tx, c port.Connection, now time.Time) (int, error) {
	n, err := tx.Identities().RevokeByConnection(ctx, c.RealmID, c.ID, now, RevokeConnectionDeleted)
	if err != nil {
		return 0, err
	}
	return n, tx.Connections().Delete(ctx, c.RealmID, c.ID)
}

// PurgeConnections は Org の connection をすべて消す（Org の削除、フィーチャーの無効化の片付け。11.12）。消した数を返す。
func PurgeConnections(ctx context.Context, tx port.Tx, realmID, orgID string, now time.Time, limit int) (int, error) {
	cs, err := tx.Connections().ListByOwner(ctx, realmID, orgID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range cs {
		if limit >= 0 && n >= limit {
			break
		}
		if _, err := removeConnection(ctx, tx, c, now); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
