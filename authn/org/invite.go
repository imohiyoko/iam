package org

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 招待（design.md 4.4、ADR 0056）。招待したアドレスが Membership に結び付く。受け入れにはトークン（招待したアドレスに届く）と、
// アドレスの所有確認が要る。realm が経路 invitation を受け入れるならトークンが所有確認を兼ねる。受け入れないなら、
// 本人が先にそのアドレスを確認済みのメールとして持っている必要がある。

// TypeInvitation は招待の通知の種類。秘密（トークン）と宛先は claim で取り出す。
const TypeInvitation = "org_invitation"

// DefaultInvitationTTL は招待の有効期限の既定。
const DefaultInvitationTTL = 7 * 24 * time.Hour

var (
	// ErrPersonalOrg は個人 Org への招待など、個人 Org にはできない操作（11.13）。
	ErrPersonalOrg = errs.WithCode(errs.KindFailedPrecondition, "personal_org", "not allowed on a personal org")
	// ErrRoleInvalid は知らない org_role。
	ErrRoleInvalid = errs.WithCode(errs.KindInvalid, "invalid_org_role", "invalid org role")
	// ErrAlreadyMember は既に active な Membership がある。
	ErrAlreadyMember = errs.WithCode(errs.KindConflict, "already_member", "already a member")
	// ErrInvitationInvalid は無い・期限切れ・終わった・トークンの合わない招待。区別しない。
	ErrInvitationInvalid = errs.WithCode(errs.KindNotFound, "invalid_invitation", "invitation invalid")
	// ErrLoginRequired は、招待したアドレスが既存のユーザーのもので、ログインしていない。
	ErrLoginRequired = errs.WithCode(errs.KindFailedPrecondition, "login_required", "log in to accept the invitation")
	// ErrEmailVerificationRequired は、realm が招待をメールの確認とみなさず、本人がまだアドレスを確認していない。
	ErrEmailVerificationRequired = errs.WithCode(errs.KindFailedPrecondition, "email_verification_required", "verify the invited email first")
	// ErrValidityInvalid は有効期間の始まりが終わり以後。
	ErrValidityInvalid = errs.WithCode(errs.KindInvalid, "invalid_validity", "valid_from must be before valid_until")
)

// Invite は招待の内容。
type Invite struct {
	Email      string
	Role       port.OrgRole
	ValidFrom  *time.Time
	ValidUntil *time.Time
	// Managed は管理ユーザーとして招く（ADR 0076）。アドレスのドメインを Org が証明済みであること。
	Managed bool
}

// Invited は作った招待と、宛先（正規化したアドレス）。
type Invited struct {
	Invitation port.Invitation
	Email      string
}

func validRole(r port.OrgRole) bool {
	return r == port.OrgOwner || r == port.OrgAdmin || r == port.OrgMember
}

func (s *Service) invitationTTL() time.Duration {
	if s.InvitationTTL > 0 {
		return s.InvitationTTL
	}
	return DefaultInvitationTTL
}

// Invite は Org にアドレスを招待し、トークンを通知に積む。招待する人の権限は呼び出し側が確かめる。
func (s *Service) Invite(ctx context.Context, tx port.Tx, o port.Org, in Invite, actor audit.Actor, requestID string) (Invited, error) {
	if o.Kind != port.OrgShared {
		return Invited{}, ErrPersonalOrg
	}
	if !validRole(in.Role) {
		return Invited{}, ErrRoleInvalid
	}
	if in.ValidFrom != nil && in.ValidUntil != nil && !in.ValidFrom.Before(*in.ValidUntil) {
		return Invited{}, ErrValidityInvalid
	}
	email, err := account.NormalizeEmail(in.Email)
	if err != nil {
		return Invited{}, err
	}
	if in.Managed {
		if err := s.managedAddress(ctx, tx, o, email); err != nil {
			return Invited{}, err
		}
	}
	ix, err := s.Crypter.EmailIndex(ctx, email)
	if err != nil {
		return Invited{}, err
	}
	var userPublicID string
	switch e, err := tx.Emails().GetByIndex(ctx, o.RealmID, ix.Value); {
	case err == nil:
		m, err := tx.Memberships().GetByUserOrg(ctx, o.RealmID, e.UserID, o.ID)
		if err == nil && m.Status == port.MembershipActive {
			return Invited{}, ErrAlreadyMember
		}
		if err != nil && !errors.Is(err, errs.NotFound) {
			return Invited{}, err
		}
		u, err := tx.Users().Get(ctx, o.RealmID, e.UserID)
		if err != nil {
			return Invited{}, err
		}
		userPublicID = u.PublicID
	case !errors.Is(err, errs.NotFound):
		return Invited{}, err
	}
	// 招待中を数えるなら、招待の時点で枠を確かめる（受け入れのときは、その招待の枠を引き継ぐ）。
	if s.QuotaCount.Invited {
		if err := s.checkAdd(ctx, tx, o, spanOf(in.ValidFrom, in.ValidUntil), ""); err != nil {
			return Invited{}, err
		}
	}
	now := s.Clock.Now()
	inv := port.Invitation{ID: id.New(id.Invitation), PublicID: id.NewExternal(id.Invitation), RealmID: o.RealmID, OrgID: o.ID,
		EmailIndex: ix.Value, IndexKeyID: ix.KeyID, Role: in.Role, ValidFrom: in.ValidFrom, ValidUntil: in.ValidUntil,
		InvitedBy: actor.ID, ExpiresAt: now.Add(s.invitationTTL()), Status: port.InvitationPending, CreatedAt: now, Managed: in.Managed}
	// アドレスは招待ごとのデータ鍵で暗号化し、招待が終わったら鍵を消す（crypto-shredding）。
	if err := s.Crypter.CreateDataKey(ctx, tx.DataKeys(), inv.ID, now); err != nil {
		return Invited{}, err
	}
	if inv.EmailCiphertext, err = s.Crypter.Encrypt(ctx, tx.DataKeys(), inv.ID, []byte(email), "invitation.email"); err != nil {
		return Invited{}, err
	}
	token, hash, err := newInvitationToken(inv.PublicID)
	if err != nil {
		return Invited{}, err
	}
	inv.TokenHash = hash
	if err := tx.Invitations().Create(ctx, inv); err != nil {
		return Invited{}, err
	}
	// 期限の後にアドレスの鍵を消す（ADR 0060）。受け入れ・取り消しでは close が予約を取り消す。
	if err := eventlog.Schedule(ctx, tx, s.Clock, o.RealmID, invitationRef(inv), EventInvitationExpired, inv.ExpiresAt,
		map[string]any{"invitation_id": inv.PublicID}); err != nil {
		return Invited{}, err
	}
	n := port.Notification{Type: TypeInvitation, RealmID: o.RealmID, UserID: userPublicID, OrgID: o.PublicID}
	if _, err := s.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: email, Token: token, ExpiresAt: inv.ExpiresAt}); err != nil {
		return Invited{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.invitation.created", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"invitation_id": inv.PublicID, "role": string(inv.Role)},
	})
	return Invited{Invitation: inv, Email: email}, err
}

func newInvitationToken(publicID string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(secret))
	return publicID + "." + secret, h[:], nil
}

// InvitationEmail は pending の招待のアドレスを返す。終わった招待は鍵を消しているため空を返す。
func (s *Service) InvitationEmail(ctx context.Context, tx port.Tx, inv port.Invitation) (string, error) {
	if inv.Status != port.InvitationPending {
		return "", nil
	}
	b, err := s.Crypter.Decrypt(ctx, tx.DataKeys(), inv.ID, inv.EmailCiphertext, "invitation.email")
	return string(b), err
}

// Revoke は pending の招待を取り消し、アドレスの鍵を消す。終わった招待は ErrInvitationInvalid。
func (s *Service) Revoke(ctx context.Context, tx port.Tx, o port.Org, publicID string, actor audit.Actor, requestID string) error {
	inv, err := tx.Invitations().GetByPublicID(ctx, o.RealmID, publicID)
	if errors.Is(err, errs.NotFound) || (err == nil && inv.OrgID != o.ID) {
		return ErrInvitationInvalid
	}
	if err != nil {
		return err
	}
	if err := s.close(ctx, tx, inv, port.InvitationRevoked, actor.ID); err != nil {
		return err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.invitation.revoked", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"invitation_id": inv.PublicID},
	})
	return err
}

func (s *Service) close(ctx context.Context, tx port.Tx, inv port.Invitation, status port.InvitationStatus, by string) error {
	ok, err := tx.Invitations().Close(ctx, inv.RealmID, inv.ID, status, s.Clock.Now(), by)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvitationInvalid
	}
	if err := tx.ScheduledEvents().CancelByRef(ctx, inv.RealmID, invitationRef(inv)); err != nil {
		return err
	}
	return tx.DataKeys().Delete(ctx, inv.ID)
}

// EventInvitationExpired は招待の期限の後始末の出来事（Scheduler の Handler は ExpireDue）。
const EventInvitationExpired = "org.invitation.expired"

func invitationRef(inv port.Invitation) string { return "invitation:" + inv.PublicID }

// ExpireDue は期限を過ぎた pending の招待を expired にし、アドレスの鍵を消す（eventlog.Handler）。
// 既に終わった招待は何もしない。
func (s *Service) ExpireDue(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	publicID, _ := details["invitation_id"].(string)
	inv, err := tx.Invitations().GetByPublicID(ctx, e.RealmID, publicID)
	if errors.Is(err, errs.NotFound) {
		return eventlog.ErrSkip
	}
	if err != nil {
		return err
	}
	if inv.Status != port.InvitationPending {
		return eventlog.ErrSkip
	}
	err = s.close(ctx, tx, inv, port.InvitationExpired, "")
	if errors.Is(err, ErrInvitationInvalid) {
		return eventlog.ErrSkip
	}
	return err
}

// Accepted は受け入れの結果。Created は招待からの登録で作ったユーザー（ログインしていない受け入れ）。
type Accepted struct {
	Joined  Joined
	Created *account.Created
}

// Accept は招待を受け入れる。u はログインしている本人（いなければ nil）。
//
//   - アドレスが u のもの：そのメールを結び付ける
//   - アドレスが誰のものでもない：realm が経路 invitation を受け入れるなら、u に足す（u が nil なら、そのアドレスで登録する）。
//     受け入れないなら ErrEmailVerificationRequired（先にアドレスを確かめる）
//   - アドレスがほかのユーザーのもの：u がいれば account.ErrEmailExists、いなければ ErrLoginRequired
func (s *Service) Accept(ctx context.Context, tx port.Tx, realmID, token string, u *port.User, requestID string) (Accepted, error) {
	inv, err := s.lookup(ctx, tx, realmID, token)
	if err != nil {
		return Accepted{}, err
	}
	email, err := s.InvitationEmail(ctx, tx, inv)
	if err != nil {
		return Accepted{}, err
	}
	o, err := tx.Orgs().Get(ctx, realmID, inv.OrgID)
	if err != nil {
		return Accepted{}, err
	}
	var out Accepted
	var user port.User
	var bound port.UserEmail
	existing, err := tx.Emails().GetByIndex(ctx, realmID, inv.EmailIndex)
	switch {
	case err == nil && u != nil && existing.UserID == u.ID:
		if existing.VerifiedAt == nil {
			return Accepted{}, ErrEmailVerificationRequired
		}
		user, bound = *u, existing
	case err == nil && u != nil:
		return Accepted{}, account.ErrEmailExists
	case err == nil:
		return Accepted{}, ErrLoginRequired
	case !errors.Is(err, errs.NotFound):
		return Accepted{}, err
	case !s.Accounts.Allows(port.VerifiedViaInvitation):
		return Accepted{}, ErrEmailVerificationRequired
	case u != nil:
		user = *u
		if bound, err = s.Accounts.AddEmail(ctx, tx, realmID, u.ID, email, port.VerifiedViaInvitation, audit.Actor{Type: "user", ID: u.PublicID}, requestID); err != nil {
			return Accepted{}, err
		}
	default:
		c, err := s.Accounts.CreateWithEmail(ctx, tx, realmID, email, port.VerifiedViaInvitation, audit.Actor{}, requestID)
		if err != nil {
			return Accepted{}, err
		}
		out.Created, user, bound = &c, c.User, c.Email
	}
	actor := audit.Actor{Type: "user", ID: user.PublicID}
	m, err := s.join(ctx, tx, o, user, inv, bound.ID)
	if err != nil {
		return Accepted{}, err
	}
	if err := s.close(ctx, tx, inv, port.InvitationAccepted, user.PublicID); err != nil {
		return Accepted{}, err
	}
	if inv.Managed {
		if m, err = s.acceptManaged(ctx, tx, o, m, user, out.Created != nil, actor, requestID); err != nil {
			return Accepted{}, err
		}
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.invitation.accepted", Result: audit.ResultSuccess, RealmID: realmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"invitation_id": inv.PublicID, "membership_id": m.PublicID, "role": string(m.Role)},
	})
	out.Joined = Joined{Org: o, Membership: m}
	return out, err
}

func (s *Service) lookup(ctx context.Context, tx port.Tx, realmID, token string) (port.Invitation, error) {
	publicID, secret, ok := strings.Cut(token, ".")
	if !ok || !id.Valid(id.Invitation, publicID) || len(secret) != 43 {
		return port.Invitation{}, ErrInvitationInvalid
	}
	inv, err := tx.Invitations().GetByPublicID(ctx, realmID, publicID)
	if errors.Is(err, errs.NotFound) {
		return port.Invitation{}, ErrInvitationInvalid
	}
	if err != nil {
		return port.Invitation{}, err
	}
	h := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(inv.TokenHash, h[:]) != 1 || inv.Status != port.InvitationPending || !s.Clock.Now().Before(inv.ExpiresAt) {
		return port.Invitation{}, ErrInvitationInvalid
	}
	return inv, nil
}

// join は招待から Membership を作る。終わった Membership があれば使い直す（UNIQUE (user, org)。再参加は新しい招待で。4.10）。
func (s *Service) join(ctx context.Context, tx port.Tx, o port.Org, u port.User, inv port.Invitation, emailID string) (port.Membership, error) {
	now := s.Clock.Now()
	m, err := tx.Memberships().GetByUserOrg(ctx, o.RealmID, u.ID, o.ID)
	if err == nil && m.Status != port.MembershipEnded {
		return port.Membership{}, ErrAlreadyMember
	}
	// 受け入れる招待の枠は、数えていれば本人の分として除く（同じ人を2度数えない）。
	if err := s.checkAdd(ctx, tx, o, spanOf(inv.ValidFrom, inv.ValidUntil), inv.ID); err != nil {
		return port.Membership{}, err
	}
	switch {
	case err == nil && m.Status == port.MembershipEnded:
		m.Status, m.Role, m.EmailID, m.ValidFrom, m.ValidUntil, m.EndedReason, m.UpdatedAt =
			port.MembershipActive, inv.Role, emailID, inv.ValidFrom, inv.ValidUntil, "", now
		return m, tx.Memberships().Update(ctx, m)
	case err == nil:
		return port.Membership{}, ErrAlreadyMember
	case !errors.Is(err, errs.NotFound):
		return port.Membership{}, err
	}
	m = port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: o.RealmID, UserID: u.ID, OrgID: o.ID,
		Status: port.MembershipActive, Role: inv.Role, EmailID: emailID, ValidFrom: inv.ValidFrom, ValidUntil: inv.ValidUntil,
		CreatedAt: now, UpdatedAt: now}
	return m, tx.Memberships().Create(ctx, m)
}

// BindEmail は本人の Membership に、確認済みのメール（公開 ID）を結び付ける（4.4）。空なら primary に戻す。
func (s *Service) BindEmail(ctx context.Context, tx port.Tx, u port.User, orgPublicID, emailPublicID string, requestID string) (Joined, error) {
	o, err := tx.Orgs().GetByPublicID(ctx, u.RealmID, orgPublicID)
	if err != nil {
		return Joined{}, err
	}
	m, err := tx.Memberships().GetByUserOrg(ctx, u.RealmID, u.ID, o.ID)
	if err == nil && m.Status == port.MembershipEnded {
		err = errs.New(errs.KindNotFound, "membership")
	}
	if err != nil {
		return Joined{}, err
	}
	var emailID string
	if emailPublicID != "" {
		e, err := tx.Emails().GetByPublicID(ctx, u.RealmID, emailPublicID)
		if err == nil && e.UserID != u.ID {
			err = errs.New(errs.KindNotFound, "email")
		}
		if err != nil {
			return Joined{}, err
		}
		if e.VerifiedAt == nil {
			return Joined{}, account.ErrEmailUnverified
		}
		emailID = e.ID
	}
	m.EmailID, m.UpdatedAt = emailID, s.Clock.Now()
	if err := tx.Memberships().Update(ctx, m); err != nil {
		return Joined{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "membership.email_bound", Result: audit.ResultSuccess, RealmID: u.RealmID, OrgID: o.PublicID,
		Actor: audit.Actor{Type: "user", ID: u.PublicID}, RequestID: requestID,
		Details: map[string]any{"membership_id": m.PublicID, "email_id": emailPublicID},
	})
	return Joined{Org: o, Membership: m}, err
}

// BoundEmail は Membership に結び付いたメール（未設定なら primary）を返す。Org とその文脈に見せてよいのはこれだけ（4.4）。
func BoundEmail(ctx context.Context, tx port.Tx, m port.Membership) (port.UserEmail, error) {
	es, err := tx.Emails().ListByUser(ctx, m.RealmID, m.UserID)
	if err != nil {
		return port.UserEmail{}, err
	}
	for _, e := range es {
		if (m.EmailID != "" && e.ID == m.EmailID) || (m.EmailID == "" && e.IsPrimary) {
			return e, nil
		}
	}
	return port.UserEmail{}, errs.New(errs.KindNotFound, "email")
}
