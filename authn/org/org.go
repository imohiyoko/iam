// Package org は Org と Membership を扱う（design.md 3.1、4.4、11.13、ADR 0055）。
//
// フィーチャー org がオンのとき、ユーザーと同じトランザクションで個人 Org と、本人の owner の Membership を作る。
// 共有 Org は作った人を owner にして作る。セッションの active な Org は常に値を持つ（Pick）。
package org

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	feature.Register(feature.Feature{Name: feature.Org, DataVersion: 1, DefaultEnabled: true})
}

// CreationPolicy は共有 Org を作れる人（design.md 4.11）。運営者は管理 API からいつでも作れる。
type CreationPolicy string

const (
	// CreateAnyone はログインしているユーザーなら誰でも作れる（既定）。
	CreateAnyone CreationPolicy = "anyone"
	// CreateOperatorsOnly は運営者（管理 API）だけが作れる。
	CreateOperatorsOnly CreationPolicy = "operators_only"
	// CreateInviteOnly は、共有 Org の active な Membership を持つ（どこかの Org に招かれた）ユーザーだけが作れる。
	CreateInviteOnly CreationPolicy = "invite_only"
)

// MaxNameLength は Org の名前の最大の文字数。
const MaxNameLength = 100

var (
	// ErrNameInvalid は名前が空・長すぎる・制御文字を含む。
	ErrNameInvalid = errs.WithCode(errs.KindInvalid, "invalid_org_name", "invalid org name")
	// ErrCreationNotAllowed は作成のポリシーで作れない。
	ErrCreationNotAllowed = errs.WithCode(errs.KindPermissionDenied, "org_creation_not_allowed", "org creation not allowed")
	// ErrNoAvailableOrg は入れる Org が無い（4.4、4.9）。
	ErrNoAvailableOrg = errs.WithCode(errs.KindPermissionDenied, errs.CodeNoAvailableOrg, "no available org")
)

// Service は Org と Membership を扱う。
type Service struct {
	Clock  clock.Clock
	Policy CreationPolicy
}

// NormalizeName は名前の前後の空白を除き、形式を確かめる。
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxNameLength {
		return "", ErrNameInvalid
	}
	if strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) }) {
		return "", ErrNameInvalid
	}
	return name, nil
}

// CreatePersonal はユーザーの個人 Org と、本人の owner の Membership を作る（11.13）。
// ユーザーの作成と同じトランザクションで呼ぶ。既にあれば errs.Conflict。
func (s *Service) CreatePersonal(ctx context.Context, tx port.Tx, u port.User, actor audit.Actor, requestID string) (port.Org, error) {
	now := s.Clock.Now()
	o := port.Org{ID: id.New(id.Org), PublicID: id.NewExternal(id.Org), RealmID: u.RealmID, Kind: port.OrgPersonal,
		PersonalOwnerID: u.ID, CreatedAt: now, UpdatedAt: now}
	if err := tx.Orgs().Create(ctx, o); err != nil {
		return port.Org{}, err
	}
	if _, err := s.addMember(ctx, tx, o, u.ID, port.OrgOwner); err != nil {
		return port.Org{}, err
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.created", Result: audit.ResultSuccess, RealmID: u.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"kind": string(o.Kind), "user_id": u.PublicID},
	})
	return o, err
}

// EnsurePersonal はユーザーの個人 Org を返す。無ければ作る（後から Org を有効にしたときの、準備処理の取りこぼしの救済）。
func (s *Service) EnsurePersonal(ctx context.Context, tx port.Tx, u port.User, requestID string) (port.Org, error) {
	o, err := tx.Orgs().GetPersonal(ctx, u.RealmID, u.ID)
	if err == nil || !errors.Is(err, errs.NotFound) {
		return o, err
	}
	return s.CreatePersonal(ctx, tx, u, audit.Actor{Type: "system"}, requestID)
}

// Create は共有 Org を作り、owner を最初のオーナーにする。operator は運営者（管理 API）による作成で、ポリシーを見ない。
func (s *Service) Create(ctx context.Context, tx port.Tx, owner port.User, name string, operator bool, actor audit.Actor, requestID string) (port.Org, port.Membership, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	if !operator {
		if err := s.mayCreate(ctx, tx, owner); err != nil {
			return port.Org{}, port.Membership{}, err
		}
	}
	now := s.Clock.Now()
	o := port.Org{ID: id.New(id.Org), PublicID: id.NewExternal(id.Org), RealmID: owner.RealmID, Kind: port.OrgShared, Name: name,
		CreatedAt: now, UpdatedAt: now}
	if err := tx.Orgs().Create(ctx, o); err != nil {
		return port.Org{}, port.Membership{}, err
	}
	m, err := s.addMember(ctx, tx, o, owner.ID, port.OrgOwner)
	if err != nil {
		return port.Org{}, port.Membership{}, err
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "org.created", Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"kind": string(o.Kind), "owner_id": owner.PublicID, "membership_id": m.PublicID},
	})
	return o, m, err
}

func (s *Service) mayCreate(ctx context.Context, tx port.Tx, u port.User) error {
	switch s.Policy {
	case CreateAnyone, "":
		return nil
	case CreateInviteOnly:
		ms, err := tx.Memberships().ListByUser(ctx, u.RealmID, u.ID)
		if err != nil {
			return err
		}
		for _, m := range ms {
			if m.Status != port.MembershipActive {
				continue
			}
			o, err := tx.Orgs().Get(ctx, u.RealmID, m.OrgID)
			if err != nil {
				return err
			}
			if o.Kind == port.OrgShared {
				return nil
			}
		}
	}
	return ErrCreationNotAllowed
}

func (s *Service) addMember(ctx context.Context, tx port.Tx, o port.Org, userID string, r port.OrgRole) (port.Membership, error) {
	now := s.Clock.Now()
	m := port.Membership{ID: id.New(id.Membership), PublicID: id.NewExternal(id.Membership), RealmID: o.RealmID, UserID: userID,
		OrgID: o.ID, Status: port.MembershipActive, Role: r, CreatedAt: now, UpdatedAt: now}
	return m, tx.Memberships().Create(ctx, m)
}

// Joined は Membership と、その Org。
type Joined struct {
	Org        port.Org
	Membership port.Membership
}

// ListForUser はユーザーの終了していない Membership と Org を、作成の順に返す。
func (s *Service) ListForUser(ctx context.Context, tx port.Tx, realmID, userID string) ([]Joined, error) {
	ms, err := tx.Memberships().ListByUser(ctx, realmID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Joined, 0, len(ms))
	for _, m := range ms {
		if m.Status == port.MembershipEnded {
			continue
		}
		o, err := tx.Orgs().Get(ctx, realmID, m.OrgID)
		if err != nil {
			return nil, err
		}
		out = append(out, Joined{Org: o, Membership: m})
	}
	return out, nil
}

// Pick はログインで入る Org（内部 ID）を決める（4.4）。explicit（内部 ID）があれば、その Org の active な
// Membership が要る。無ければ個人 Org（無ければ作る）。手がかりと前回の Org による選択は Resolve で足す。
func (s *Service) Pick(ctx context.Context, tx port.Tx, u port.User, explicit, requestID string) (string, error) {
	if explicit != "" {
		m, err := tx.Memberships().GetByUserOrg(ctx, u.RealmID, u.ID, explicit)
		if errors.Is(err, errs.NotFound) || (err == nil && m.Status != port.MembershipActive) {
			return "", ErrNoAvailableOrg
		}
		if err != nil {
			return "", err
		}
		return explicit, nil
	}
	o, err := s.EnsurePersonal(ctx, tx, u, requestID)
	if err != nil {
		return "", err
	}
	return o.ID, nil
}
