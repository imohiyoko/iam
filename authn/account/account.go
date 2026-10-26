// Package account はユーザーとメールアドレスを扱う（design.md 3.1、4.1〜4.3）。
//
// 不変条件（13.5）：全ユーザーが確認済みのメールを1つ以上持つ。ユーザーはメールの所有確認が済んだ時点で、
// 確認済みのメールと同じトランザクションで作る（CreateWithEmail）。ユーザーだけを作る経路は持たない。
package account

import (
	"context"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Service はユーザーとメールを扱う。
type Service struct {
	Crypter *pii.Crypter
	Clock   clock.Clock
	// VerifiedVia は realm が「確認済み」とみなす経路（4.1）。含まれない経路ではユーザーを作らない。
	VerifiedVia []port.VerifiedVia
}

// ErrEmailInvalid はメールアドレスの形式の誤り。
var ErrEmailInvalid = errs.WithCode(errs.KindInvalid, "invalid_email", "invalid email address")

// ErrViaNotAllowed は realm が受け入れない確認の経路。
var ErrViaNotAllowed = errs.WithCode(errs.KindFailedPrecondition, "verification_method_disabled", "verification method disabled in realm")

// NormalizeEmail はアドレスの形式を確かめ、正規化（小文字化のみ。9.5）したものを返す。
// 表示名つき（"A <a@example.com>"）や複数のアドレスは受け付けない。
func NormalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 {
		return "", ErrEmailInvalid
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s || !strings.Contains(s, "@") {
		return "", ErrEmailInvalid
	}
	return pii.NormalizeEmail(s), nil
}

// Allows は経路が realm で有効かを返す。
func (s *Service) Allows(via port.VerifiedVia) bool { return slices.Contains(s.VerifiedVia, via) }

// FindByEmail は正規化済みのアドレスのメールを返す。無ければ errs.NotFound。
func (s *Service) FindByEmail(ctx context.Context, tx port.Tx, realmID, email string) (port.UserEmail, error) {
	ix, err := s.Crypter.EmailIndex(ctx, email)
	if err != nil {
		return port.UserEmail{}, err
	}
	return tx.Emails().GetByIndex(ctx, realmID, ix.Value)
}

// Created は作ったユーザーと、その確認済みのメール。
type Created struct {
	User  port.User
	Email port.UserEmail
}

// CreateWithEmail はユーザーを、確認済みのメール（primary）と一緒に作る。
// アドレスが既に使われていれば ErrEmailExists（errs.Conflict。自動リンクはしない。4.2）。
func (s *Service) CreateWithEmail(ctx context.Context, tx port.Tx, realmID, email string, via port.VerifiedVia, actor audit.Actor, requestID string) (Created, error) {
	if !s.Allows(via) {
		return Created{}, ErrViaNotAllowed
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return Created{}, err
	}
	ix, err := s.unusedIndex(ctx, tx, realmID, email)
	if err != nil {
		return Created{}, err
	}
	now := s.Clock.Now()
	u := port.User{ID: id.New(id.User), PublicID: id.NewExternal(id.User), RealmID: realmID, Status: port.UserActive, CreatedAt: now, UpdatedAt: now}
	if err := tx.Users().Create(ctx, u); err != nil {
		return Created{}, err
	}
	if err := s.Crypter.CreateDataKey(ctx, tx.DataKeys(), u.ID, now); err != nil {
		return Created{}, err
	}
	e, err := s.createEmail(ctx, tx, realmID, u.ID, email, ix, via, true, now)
	if err != nil {
		return Created{}, err
	}
	if actor.Type == "" {
		actor = audit.Actor{Type: "user", ID: u.PublicID}
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: "user.created", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"user_id": u.PublicID, "verified_via": string(via)},
	})
	return Created{User: u, Email: e}, err
}

// ErrEmailExists は、アドレスが既にどれかのユーザーに紐付いていること（1つのアドレスは1ユーザーにだけ紐付く。4.2）。
var ErrEmailExists = errs.WithCode(errs.KindConflict, "email_exists", "email already registered")

// unusedIndex はアドレスのブラインドインデックスを返す。既に使われていれば ErrEmailExists。
// 書き込みの前に確かめる。ユーザーを作った後でメールの一意制約に当たると、呼び出し側が
// errs.Conflict を受けて処理を続けたとき、メールの無いユーザーが残る（13.5 の不変条件に反する）。
// 一意制約は同時に登録されたときの最後の守りとして残す。
func (s *Service) unusedIndex(ctx context.Context, tx port.Tx, realmID, email string) (pii.Index, error) {
	ix, err := s.Crypter.EmailIndex(ctx, email)
	if err != nil {
		return pii.Index{}, err
	}
	switch _, err := tx.Emails().GetByIndex(ctx, realmID, ix.Value); {
	case err == nil:
		return pii.Index{}, ErrEmailExists
	case !errors.Is(err, errs.NotFound):
		return pii.Index{}, err
	}
	return ix, nil
}

// createEmail は確認済みのメールを、ユーザーのデータ鍵で暗号化して置く。
func (s *Service) createEmail(ctx context.Context, tx port.Tx, realmID, userID, email string, ix pii.Index, via port.VerifiedVia, primary bool, now time.Time) (port.UserEmail, error) {
	dom, err := s.Crypter.DomainIndex(ctx, email)
	if err != nil {
		return port.UserEmail{}, err
	}
	ct, err := s.Crypter.Encrypt(ctx, tx.DataKeys(), userID, []byte(email), "email")
	if err != nil {
		return port.UserEmail{}, err
	}
	e := port.UserEmail{ID: id.New(id.Email), PublicID: id.NewExternal(id.Email), RealmID: realmID, UserID: userID, Ciphertext: ct,
		Index: ix.Value, DomainIndex: dom.Value, IndexKeyID: ix.KeyID, VerifiedAt: &now, VerifiedVia: via, IsPrimary: primary, CreatedAt: now}
	return e, tx.Emails().Create(ctx, e)
}

// EmailAddress はメールのアドレスを復号する。データ鍵が消されていれば pii.ErrShredded。
func (s *Service) EmailAddress(ctx context.Context, tx port.Tx, e port.UserEmail) (string, error) {
	if len(e.Ciphertext) == 0 {
		return "", errors.New("account: address not stored (index_only)")
	}
	b, err := s.Crypter.Decrypt(ctx, tx.DataKeys(), e.UserID, e.Ciphertext, "email")
	return string(b), err
}

// CanLogin はユーザーが now の時点で認証できる状態かを返す（削除・統合済みでなく、有効期間内。4.7、4.8）。
// 停止（suspensions）は停止のフィーチャーで足す。
func CanLogin(u port.User, now time.Time) bool {
	if u.Status != port.UserActive {
		return false
	}
	if u.ValidFrom != nil && now.Before(*u.ValidFrom) {
		return false
	}
	return u.ValidUntil == nil || now.Before(*u.ValidUntil)
}
