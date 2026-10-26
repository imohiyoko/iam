package account

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 認証手段の追加・削除（design.md 4.2、4.3）。
//
// 不変条件（13.5）：本人の操作で、最後の確認済みメールと最後の認証手段は消せない。
// 追加はログイン済みの本人だけが行い、未ログインでメールが一致しても自動リンクしない。

// ErrLastEmail は最後の確認済みメールを消そうとしたこと。
var ErrLastEmail = errs.WithCode(errs.KindFailedPrecondition, "last_email", "cannot remove the last verified email")

// ErrPrimaryEmail は primary のメールを消そうとしたこと。先に別のメールを primary にする。
var ErrPrimaryEmail = errs.WithCode(errs.KindFailedPrecondition, "primary_email", "make another email primary first")

// ErrLastMethod は最後の認証手段を消そうとしたこと。
var ErrLastMethod = errs.WithCode(errs.KindFailedPrecondition, "last_method", "cannot remove the last authentication method")

// ErrEmailUnverified は未確認のメールを primary にしようとしたこと。
var ErrEmailUnverified = errs.WithCode(errs.KindFailedPrecondition, "email_unverified", "email is not verified")

// Methods はユーザーの認証手段。外部 ID の紐付けと passkey は無効化していないものだけ。
type Methods struct {
	Emails     []port.UserEmail
	Identities []port.Identity
	Passkeys   []port.Passkey
}

// ListMethods はユーザーのメールと、無効化していない外部 ID の紐付けと passkey を返す。
func (s *Service) ListMethods(ctx context.Context, tx port.Tx, realmID, userID string) (Methods, error) {
	es, err := tx.Emails().ListByUser(ctx, realmID, userID)
	if err != nil {
		return Methods{}, err
	}
	is, err := tx.Identities().ListByUser(ctx, realmID, userID)
	if err != nil {
		return Methods{}, err
	}
	ps, err := tx.Passkeys().ListByUser(ctx, realmID, userID)
	if err != nil {
		return Methods{}, err
	}
	m := Methods{Emails: es}
	for _, i := range is {
		if i.RevokedAt == nil {
			m.Identities = append(m.Identities, i)
		}
	}
	for _, p := range ps {
		if p.RevokedAt == nil {
			m.Passkeys = append(m.Passkeys, p)
		}
	}
	return m, nil
}

// loginMethods はログインに使える手段の数。外部 ID の紐付け、passkey、`code` が有効なら確認済みのメール。
// パスワードなどは、そのフィーチャーを足すときにここで数える。
func (s *Service) loginMethods(m Methods) int {
	n := len(m.Identities) + len(m.Passkeys)
	if s.Allows(port.VerifiedViaCode) {
		n += verified(m.Emails)
	}
	return n
}

func verified(es []port.UserEmail) int {
	n := 0
	for _, e := range es {
		if e.VerifiedAt != nil {
			n++
		}
	}
	return n
}

// AddEmail は所有を確認したメールをユーザーに足す（primary にはしない）。
// アドレスが使われていれば ErrEmailExists（同じユーザーでも同じ）。
func (s *Service) AddEmail(ctx context.Context, tx port.Tx, realmID, userID, email string, via port.VerifiedVia, actor audit.Actor, requestID string) (port.UserEmail, error) {
	if !s.Allows(via) {
		return port.UserEmail{}, ErrViaNotAllowed
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return port.UserEmail{}, err
	}
	ix, err := s.unusedIndex(ctx, tx, realmID, email)
	if err != nil {
		return port.UserEmail{}, err
	}
	e, err := s.createEmail(ctx, tx, realmID, userID, email, ix, via, false, s.Clock.Now())
	if err != nil {
		return port.UserEmail{}, err
	}
	return e, s.record(ctx, tx, realmID, "email.added", actor, requestID, map[string]any{"email_id": e.PublicID, "verified_via": string(via)})
}

// email はユーザーのメールを公開 ID で引く。別のユーザーのものは無いものとして扱う。
func email(ctx context.Context, tx port.Tx, realmID, userID, publicID string) (port.UserEmail, error) {
	e, err := tx.Emails().GetByPublicID(ctx, realmID, publicID)
	if err == nil && e.UserID != userID {
		err = errs.New(errs.KindNotFound, "email")
	}
	return e, err
}

// RemoveEmail はユーザーのメールを消す。primary は ErrPrimaryEmail、最後の確認済みメールは ErrLastEmail、
// 消すとログインの手段が無くなるなら ErrLastMethod。
func (s *Service) RemoveEmail(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) error {
	e, err := email(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return err
	}
	if e.IsPrimary {
		return ErrPrimaryEmail
	}
	m, err := s.ListMethods(ctx, tx, realmID, userID)
	if err != nil {
		return err
	}
	after := m
	after.Emails = nil
	for _, x := range m.Emails {
		if x.ID != e.ID {
			after.Emails = append(after.Emails, x)
		}
	}
	if verified(after.Emails) == 0 {
		return ErrLastEmail
	}
	if s.loginMethods(after) == 0 {
		return ErrLastMethod
	}
	if err := tx.Emails().Delete(ctx, realmID, e.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, "email.removed", actor, requestID, map[string]any{"email_id": e.PublicID})
}

// SetPrimaryEmail は確認済みのメールを primary にする。
func (s *Service) SetPrimaryEmail(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) error {
	e, err := email(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return err
	}
	if e.VerifiedAt == nil {
		return ErrEmailUnverified
	}
	if e.IsPrimary {
		return nil
	}
	if err := tx.Emails().SetPrimary(ctx, realmID, userID, e.ID); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, "email.primary_changed", actor, requestID, map[string]any{"email_id": e.PublicID})
}

// ReasonUnlinked は本人による外部 ID の連携の解除。
const ReasonUnlinked = "unlinked"

// UnlinkIdentity は外部 ID の紐付けを無効化する（削除しない。4.6）。最後のログインの手段なら ErrLastMethod。
// その外部 ID で作ったセッションは、次の検証（遅くとも validity_max_delay の後）から使えない。
func (s *Service) UnlinkIdentity(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) (port.Identity, error) {
	i, err := tx.Identities().GetByPublicID(ctx, realmID, publicID)
	if err == nil && (i.UserID != userID || i.RevokedAt != nil) {
		err = errs.New(errs.KindNotFound, "identity")
	}
	if err != nil {
		return port.Identity{}, err
	}
	m, err := s.ListMethods(ctx, tx, realmID, userID)
	if err != nil {
		return port.Identity{}, err
	}
	if s.loginMethods(m) <= 1 {
		return port.Identity{}, ErrLastMethod
	}
	if err := tx.Identities().Revoke(ctx, realmID, i.ID, s.Clock.Now(), ReasonUnlinked); err != nil {
		return port.Identity{}, err
	}
	return i, s.record(ctx, tx, realmID, "identity.unlinked", actor, requestID,
		map[string]any{"identity_id": i.PublicID, "connection_id": i.ConnectionID})
}

// ReasonRevokedByUser は本人による passkey の無効化。
const ReasonRevokedByUser = "revoked_by_user"

// ErrPasskeyName は passkey の名前の誤り（空、長すぎる、制御文字を含む）。
var ErrPasskeyName = errs.WithCode(errs.KindInvalid, "invalid_name", "invalid passkey name")

// MaxPasskeyName は passkey の名前の最大の長さ（文字数）。
const MaxPasskeyName = 64

// PasskeyName は名前を確かめ、前後の空白を除いたものを返す。
func PasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxPasskeyName ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", ErrPasskeyName
	}
	return name, nil
}

// passkey はユーザーの無効化していない passkey を公開 ID で引く。別のユーザーのものは無いものとして扱う。
func passkey(ctx context.Context, tx port.Tx, realmID, userID, publicID string) (port.Passkey, error) {
	p, err := tx.Passkeys().GetByPublicID(ctx, realmID, publicID)
	if err == nil && (p.UserID != userID || p.RevokedAt != nil) {
		err = errs.New(errs.KindNotFound, "passkey")
	}
	return p, err
}

// RenamePasskey は passkey の名前を変える。
func (s *Service) RenamePasskey(ctx context.Context, tx port.Tx, realmID, userID, publicID, name string, actor audit.Actor, requestID string) (port.Passkey, error) {
	name, err := PasskeyName(name)
	if err != nil {
		return port.Passkey{}, err
	}
	p, err := passkey(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return port.Passkey{}, err
	}
	if err := tx.Passkeys().Rename(ctx, realmID, p.ID, name); err != nil {
		return port.Passkey{}, err
	}
	p.Name = name
	return p, s.record(ctx, tx, realmID, "passkey.renamed", actor, requestID, map[string]any{"passkey_id": p.PublicID})
}

// RevokePasskey は passkey を無効化する（削除しない。同じ credential_id は再登録できない。4.6）。
// 最後のログインの手段なら ErrLastMethod。その passkey で作ったセッションは、次の検証
// （遅くとも validity_max_delay の後）から使えない。
func (s *Service) RevokePasskey(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) (port.Passkey, error) {
	p, err := passkey(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return port.Passkey{}, err
	}
	m, err := s.ListMethods(ctx, tx, realmID, userID)
	if err != nil {
		return port.Passkey{}, err
	}
	if s.loginMethods(m) <= 1 {
		return port.Passkey{}, ErrLastMethod
	}
	if err := tx.Passkeys().Revoke(ctx, realmID, p.ID, s.Clock.Now(), ReasonRevokedByUser); err != nil {
		return port.Passkey{}, err
	}
	return p, s.record(ctx, tx, realmID, "passkey.revoked", actor, requestID,
		map[string]any{"passkey_id": p.PublicID, "reason": ReasonRevokedByUser})
}

func (s *Service) record(ctx context.Context, tx port.Tx, realmID, typ string, actor audit.Actor, requestID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID, Details: details,
	})
	return err
}
