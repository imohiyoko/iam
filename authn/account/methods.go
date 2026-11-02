package account

import (
	"context"

	"github.com/imohiyoko/iam/authn/method"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
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

// ErrEmailBound は Membership に結び付けたメールを消そうとしたこと。先に結び付け直す（4.4）。
var ErrEmailBound = errs.WithCode(errs.KindFailedPrecondition, "email_bound_to_membership", "rebind the membership email first")

// ErrLastMethod は最後の認証手段を消そうとしたこと。
var ErrLastMethod = errs.WithCode(errs.KindFailedPrecondition, "last_method", "cannot remove the last authentication method")

// ErrEmailUnverified は未確認のメールを primary にしようとしたこと。
var ErrEmailUnverified = errs.WithCode(errs.KindFailedPrecondition, "email_unverified", "email is not verified")

// Methods はユーザーの認証手段。外部 ID の紐付けと passkey は無効化していないものだけ。
type Methods struct {
	Emails     []port.UserEmail
	Identities []port.Identity
	// Passkeys は有効な passkey（汎用の認証情報の方式 passkey。ADR 0106）。Relying Party が決まらない構成でも数える（従来どおり）。
	Passkeys []port.Credential
	// TOTP は有効な TOTP（汎用の認証情報の方式 totp。ADR 0101）。2要素目だけに使う（ログインの手段には数えない）。
	TOTP []port.Credential
	// Password は有効なパスワード（汎用の認証情報の方式 password。フィーチャー password。ADR 0101）。無ければ nil。
	// フィーチャーが止まっていても数える（従来どおり）。
	Password *port.Credential
	// Credentials は無効化していない汎用の認証情報（認証方式のプラグイン。ADR 0092）のうち、TOTP とパスワード以外。
	Credentials []port.Credential
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
	cs, err := tx.Credentials().ListByUser(ctx, realmID, userID, "")
	if err != nil {
		return Methods{}, err
	}
	m := Methods{Emails: es}
	for _, c := range cs {
		switch {
		case c.RevokedAt != nil:
		case c.Method == method.TOTP:
			m.TOTP = append(m.TOTP, c)
		case c.Method == method.Password:
			if m.Password == nil {
				m.Password = &c
			}
		case c.Method == method.Passkey:
			m.Passkeys = append(m.Passkeys, c)
		default:
			m.Credentials = append(m.Credentials, c)
		}
	}
	for _, i := range is {
		if i.RevokedAt == nil {
			m.Identities = append(m.Identities, i)
		}
	}
	return m, nil
}

// loginMethods はログインに使える手段の数。外部 ID の紐付け、passkey、パスワード、`code` が有効なら確認済みのメール、
// 動いている方式のうち1要素目に使えるものの汎用の認証情報。
func (s *Service) loginMethods(m Methods) int {
	n := len(m.Identities) + len(m.Passkeys)
	for _, c := range m.Credentials {
		if s.Methods.Supports(c.Method, port.UsageFirstFactor) {
			n++
		}
	}
	if m.Password != nil {
		n++
	}
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
	return s.addEmail(ctx, tx, realmID, userID, email, via, actor, requestID, nil)
}

// AdminAddEmail は運営者が所有を確かめたメールを、確認済み（admin）として足す（ADR 0097）。監査ログに対象のユーザーを残す。
func (s *Service) AdminAddEmail(ctx context.Context, tx port.Tx, u port.User, email string, actor audit.Actor, requestID string) (port.UserEmail, error) {
	if u.Status != port.UserActive {
		return port.UserEmail{}, ErrUserNotActive
	}
	return s.addEmail(ctx, tx, u.RealmID, u.ID, email, port.VerifiedViaAdmin, actor, requestID, map[string]any{"user_id": u.PublicID})
}

// ErrUserNotActive は削除・統合したユーザーへの操作。
var ErrUserNotActive = errs.WithCode(errs.KindFailedPrecondition, "user_not_active", "the user is not active")

// subjectDetails は監査ログの details に、運営者の操作の対象（subject）を足す。
func subjectDetails(d, subject map[string]any) map[string]any {
	for k, v := range subject {
		d[k] = v
	}
	return d
}

func (s *Service) addEmail(ctx context.Context, tx port.Tx, realmID, userID, email string, via port.VerifiedVia, actor audit.Actor, requestID string, subject map[string]any) (port.UserEmail, error) {
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
	return e, s.record(ctx, tx, realmID, "email.added", actor, requestID,
		subjectDetails(map[string]any{"email_id": e.PublicID, "verified_via": string(via)}, subject))
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
	return s.removeEmail(ctx, tx, realmID, userID, publicID, actor, requestID, nil)
}

// AdminRemoveEmail は運営者によるメールの削除（ADR 0097）。本人と同じ不変条件を守る。監査ログに対象のユーザーを残す。
func (s *Service) AdminRemoveEmail(ctx context.Context, tx port.Tx, u port.User, publicID string, actor audit.Actor, requestID string) error {
	return s.removeEmail(ctx, tx, u.RealmID, u.ID, publicID, actor, requestID, map[string]any{"user_id": u.PublicID})
}

func (s *Service) removeEmail(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string, subject map[string]any) error {
	e, err := email(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return err
	}
	if e.IsPrimary {
		return ErrPrimaryEmail
	}
	// Membership に結び付けたメールは、結び付け直してからでないと消せない（4.4）。
	ms, err := tx.Memberships().ListByUser(ctx, realmID, userID)
	if err != nil {
		return err
	}
	for _, x := range ms {
		if x.EmailID == e.ID && x.Status != port.MembershipEnded {
			return ErrEmailBound
		}
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
	return s.record(ctx, tx, realmID, "email.removed", actor, requestID, subjectDetails(map[string]any{"email_id": e.PublicID}, subject))
}

// SetPrimaryEmail は確認済みのメールを primary にする。
func (s *Service) SetPrimaryEmail(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) error {
	return s.setPrimaryEmail(ctx, tx, realmID, userID, publicID, actor, requestID, nil)
}

// AdminSetPrimaryEmail は運営者による primary のメールの変更（ADR 0097）。監査ログに対象のユーザーを残す。
func (s *Service) AdminSetPrimaryEmail(ctx context.Context, tx port.Tx, u port.User, publicID string, actor audit.Actor, requestID string) error {
	return s.setPrimaryEmail(ctx, tx, u.RealmID, u.ID, publicID, actor, requestID, map[string]any{"user_id": u.PublicID})
}

func (s *Service) setPrimaryEmail(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string, subject map[string]any) error {
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
	return s.record(ctx, tx, realmID, "email.primary_changed", actor, requestID, subjectDetails(map[string]any{"email_id": e.PublicID}, subject))
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
var ErrPasskeyName = passkeym.ErrName

// MaxPasskeyName は passkey の名前の最大の長さ（文字数）。
const MaxPasskeyName = passkeym.MaxName

// PasskeyName は名前を確かめ、前後の空白を除いたものを返す。
func PasskeyName(name string) (string, error) { return passkeym.ValidName(name) }

// passkey はユーザーの無効化していない passkey を公開 ID（汎用の crd_。ADR 0106）で引く。別のユーザーのものと、
// passkey でないものは無いものとして扱う。
func passkey(ctx context.Context, tx port.Tx, realmID, userID, publicID string) (port.Credential, error) {
	c, err := credential(ctx, tx, realmID, userID, publicID)
	if err == nil && c.Method != method.Passkey {
		err = errs.New(errs.KindNotFound, "passkey")
	}
	return c, err
}

// RenamePasskey は passkey の名前を変える。名前は方式のデータにあるので、復号して暗号化し直し、比較と交換で書く
// （同時のログインが署名の回数を書いていれば errs.Conflict）。
func (s *Service) RenamePasskey(ctx context.Context, tx port.Tx, realmID, userID, publicID, name string, actor audit.Actor, requestID string) (passkeym.Summary, error) {
	name, err := PasskeyName(name)
	if err != nil {
		return passkeym.Summary{}, err
	}
	c, err := passkey(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return passkeym.Summary{}, err
	}
	mc, d, err := passkeym.Read(ctx, tx, s.Crypter, c)
	if err != nil {
		return passkeym.Summary{}, err
	}
	d.Name = name
	raw, err := passkeym.Encode(d)
	if err != nil {
		return passkeym.Summary{}, err
	}
	ct, err := s.Crypter.Encrypt(ctx, tx.DataKeys(), c.UserID, raw, method.DataAAD(c.Method, c.ID))
	if err != nil {
		return passkeym.Summary{}, err
	}
	if err := tx.Credentials().UpdateData(ctx, realmID, c.ID, c.Data, ct, c.DataVersion); err != nil {
		return passkeym.Summary{}, err
	}
	return passkeym.View(mc, d), s.record(ctx, tx, realmID, "passkey.renamed", actor, requestID, map[string]any{"passkey_id": c.PublicID})
}

// RevokePasskey は passkey を無効化する（削除しない。同じ credential ID は再登録できない。4.6）。
// 最後のログインの手段なら ErrLastMethod。その passkey で作ったセッションは、次の検証
// （遅くとも validity_max_delay の後）から使えない。
func (s *Service) RevokePasskey(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) (port.Credential, error) {
	c, err := passkey(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return port.Credential{}, err
	}
	m, err := s.ListMethods(ctx, tx, realmID, userID)
	if err != nil {
		return port.Credential{}, err
	}
	if s.loginMethods(m) <= 1 {
		return port.Credential{}, ErrLastMethod
	}
	if err := tx.Credentials().Revoke(ctx, realmID, c.ID, s.Clock.Now(), ReasonRevokedByUser); err != nil {
		return port.Credential{}, err
	}
	return c, s.record(ctx, tx, realmID, "passkey.revoked", actor, requestID,
		map[string]any{"passkey_id": c.PublicID, "reason": ReasonRevokedByUser})
}

// RevokePassword はパスワードを無効化する（削除しない）。最後のログインの手段なら ErrLastMethod。
// 他のセッションの失効は呼び出し側が行う（5.2）。
func (s *Service) RevokePassword(ctx context.Context, tx port.Tx, realmID, userID string, c port.Credential, reason string, actor audit.Actor, requestID string) error {
	m, err := s.ListMethods(ctx, tx, realmID, userID)
	if err != nil {
		return err
	}
	if s.loginMethods(m) <= 1 {
		return ErrLastMethod
	}
	if err := tx.Credentials().Revoke(ctx, realmID, c.ID, s.Clock.Now(), reason); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, "password.removed", actor, requestID, map[string]any{"reason": reason, "credential_id": c.PublicID})
}

// RevokeTOTP は TOTP を無効化する（削除しない。4.6）。TOTP は2要素目だけに使うので、最後の1つでも
// 無効化できる（2段階認証が必須なら、次のログインで登録を求める）。
// ID は汎用の crd_ のもの（ADR 0101）。
func (s *Service) RevokeTOTP(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) (port.Credential, error) {
	c, err := credential(ctx, tx, realmID, userID, publicID)
	if err == nil && c.Method != method.TOTP {
		err = errs.New(errs.KindNotFound, "totp")
	}
	if err != nil {
		return port.Credential{}, err
	}
	if err := tx.Credentials().Revoke(ctx, realmID, c.ID, s.Clock.Now(), ReasonRevokedByUser); err != nil {
		return port.Credential{}, err
	}
	return c, s.record(ctx, tx, realmID, "totp.revoked", actor, requestID, map[string]any{"totp_id": c.PublicID, "reason": ReasonRevokedByUser})
}

func (s *Service) record(ctx context.Context, tx port.Tx, realmID, typ string, actor audit.Actor, requestID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID, Details: details,
	})
	return err
}
