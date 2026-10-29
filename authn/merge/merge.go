// Package merge はアカウント統合を扱う（design.md 11.6、ADR 0082）。
//
// 統合元 B でログインした本人が1回限りの統合トークンを発行し、統合先 A でログインした本人がそれを使う（両方の所有の証明）。
// B のメール・外部 ID・passkey・TOTP・パスワード・ロールの付与・Group の所属・カスタム属性の値・Membership を A に移し、
// B を merged にして、B のセッションとログインの系列を終える。取り消しはできない。
package merge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/totp"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー account_merge の宣言（features/accountmerge が登録する）。
var Feature = feature.Feature{Name: feature.AccountMerge, DataVersion: 1}

// TokenTTL は統合トークンの寿命。
const TokenTTL = 10 * time.Minute

// EventUserMerged は統合の出来事（監査ログと EventSink。sub が変わることを連携先に伝える）。
const EventUserMerged = "user.merged"

// ReasonMerged はセッション・外部 ID・認証手段を統合で終えた理由。
const ReasonMerged = "merged"

const sealPurpose = "flow.merge"

var (
	// ErrInvalidToken は統合トークンが無い・使用済み・期限切れ・別の realm のもの。
	ErrInvalidToken = errs.WithCode(errs.KindInvalid, "invalid_merge_token", "invalid or expired merge token")
	// ErrSameUser は統合元と統合先が同じユーザー。
	ErrSameUser = errs.WithCode(errs.KindInvalid, "same_user", "cannot merge a user into itself")
	// ErrDeletionScheduled はどちらかに削除の予定があること。
	ErrDeletionScheduled = errs.WithCode(errs.KindFailedPrecondition, "deletion_scheduled", "cancel the account deletion first")
	// ErrLegalHold は統合元に消去の保留があること（統合元の記録を残す必要がある）。
	ErrLegalHold = errs.WithCode(errs.KindFailedPrecondition, "legal_hold", "the account is under legal hold")
)

// Service は統合トークンと統合を扱う。
type Service struct {
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Sessions *session.Manager
	// Orgs は Membership と個人 Org を引き継ぐ。nil ならフィーチャー org が動いていない。
	Orgs *org.Service
}

// Token は発行した統合トークン。
type Token struct {
	Token     string
	ExpiresAt time.Time
}

type state struct {
	RealmID   string    `json:"realm_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return "merge:" + hex.EncodeToString(h[:])
}

// Issue は統合元のユーザー u（ログイン中の本人）の統合トークンを発行する。
func (s *Service) Issue(ctx context.Context, tx port.Tx, u port.User) (Token, error) {
	if err := s.mergeable(ctx, tx, u); err != nil {
		return Token{}, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Token{}, err
	}
	t := Token{Token: base64.RawURLEncoding.EncodeToString(b), ExpiresAt: s.Clock.Now().Add(TokenTTL)}
	raw, err := json.Marshal(state{RealmID: u.RealmID, UserID: u.ID, ExpiresAt: t.ExpiresAt})
	if err != nil {
		return Token{}, err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, raw)
	if err != nil {
		return Token{}, err
	}
	return t, s.Cache.Set(ctx, tokenKey(t.Token), sealed, TokenTTL)
}

// take は統合トークンを使い、統合元のユーザー（内部 ID）を返す。1回しか使えない。
func (s *Service) take(ctx context.Context, realmID, token string) (string, error) {
	if token == "" {
		return "", ErrInvalidToken
	}
	b, ok, err := s.Cache.Take(ctx, tokenKey(token))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrInvalidToken
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return "", ErrInvalidToken
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil || st.RealmID != realmID || !s.Clock.Now().Before(st.ExpiresAt) {
		return "", ErrInvalidToken
	}
	return st.UserID, nil
}

// mergeable は u が統合に加われるかを確かめる。
func (s *Service) mergeable(ctx context.Context, tx port.Tx, u port.User) error {
	now := s.Clock.Now()
	if _, err := account.Check(ctx, tx, u, now, now); err != nil {
		return err
	}
	switch {
	case u.DeletionScheduledAt != nil:
		return ErrDeletionScheduled
	case u.ManagedOrgID != "":
		return org.ErrManagedUser // Org の許可の流れは未実装（ADR 0082）
	}
	return nil
}

// Merged は統合の結果。
type Merged struct {
	// From は統合元のユーザー（公開 ID）。
	From string
	// SharedOrg は統合元の個人 Org の中身を移した、新しい共有 Org（公開 ID）。無ければ空。
	SharedOrg string
	// PersonalOrg は統合元の個人 Org（公開 ID。残したまま）。無ければ空。
	PersonalOrg string
	// Sessions は失効させた統合元のセッション。確定の後に Sessions.ForgetIDs に渡す。
	Sessions []string
}

// Merge は token の統合元のユーザーを into（ログイン中の統合先の本人）に統合する。呼び出し側のトランザクションで呼ぶ。
func (s *Service) Merge(ctx context.Context, tx port.Tx, into port.User, token string, actor audit.Actor, requestID string) (Merged, error) {
	fromID, err := s.take(ctx, into.RealmID, token)
	if err != nil {
		return Merged{}, err
	}
	if fromID == into.ID {
		return Merged{}, ErrSameUser
	}
	from, err := tx.Users().Get(ctx, into.RealmID, fromID)
	if errors.Is(err, errs.NotFound) {
		return Merged{}, ErrInvalidToken
	}
	if err != nil {
		return Merged{}, err
	}
	if from.Status != port.UserActive {
		return Merged{}, ErrInvalidToken
	}
	if from.LegalHold {
		return Merged{}, ErrLegalHold
	}
	for _, u := range []port.User{from, into} {
		if err := s.mergeable(ctx, tx, u); err != nil {
			return Merged{}, err
		}
	}
	out := Merged{From: from.PublicID}
	var personal string
	if s.Orgs != nil {
		mo, err := s.Orgs.MergeUser(ctx, tx, from, into, actor, requestID)
		if err != nil {
			return Merged{}, err
		}
		out.SharedOrg, out.PersonalOrg, personal = mo.Shared, mo.PersonalPublic, mo.Personal
	}
	moved, err := s.move(ctx, tx, from, into, personal)
	if err != nil {
		return Merged{}, err
	}
	// ログインの系列（連携先の認可、Back-Channel Logout）を終えてから、セッションを失効させる。
	if err := s.Sessions.EndUserTx(ctx, tx, from.RealmID, from.ID, ReasonMerged, requestID); err != nil {
		return Merged{}, err
	}
	if out.Sessions, err = s.Sessions.RevokeAllTx(ctx, tx, from.RealmID, from.ID, "", ReasonMerged, actor, requestID); err != nil {
		return Merged{}, err
	}
	now := s.Clock.Now()
	if err := tx.Users().SetMerged(ctx, from.RealmID, from.ID, into.ID, now); err != nil {
		return Merged{}, err
	}
	details := map[string]any{"user_id": into.PublicID, "merged_user_id": from.PublicID}
	for k, v := range moved {
		details[k] = v
	}
	if out.SharedOrg != "" {
		// ホスト先は、個人 Org の ID で持つデータを新しい Org に付け替える。
		details["shared_org_id"], details["personal_org_id"] = out.SharedOrg, out.PersonalOrg
	}
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: EventUserMerged, Result: audit.ResultSuccess, RealmID: into.RealmID, Actor: actor, RequestID: requestID, Details: details,
	})
	return out, err
}

// move は from の認証手段・付与・属性を into に移し、種類ごとの件数を返す。personal は from の個人 Org（内部 ID）で、
// そこでの付与は移さない（個人 Org に残す）。
func (s *Service) move(ctx context.Context, tx port.Tx, from, into port.User, personal string) (map[string]int, error) {
	n := map[string]int{}
	var err error
	bindings := func(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
		return s.moveBindings(ctx, tx, from, into, personal)
	}
	steps := []struct {
		name string
		fn   func(context.Context, port.Tx, port.User, port.User) (int, error)
	}{
		{"emails", s.moveEmails}, {"identities", s.moveIdentities}, {"passkeys", movePasskeys}, {"totp", s.moveTOTP},
		{"passwords", s.movePassword}, {"role_bindings", bindings}, {"groups", s.moveGroups}, {"attributes", s.moveAttributes},
	}
	for _, st := range steps {
		if n[st.name], err = st.fn(ctx, tx, from, into); err != nil {
			return nil, err
		}
	}
	// リカバリーコードは統合元のものを捨てる（統合先のものを使う）。
	return n, tx.RecoveryCodes().Replace(ctx, from.RealmID, from.ID, nil)
}

// recrypt は from のデータ鍵の暗号文を into のデータ鍵で暗号化し直す。
func (s *Service) recrypt(ctx context.Context, tx port.Tx, from, into string, ct []byte, aad string) ([]byte, error) {
	if len(ct) == 0 {
		return ct, nil
	}
	pt, err := s.Crypter.Decrypt(ctx, tx.DataKeys(), from, ct, aad)
	if err != nil {
		return nil, err
	}
	return s.Crypter.Encrypt(ctx, tx.DataKeys(), into, pt, aad)
}

// moveEmails はメールを同じ ID のまま移す（Membership の EmailID が指し続けるように）。primary は統合先のものを残す。
func (s *Service) moveEmails(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	es, err := tx.Emails().ListByUser(ctx, from.RealmID, from.ID)
	if err != nil {
		return 0, err
	}
	for _, e := range es {
		ct, err := s.recrypt(ctx, tx, from.ID, into.ID, e.Ciphertext, account.EmailAAD)
		if err != nil {
			return 0, err
		}
		if err := tx.Emails().Delete(ctx, e.RealmID, e.ID); err != nil {
			return 0, err
		}
		e.UserID, e.Ciphertext, e.IsPrimary = into.ID, ct, false
		if err := tx.Emails().Create(ctx, e); err != nil {
			return 0, err
		}
	}
	return len(es), nil
}

// moveIdentities は有効な外部 ID の紐付けを統合先に付け直す（統合元の紐付けは無効化して残す）。
func (s *Service) moveIdentities(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	is, err := tx.Identities().ListByUser(ctx, from.RealmID, from.ID)
	if err != nil {
		return 0, err
	}
	now, n := s.Clock.Now(), 0
	for _, i := range is {
		if i.RevokedAt != nil {
			continue
		}
		if err := tx.Identities().Revoke(ctx, i.RealmID, i.ID, now, ReasonMerged); err != nil {
			return 0, err
		}
		if err := tx.Identities().Create(ctx, port.Identity{ID: id.New(id.Identity), PublicID: id.NewExternal(id.Identity), RealmID: i.RealmID,
			UserID: into.ID, ConnectionID: i.ConnectionID, ProviderSubject: i.ProviderSubject, CreatedAt: now}); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// movePasskeys は passkey を移す。認証器は統合元のユーザーハンドルを返すので、それを passkey に残す。
func movePasskeys(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	return tx.Passkeys().MoveUser(ctx, from.RealmID, from.ID, into.ID, []byte(from.PublicID))
}

// moveTOTP は統合先に TOTP が無ければ統合元の有効な TOTP を移し、統合元のものは無効化する。
func (s *Service) moveTOTP(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	mine, err := tx.TOTP().ListByUser(ctx, into.RealmID, into.ID)
	if err != nil {
		return 0, err
	}
	has := false
	for _, c := range mine {
		has = has || c.RevokedAt == nil
	}
	theirs, err := tx.TOTP().ListByUser(ctx, from.RealmID, from.ID)
	if err != nil {
		return 0, err
	}
	now, n := s.Clock.Now(), 0
	for _, c := range theirs {
		if c.RevokedAt != nil {
			continue
		}
		if !has {
			ct, err := s.recrypt(ctx, tx, from.ID, into.ID, c.SecretCiphertext, totp.SecretAAD)
			if err != nil {
				return 0, err
			}
			if err := tx.TOTP().Create(ctx, port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: c.RealmID,
				UserID: into.ID, SecretCiphertext: ct, LastUsedStep: c.LastUsedStep, CreatedAt: c.CreatedAt}); err != nil {
				return 0, err
			}
			has, n = true, n+1
		}
		if err := tx.TOTP().Revoke(ctx, c.RealmID, c.ID, now, ReasonMerged); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// movePassword は統合先にパスワードが無ければ統合元のものを移し、統合元のものは無効化する。
func (s *Service) movePassword(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	theirs, err := tx.Passwords().GetActive(ctx, from.RealmID, from.ID)
	if errors.Is(err, errs.NotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	if _, err := tx.Passwords().GetActive(ctx, into.RealmID, into.ID); errors.Is(err, errs.NotFound) {
		if err := tx.Passwords().Create(ctx, port.PasswordCredential{ID: id.New(id.Password), RealmID: theirs.RealmID, UserID: into.ID,
			Hash: theirs.Hash, CreatedAt: theirs.CreatedAt}); err != nil {
			return 0, err
		}
		n = 1
	} else if err != nil {
		return 0, err
	}
	return n, tx.Passwords().Revoke(ctx, theirs.RealmID, theirs.ID, s.Clock.Now(), ReasonMerged)
}

// moveBindings はロールの付与を統合先に付け直す（同じ付与が既にあれば、統合元の付与を消すだけ）。個人 Org personal での
// 付与は統合元に残す。
func (s *Service) moveBindings(ctx context.Context, tx port.Tx, from, into port.User, personal string) (int, error) {
	all, err := tx.RoleBindings().ListByPrincipal(ctx, from.RealmID, port.PrincipalUser, from.ID)
	if err != nil {
		return 0, err
	}
	var bs []port.RoleBinding
	for _, b := range all {
		if personal == "" || b.OrgID != personal {
			bs = append(bs, b)
		}
	}
	for _, b := range bs {
		c := b
		c.ID, c.PublicID, c.PrincipalID = id.New(id.RoleBinding), id.NewExternal(id.RoleBinding), into.ID
		if err := tx.RoleBindings().Create(ctx, c); err != nil && !errors.Is(err, errs.Conflict) {
			return 0, err
		}
		if err := tx.RoleBindings().Delete(ctx, b.RealmID, b.ID); err != nil {
			return 0, err
		}
	}
	return len(bs), nil
}

// moveGroups は Group の所属を統合先に付け直す。
func (s *Service) moveGroups(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	gs, err := tx.Groups().ListByMember(ctx, from.RealmID, port.PrincipalUser, from.ID)
	if err != nil {
		return 0, err
	}
	now := s.Clock.Now()
	for _, g := range gs {
		err := tx.Groups().AddMember(ctx, g.RealmID, port.GroupMember{GroupID: g.ID, MemberType: port.PrincipalUser, MemberID: into.ID, CreatedAt: now})
		if err != nil && !errors.Is(err, errs.Conflict) {
			return 0, err
		}
		if err := tx.Groups().RemoveMember(ctx, g.RealmID, g.ID, port.PrincipalUser, from.ID); err != nil {
			return 0, err
		}
	}
	return len(gs), nil
}

// moveAttributes はカスタム属性の値を、統合先に値の無い属性だけ移す。統合元の値は消す。
func (s *Service) moveAttributes(ctx context.Context, tx port.Tx, from, into port.User) (int, error) {
	theirs, err := tx.Attributes().ListValues(ctx, from.RealmID, from.ID)
	if err != nil || len(theirs) == 0 {
		return 0, err
	}
	mine, err := tx.Attributes().ListValues(ctx, into.RealmID, into.ID)
	if err != nil {
		return 0, err
	}
	have := map[string]bool{}
	for _, v := range mine {
		have[v.Key] = true
	}
	defs, err := tx.Attributes().ListDefs(ctx, from.RealmID)
	if err != nil {
		return 0, err
	}
	encrypted := map[string]bool{}
	for _, d := range defs {
		encrypted[d.Key] = d.Encrypted
	}
	now, n := s.Clock.Now(), 0
	for _, v := range theirs {
		if !have[v.Key] {
			val := v.Value
			if encrypted[v.Key] {
				if val, err = s.recrypt(ctx, tx, from.ID, into.ID, val, attribute.AAD(v.Key)); err != nil {
					return 0, err
				}
			}
			if err := tx.Attributes().SetValue(ctx, port.UserAttribute{RealmID: v.RealmID, UserID: into.ID, Key: v.Key, Value: val, UpdatedAt: now}); err != nil {
				return 0, err
			}
			n++
		}
		if err := tx.Attributes().DeleteValue(ctx, v.RealmID, from.ID, v.Key); err != nil {
			return 0, err
		}
	}
	return n, nil
}
