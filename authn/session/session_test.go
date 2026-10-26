package session_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

var cfg = session.Config{
	AbsoluteLifetime: 30 * 24 * time.Hour,
	IdleTimeout:      7 * 24 * time.Hour,
	ValidityMaxDelay: 30 * time.Second,
	RotationInterval: time.Hour,
	RotationGrace:    time.Minute,
}

func setup(t *testing.T) (*testkit.Kit, *session.Manager, port.User) {
	k := testkit.New(t)
	m := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Config: cfg}
	return k, m, k.SeedUser(t)
}

func issue(t *testing.T, k *testkit.Kit, m *session.Manager, u port.User, replaceToken string) session.Issued {
	t.Helper()
	var out session.Issued
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = m.Issue(ctx, tx, session.Issue{RealmID: k.RealmID, UserID: u.ID, AuthMethods: []string{"otp"},
			IP: "192.0.2.10", UserAgent: "test-agent", ReplaceToken: replaceToken})
		return err
	})
	return out
}

func mustValid(t *testing.T, m *session.Manager, realmID, token string) session.Validated {
	t.Helper()
	v, err := m.Validate(context.Background(), realmID, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return v
}

func mustInvalid(t *testing.T, m *session.Manager, realmID, token string) {
	t.Helper()
	_, err := m.Validate(context.Background(), realmID, token)
	if !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if !errors.Is(err, errs.AuthenticationFailed) {
		t.Fatalf("error must map to authentication_failed: %v", err)
	}
}

func TestIssueAndValidate(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	v := mustValid(t, m, k.RealmID, is.Token)
	if v.PrincipalID != u.ID || v.SessionID != is.Session.ID || v.RotateDue {
		t.Fatalf("validated = %+v", v)
	}
	// キャッシュに当たった後も同じ結果になる。
	if v2 := mustValid(t, m, k.RealmID, is.Token); v2.PrincipalID != u.ID {
		t.Fatalf("cached = %+v", v2)
	}
	// 別の realm では使えない。
	mustInvalid(t, m, "rlm_other", is.Token)
}

func TestWrongSecretRejected(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	sid, _, _ := session.SplitToken(is.Token)
	forged := sid + "." + strings.Repeat("A", 43)
	mustInvalid(t, m, k.RealmID, forged) // キャッシュに外れた場合
	mustValid(t, m, k.RealmID, is.Token)
	mustInvalid(t, m, k.RealmID, forged) // キャッシュに当たった場合
	for _, bad := range []string{"", "x", sid, sid + ".", "ses_bad." + strings.Repeat("A", 43), is.Token + "x"} {
		mustInvalid(t, m, k.RealmID, bad)
	}
}

// 不変条件：セッショントークンの秘密部分はログ・イベントに出ない（design.md 13.5）。
func TestSecretNotStoredOrLogged(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	mustValid(t, m, k.RealmID, is.Token)
	_, secret, _ := session.SplitToken(is.Token)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		s, err := tx.Sessions().Get(ctx, k.RealmID, is.Session.ID)
		if err != nil {
			return err
		}
		if bytes.Contains(s.TokenHash, []byte(secret)) || len(s.TokenHash) != 32 {
			t.Fatalf("token hash must be SHA-256 of the secret")
		}
		if bytes.Contains(s.IP, []byte("192.0.2.10")) || bytes.Contains(s.UserAgent, []byte("test-agent")) {
			t.Fatal("IP and User-Agent must be encrypted")
		}
		recs, err := tx.Audit().Scan(ctx, 1, 1000)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if bytes.Contains(r.Payload, []byte(secret)) {
				t.Fatalf("secret in audit log: %s", r.Payload)
			}
		}
		pending, err := tx.Outbox().Pending(ctx, "audit", 1000)
		for _, p := range pending {
			if bytes.Contains(p.Payload, []byte(secret)) {
				t.Fatalf("secret in outbox: %s", p.Payload)
			}
		}
		return err
	})
}

func TestRevokeIsImmediate(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	mustValid(t, m, k.RealmID, is.Token)
	if err := m.Revoke(context.Background(), k.RealmID, is.Session.ID, u.ID, session.ReasonLogout, audit.Actor{Type: "user", ID: u.PublicID}, ""); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, m, k.RealmID, is.Token)
}

func TestRevokeOthersSessionLooksMissing(t *testing.T) {
	k, m, u := setup(t)
	other := k.SeedUser(t)
	is := issue(t, k, m, other, "")
	err := m.Revoke(context.Background(), k.RealmID, is.Session.ID, u.ID, session.ReasonUser, audit.Actor{Type: "user", ID: u.PublicID}, "")
	if !errors.Is(err, errs.NotFound) {
		t.Fatalf("want NotFound, got %v", err)
	}
	mustValid(t, m, k.RealmID, is.Token)
}

// 不変条件：変更がセッション検証に反映される遅れは上限を超えない（design.md 5.3、13.5）。
// キャッシュの削除が届かなかった場合（Storage を直接書き換える）でも、ValidityMaxDelay の後には拒否する。
func TestRevocationReflectedWithinMaxDelay(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	mustValid(t, m, k.RealmID, is.Token) // キャッシュに載せる
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Sessions().Revoke(ctx, k.RealmID, is.Session.ID, k.Clock.Now(), "test")
	})
	k.Clock.Advance(cfg.ValidityMaxDelay - time.Nanosecond)
	mustValid(t, m, k.RealmID, is.Token) // 上限の内側ではキャッシュの結果が残りうる
	k.Clock.Advance(time.Nanosecond)
	mustInvalid(t, m, k.RealmID, is.Token)
}

func TestUserValidityEndHonoredByCache(t *testing.T) {
	k, m, _ := setup(t)
	end := k.Clock.Now().Add(10 * time.Second) // 反映遅れの上限より短い
	u := port.User{ID: "usr_00000000000000000000000001", PublicID: "11111111-1111-4111-8111-111111111111", RealmID: k.RealmID, Status: port.UserActive, ValidUntil: &end,
		CreatedAt: k.Clock.Now(), UpdatedAt: k.Clock.Now()}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		return k.Crypter.CreateDataKey(ctx, tx.DataKeys(), u.ID, k.Clock.Now())
	})
	is := issue(t, k, m, u, "")
	mustValid(t, m, k.RealmID, is.Token)
	k.Clock.Set(end)
	mustInvalid(t, m, k.RealmID, is.Token)
}

func TestExpiryAndIdleTimeout(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	k.Clock.Advance(cfg.IdleTimeout)
	mustInvalid(t, m, k.RealmID, is.Token)

	is = issue(t, k, m, u, "")
	// 使い続ければ無操作の期限は延びるが、絶対的な期限は延びない。
	for k.Clock.Now().Before(is.Session.ExpiresAt.Add(-24 * time.Hour)) {
		k.Clock.Advance(24 * time.Hour)
		mustValid(t, m, k.RealmID, is.Token)
	}
	k.Clock.Set(is.Session.ExpiresAt)
	mustInvalid(t, m, k.RealmID, is.Token)
}

// 不変条件：ログイン時にセッション ID が入れ替わる（design.md 5.2、13.5）。
func TestLoginReplacesSession(t *testing.T) {
	k, m, u := setup(t)
	old := issue(t, k, m, u, "")
	is := issue(t, k, m, u, old.Token)
	if is.Session.ID == old.Session.ID {
		t.Fatal("session ID must change on login")
	}
	mustInvalid(t, m, k.RealmID, old.Token)
	mustValid(t, m, k.RealmID, is.Token)

	// ID だけ（秘密なし）や偽のトークンでは、他人のセッションを失効させられない。
	other := k.SeedUser(t)
	os := issue(t, k, m, other, "")
	sid, _, _ := session.SplitToken(os.Token)
	issue(t, k, m, u, sid)
	issue(t, k, m, u, sid+"."+strings.Repeat("A", 43))
	mustValid(t, m, k.RealmID, os.Token)
}

func TestRotate(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	k.Clock.Advance(cfg.RotationInterval)
	v := mustValid(t, m, k.RealmID, is.Token)
	if !v.RotateDue {
		t.Fatal("rotation should be due")
	}
	ctx := context.Background()
	next, err := m.Rotate(ctx, k.RealmID, is.Session.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if next.Session.ID == is.Session.ID || !next.Session.AuthenticatedAt.Equal(is.Session.AuthenticatedAt) ||
		!next.Session.ExpiresAt.Equal(is.Session.ExpiresAt) {
		t.Fatalf("rotated = %+v", next.Session)
	}
	if v := mustValid(t, m, k.RealmID, next.Token); v.RotateDue {
		t.Fatal("new session must not be due")
	}
	// 同時に届いたリクエストは古い ID で通るが、二重には入れ替えない。
	mustValid(t, m, k.RealmID, is.Token)
	if _, err := m.Rotate(ctx, k.RealmID, is.Session.ID, ""); !errors.Is(err, session.ErrNotRotated) {
		t.Fatalf("second rotation: %v", err)
	}
	k.Clock.Advance(cfg.RotationGrace)
	mustInvalid(t, m, k.RealmID, is.Token)
	mustValid(t, m, k.RealmID, next.Token)
}

func TestRevokeAllAndList(t *testing.T) {
	k, m, u := setup(t)
	keep := issue(t, k, m, u, "")
	a := issue(t, k, m, u, "")
	b := issue(t, k, m, u, "")
	mustValid(t, m, k.RealmID, a.Token)
	list, err := m.List(context.Background(), k.RealmID, u.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %d, %v", len(list), err)
	}
	ids, err := m.RevokeAll(context.Background(), k.RealmID, u.ID, keep.Session.ID, "credential_changed", audit.Actor{Type: "user", ID: u.PublicID}, "")
	if err != nil || len(ids) != 2 {
		t.Fatalf("RevokeAll = %v, %v", ids, err)
	}
	mustInvalid(t, m, k.RealmID, a.Token)
	mustInvalid(t, m, k.RealmID, b.Token)
	mustValid(t, m, k.RealmID, keep.Token)
	list, _ = m.List(context.Background(), k.RealmID, u.ID)
	if len(list) != 1 || list[0].ID != keep.Session.ID {
		t.Fatalf("List after RevokeAll = %+v", list)
	}
}

// 入れ替え後の猶予中の古い ID も、一括失効ですぐに使えなくなる。
func TestRevokeAllEndsRotationGrace(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	k.Clock.Advance(cfg.RotationInterval)
	next, err := m.Rotate(context.Background(), k.RealmID, is.Session.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, m, k.RealmID, is.Token)
	if _, err := m.RevokeAll(context.Background(), k.RealmID, u.ID, "", "credential_changed", audit.Actor{Type: "user", ID: u.PublicID}, ""); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, m, k.RealmID, is.Token)
	mustInvalid(t, m, k.RealmID, next.Token)
}

// downStorage はトランザクションを始められないストレージ。
type downStorage struct{ port.Storage }

func (downStorage) Tx(context.Context, func(context.Context, port.Tx) error) error {
	return errors.New("db down")
}

// ストレージの障害は ErrInvalid にしない（呼び出し側が有効なセッションの Cookie を消さないため）。
func TestValidateStorageErrorIsNotInvalid(t *testing.T) {
	k, m, u := setup(t)
	is := issue(t, k, m, u, "")
	m.Storage = downStorage{k.Storage}
	_, err := m.Validate(context.Background(), k.RealmID, is.Token)
	if err == nil || errors.Is(err, session.ErrInvalid) {
		t.Fatalf("want a non-ErrInvalid error, got %v", err)
	}
	if errs.KindOf(err) != errs.KindUnavailable {
		t.Fatalf("kind: %v", errs.KindOf(err))
	}
}

func TestCompleteSecondFactorKeepsAuthenticatedAt(t *testing.T) {
	k, m, u := setup(t)
	m.Config.RequireSecondFactor = true
	first := issue(t, k, m, u, "")
	if first.Session.Restriction != port.RestrictionEnroll {
		t.Fatalf("restriction = %q", first.Session.Restriction)
	}
	k.Clock.Advance(time.Minute)
	var out session.Issued
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = m.CompleteSecondFactor(ctx, tx, k.RealmID, first.Session.ID, session.SecondFactor{AMR: []string{"otp"}})
		return err
	})
	// 要素の間に始まった停止を、解除の後にこのセッションが越えないよう、1要素目の時刻を引き継ぐ。
	if !out.Session.AuthenticatedAt.Equal(first.Session.AuthenticatedAt) {
		t.Fatalf("AuthenticatedAt = %v, want %v", out.Session.AuthenticatedAt, first.Session.AuthenticatedAt)
	}
}
