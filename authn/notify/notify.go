// Package notify は通知の出来事を外部に渡す（design.md 2.4、ADR 0009、0031）。
//
// IAM はメールの文面も URL も作らない。ペイロードには ID だけを入れ、秘密（コード・トークン）と宛先は
// 配信用のサービスアカウントが claim で1回だけ取り出す。秘密は EphemeralStore に暗号化して置き、
// 有効期限で消える。IAM の Storage には秘密のハッシュだけを持つ（フローの側）。
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Topic は通知の outbox のトピック。
const Topic = "notification"

// 通知の種類（2.4）。
const (
	TypeEmailVerification = "email_verification"
	TypeMagicLink         = "magic_link"
	TypeAccountExists     = "account_exists"
)

// Secret は claim で1回だけ返すもの。
type Secret struct {
	RealmID   string    `json:"realm_id"`
	To        string    `json:"to"`
	Token     string    `json:"token,omitempty"` // マジックリンクのトークン
	Code      string    `json:"code,omitempty"`  // 確認コード
	ExpiresAt time.Time `json:"expires_at"`
}

// Service は通知を積み、秘密を claim させる。
type Service struct {
	Cache   port.EphemeralStore
	Crypter *pii.Crypter
	Clock   clock.Clock
}

func claimKey(realmID, notificationID string) string {
	return "claim:v1:" + realmID + ":" + notificationID
}

// Enqueue は通知を outbox に積む（呼び出し側のトランザクションで）。secret があれば claim 用に保持する。
// 宛先（to）は秘密と一緒に保持し、ペイロードには入れない。
func (s *Service) Enqueue(ctx context.Context, tx port.Tx, n port.Notification, secret *Secret) (port.Notification, error) {
	if n.ID == "" {
		n.ID = id.NewExternal(id.Notification)
	}
	n.HasSecret = secret != nil
	if secret != nil {
		secret.RealmID = n.RealmID
		ttl := secret.ExpiresAt.Sub(s.Clock.Now())
		if ttl <= 0 {
			return n, errs.New(errs.KindInvalid, "notify: secret already expired")
		}
		exp := secret.ExpiresAt
		n.ExpiresAt = &exp
		b, err := json.Marshal(secret)
		if err != nil {
			return n, err
		}
		sealed, err := s.Crypter.Seal(ctx, "notification.claim", b)
		if err != nil {
			return n, err
		}
		// トランザクションが取り消されても、取り出せない（通知が送られない）秘密が期限まで残るだけ。
		if err := s.Cache.Set(ctx, claimKey(n.RealmID, n.ID), sealed, ttl); err != nil {
			return n, err
		}
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return n, err
	}
	return n, tx.Outbox().Add(ctx, port.OutboxMessage{ID: n.ID, Topic: Topic, Payload: payload, CreatedAt: s.Clock.Now()})
}

// ErrNotClaimable は、無い・期限切れ・取り出し済み・別の realm の通知。区別しない。
var ErrNotClaimable = errs.WithCode(errs.KindNotFound, "not_found", "notification not claimable")

// Claim は秘密を1回だけ取り出す。
func (s *Service) Claim(ctx context.Context, realmID, notificationID string) (Secret, error) {
	if !id.Valid(id.Notification, notificationID) {
		return Secret{}, ErrNotClaimable
	}
	b, ok, err := s.Cache.Take(ctx, claimKey(realmID, notificationID))
	if err != nil {
		return Secret{}, err
	}
	if !ok {
		return Secret{}, ErrNotClaimable
	}
	pt, err := s.Crypter.Open(ctx, "notification.claim", b)
	if err != nil {
		return Secret{}, err
	}
	var sec Secret
	if err := json.Unmarshal(pt, &sec); err != nil {
		return Secret{}, err
	}
	if sec.RealmID != realmID || !s.Clock.Now().Before(sec.ExpiresAt) {
		return Secret{}, ErrNotClaimable
	}
	return sec, nil
}

// Deliverer は outbox の通知を Notifier に渡す関数を返す（eventlog.Relay の Deliver）。
// 読めないメッセージは配送済みにして飛ばす（送出全体を止めない）。
func Deliverer(n port.Notifier, log *slog.Logger) func(context.Context, []port.OutboxMessage) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx context.Context, msgs []port.OutboxMessage) ([]string, error) {
		var done []string
		for _, m := range msgs {
			var x port.Notification
			if err := json.Unmarshal(m.Payload, &x); err != nil {
				log.ErrorContext(ctx, "skipping unreadable notification", "id", m.ID, "error", err)
				done = append(done, m.ID)
				continue
			}
			if err := n.Notify(ctx, x); err != nil {
				return done, errors.Join(errors.New("notify: deliver "+m.ID), err)
			}
			done = append(done, m.ID)
		}
		return done, nil
	}
}
