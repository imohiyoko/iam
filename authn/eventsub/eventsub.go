// Package eventsub はイベントの Webhook の購読を、realm ごとに管理 API で扱う（フィーチャー event_subscriptions。ADR 0100）。
//
// 購読は監査ログのイベントを、購読ごとの配送の位置（監査ログの seq）から順に送る。監査ログが操作と同じトランザクションで
// 書かれるので、監査ログそのものを outbox として使い、購読ごとに位置を持つ（少なくとも1回。受け取る側はイベント ID で重複を除く）。
// 設定ファイルの EventSink（ADR 0071）はそのまま残り、購読はそれとは別の送り先になる。
package eventsub

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はイベントの Webhook の購読（ADR 0100）。データは購読（とその署名の鍵のデータ鍵）。
var Feature = feature.Feature{Name: feature.EventSubscriptions, DataVersion: 1}

const (
	// MaxPerRealm は realm ごとの購読の数の上限。
	MaxPerRealm = 20
	// MaxEventTypes は購読ごとのイベントの種類の数の上限。
	MaxEventTypes = 20
	maxURLLength  = 2048

	// PIIOmit・PIIPseudonymize は切り詰めた IP と User-Agent の大分類の出し方（既定は出さない）。
	PIIOmit         = "omit"
	PIIPseudonymize = "pseudonymize"

	// SecretAAD は署名の鍵の暗号文の付加データ。
	SecretAAD = "event_subscription.secret"
	// secretPrefix は署名の鍵の接頭辞（漏洩の検出のため、見て分かる形にする）。
	secretPrefix = "whsec_"
)

var typeRE = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*\.?$`)

// Service は購読の作成・変更・削除。
type Service struct {
	Crypter *pii.Crypter
	Clock   clock.Clock
	// Dev は開発ビルド（http の宛先を許す）。
	Dev bool
	// AllowPrivateNetworks は公開でないアドレスの宛先を許す（開発・テストだけ）。
	AllowPrivateNetworks bool
}

// Input は購読の設定。nil の項目は変えない（作成では既定値）。
type Input struct {
	URL        *string
	EventTypes *[]string
	PII        *string
	Enabled    *bool
}

// Actor は操作した主体（監査ログ）。
type Actor struct {
	Audit     audit.Actor
	RequestID string
}

// CheckURL は宛先の URL を確かめる。https に限り（開発ビルドだけ http）、利用者情報と断片を持たない。
// IP アドレスで書いた宛先は、公開のアドレスに限る（名前で書いた宛先は、送るときにつなぐ先で確かめる）。
func (s *Service) CheckURL(raw string) (string, error) {
	invalid := errs.WithCode(errs.KindInvalid, "invalid_url", "url must be an absolute https URL without credentials or fragment")
	if raw == "" || len(raw) > maxURLLength {
		return "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", invalid
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && s.Dev:
	default:
		return "", invalid
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && !s.AllowPrivateNetworks && !oauth.PublicAddr(a) {
		return "", errs.WithCode(errs.KindInvalid, "invalid_url", "url must not point to a non-public address")
	}
	return u.String(), nil
}

// CheckEventTypes は送るイベントの種類を確かめる。"." で終われば前方一致。重複は除き、昇順にする。
func CheckEventTypes(in []string) ([]string, error) {
	invalid := errs.WithCode(errs.KindInvalid, "invalid_event_types", "event_types must be up to 20 event types or prefixes ending with '.'")
	if len(in) > MaxEventTypes {
		return nil, invalid
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		if len(t) == 0 || len(t) > 100 || !typeRE.MatchString(t) {
			return nil, invalid
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func checkPII(v string) (string, error) {
	switch v {
	case "":
		return PIIOmit, nil
	case PIIOmit, PIIPseudonymize:
		return v, nil
	}
	return "", errs.WithCode(errs.KindInvalid, "invalid_pii", "pii must be omit or pseudonymize")
}

// Wants は購読が type のイベントを送るかを返す。
func Wants(sub port.EventSubscription, typ string) bool {
	if len(sub.EventTypes) == 0 {
		return true
	}
	for _, t := range sub.EventTypes {
		if t == typ || (strings.HasSuffix(t, ".") && strings.HasPrefix(typ, t)) {
			return true
		}
	}
	return false
}

// newSecret は署名の鍵を作る（256 ビット）。
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return secretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Create は購読を作り、署名の鍵を返す（鍵を返すのはこのときと RotateSecret だけ）。購読は作った時点の後のイベントから送る。
func (s *Service) Create(ctx context.Context, tx port.Tx, realmID string, in Input, a Actor) (port.EventSubscription, string, error) {
	sub := port.EventSubscription{ID: id.NewExternal(id.EventSubscription), RealmID: realmID, Enabled: true, CreatedBy: a.Audit.ID}
	if err := s.apply(&sub, in, true); err != nil {
		return sub, "", err
	}
	existing, err := tx.EventSubscriptions().List(ctx, realmID)
	if err != nil {
		return sub, "", err
	}
	if len(existing) >= MaxPerRealm {
		return sub, "", errs.WithCode(errs.KindConflict, "subscription_limit", "too many event subscriptions in this realm")
	}
	now := s.Clock.Now()
	sub.CreatedAt, sub.UpdatedAt = now, now
	if last, err := tx.Audit().Last(ctx); err != nil {
		return sub, "", err
	} else if last != nil {
		sub.CursorSeq = last.Seq
	}
	if err := s.Crypter.CreateDataKey(ctx, tx.DataKeys(), sub.ID, now); err != nil {
		return sub, "", err
	}
	secret, err := s.seal(ctx, tx, &sub)
	if err != nil {
		return sub, "", err
	}
	if err := tx.EventSubscriptions().Create(ctx, sub); err != nil {
		return sub, "", err
	}
	return sub, secret, s.record(ctx, tx, "event_subscription.created", sub, a, map[string]any{"enabled": sub.Enabled})
}

// apply は in を sub に書く。create なら URL が要る。
func (s *Service) apply(sub *port.EventSubscription, in Input, create bool) error {
	if in.URL != nil || create {
		u := ""
		if in.URL != nil {
			u = *in.URL
		}
		v, err := s.CheckURL(u)
		if err != nil {
			return err
		}
		sub.URL = v
	}
	if in.EventTypes != nil || create {
		var ts []string
		if in.EventTypes != nil {
			ts = *in.EventTypes
		}
		v, err := CheckEventTypes(ts)
		if err != nil {
			return err
		}
		sub.EventTypes = v
	}
	if in.PII != nil || create {
		p := ""
		if in.PII != nil {
			p = *in.PII
		}
		v, err := checkPII(p)
		if err != nil {
			return err
		}
		sub.PII = v
	}
	if in.Enabled != nil {
		sub.Enabled = *in.Enabled
	}
	return nil
}

func (s *Service) seal(ctx context.Context, tx port.Tx, sub *port.EventSubscription) (string, error) {
	secret, err := newSecret()
	if err != nil {
		return "", err
	}
	sub.SecretCiphertext, err = s.Crypter.Encrypt(ctx, tx.DataKeys(), sub.ID, []byte(secret), SecretAAD)
	return secret, err
}

// Secret は購読の署名の鍵を返す（送るとき）。
func (s *Service) Secret(ctx context.Context, tx port.Tx, sub port.EventSubscription) ([]byte, error) {
	return s.Crypter.Decrypt(ctx, tx.DataKeys(), sub.ID, sub.SecretCiphertext, SecretAAD)
}

// Update は設定を変える。止めていた購読を有効に戻すと、待ちの時刻と失敗の回数を戻す（位置はそのまま。止めていた間の分も送る）。
func (s *Service) Update(ctx context.Context, tx port.Tx, realmID, subID string, in Input, a Actor) (port.EventSubscription, error) {
	sub, err := tx.EventSubscriptions().Get(ctx, realmID, subID)
	if err != nil {
		return sub, err
	}
	wasEnabled := sub.Enabled
	if err := s.apply(&sub, in, false); err != nil {
		return sub, err
	}
	sub.UpdatedAt = s.Clock.Now()
	if err := tx.EventSubscriptions().Update(ctx, sub); err != nil {
		return sub, err
	}
	if sub.Enabled && !wasEnabled {
		sub.Failures, sub.NextAttemptAt, sub.LastError = 0, nil, ""
		if err := tx.EventSubscriptions().SetDelivery(ctx, realmID, subID, sub.EventSubscriptionDelivery); err != nil {
			return sub, err
		}
	}
	return sub, s.record(ctx, tx, "event_subscription.updated", sub, a, map[string]any{"enabled": sub.Enabled})
}

// RotateSecret は署名の鍵を作り直して返す。古い鍵はすぐに使わなくなる。
func (s *Service) RotateSecret(ctx context.Context, tx port.Tx, realmID, subID string, a Actor) (port.EventSubscription, string, error) {
	sub, err := tx.EventSubscriptions().Get(ctx, realmID, subID)
	if err != nil {
		return sub, "", err
	}
	secret, err := s.seal(ctx, tx, &sub)
	if err != nil {
		return sub, "", err
	}
	sub.UpdatedAt = s.Clock.Now()
	if err := tx.EventSubscriptions().Update(ctx, sub); err != nil {
		return sub, "", err
	}
	return sub, secret, s.record(ctx, tx, "event_subscription.secret_rotated", sub, a, nil)
}

// Delete は購読と署名の鍵（データ鍵）を消す。
func (s *Service) Delete(ctx context.Context, tx port.Tx, realmID, subID string, a Actor) error {
	sub, err := tx.EventSubscriptions().Get(ctx, realmID, subID)
	if err != nil {
		return err
	}
	if err := tx.EventSubscriptions().Delete(ctx, realmID, subID); err != nil {
		return err
	}
	if err := tx.DataKeys().Delete(ctx, subID); err != nil {
		return err
	}
	return s.record(ctx, tx, "event_subscription.deleted", sub, a, nil)
}

// RecordTest はテスト送信の結果を監査ログに残す。
func (s *Service) RecordTest(ctx context.Context, tx port.Tx, sub port.EventSubscription, a Actor, r Result) error {
	res := map[string]any{"delivered": r.Delivered}
	if r.Error != "" {
		res["error"] = r.Error
	}
	return s.recordResult(ctx, tx, "event_subscription.tested", sub, a, res, r.Delivered)
}

func (s *Service) record(ctx context.Context, tx port.Tx, typ string, sub port.EventSubscription, a Actor, extra map[string]any) error {
	return s.recordResult(ctx, tx, typ, sub, a, extra, true)
}

// recordResult は購読の出来事を監査ログに残す。URL は経路や問い合わせに秘密を含みうるので、ホスト名だけを残す。
func (s *Service) recordResult(ctx context.Context, tx port.Tx, typ string, sub port.EventSubscription, a Actor, extra map[string]any, ok bool) error {
	d := map[string]any{"subscription_id": sub.ID, "host": hostOf(sub.URL), "event_types": sub.EventTypes, "pii": sub.PII}
	for k, v := range extra {
		d[k] = v
	}
	result := audit.ResultSuccess
	if !ok {
		result = audit.ResultFailure
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: result, RealmID: sub.RealmID, Actor: a.Audit,
		RequestID: a.RequestID, Details: d})
	return err
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// Purge は全 realm の購読を最大 limit 件、署名の鍵（データ鍵）とともに消す（フィーチャーの無効化。design.md 11.12）。
func Purge(ctx context.Context, tx port.Tx, limit int) (int, error) {
	ids, err := tx.EventSubscriptions().Purge(ctx, limit)
	if err != nil {
		return 0, err
	}
	for _, sid := range ids {
		if err := tx.DataKeys().Delete(ctx, sid); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
