package eventlog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの IP と User-Agent の暗号化（design.md 9.5、9.6、ADR 0063）。
//
// ペイロードの ip と user_agent は切り詰めた値（audit.TruncateIP、audit.ClassifyUA）にし、全文は client に置く。
// client は、操作した本人（actor がユーザーのとき）のデータ鍵で暗号化してから、realm と日ごとの鍵でもう一度暗号化する。
//
//   - アカウントを削除すると本人のデータ鍵が消え、本人の全文は読めなくなる（4.10）
//   - 日ごとの鍵は保持期間（既定30日）の後に消し、その日の全文は誰のものも読めなくなる（9.6）
//
// ハッシュチェーンのレコードは書き換えないので、改ざんの検出はそのまま効く。

// EventClientKeyExpired は日ごとの鍵の保持期間の終わり（鍵を消す。Scheduler の Handler は ClientSealer.Expire）。
const EventClientKeyExpired = "audit.client_key.expired"

// DefaultClientRetention は全文を読める既定の期間（9.6）。
const DefaultClientRetention = 30 * 24 * time.Hour

const clientAAD = "audit_events.client"

// ErrClientUnreadable は全文が読めないこと（保持期間の後、アカウントの削除の後、記録が無い）。
var ErrClientUnreadable = errors.New("eventlog: client data is no longer readable")

// ClientSealer は監査ログの IP と User-Agent の全文を暗号化する。
type ClientSealer struct {
	Crypter *pii.Crypter
	Clock   clock.Clock
	// Retention は全文を読める期間。0 なら DefaultClientRetention。
	Retention time.Duration
	// AuditKeys は監査ログのハッシュチェーンの鍵（ADR 0086）。nil か、鍵を置いていなければ鍵なしのチェーンにする。
	AuditKeys port.AuditKeyStore
}

// Storage は、トランザクションの中の Record が全文を暗号化し、チェーンを監査の鍵で作るようにした s を返す。
// これを通さない Storage への Record は、切り詰めた値だけを残し（全文は残さない）、チェーンは鍵なし。
func (c *ClientSealer) Storage(s port.Storage) port.Storage { return sealingStorage{s, c} }

type sealingStorage struct {
	port.Storage
	c *ClientSealer
}

func (s sealingStorage) Tx(ctx context.Context, fn func(ctx context.Context, tx port.Tx) error) error {
	return s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, sealingTx{tx, s.c}) })
}

type sealingTx struct {
	port.Tx
	c *ClientSealer
}

type clientData struct {
	IP string `json:"ip,omitempty"`
	UA string `json:"ua,omitempty"`
}

// protectClient は e の IP と User-Agent を切り詰め、tx が暗号化できれば全文を client に置く。
func protectClient(ctx context.Context, tx port.Tx, e *audit.Event) error {
	full := clientData{IP: e.IP, UA: e.UserAgent}
	e.IP, e.UserAgent, e.Client = audit.TruncateIP(full.IP), audit.ClassifyUA(full.UA), ""
	st, ok := tx.(sealingTx)
	if !ok || (full.IP == "" && full.UA == "") {
		return nil
	}
	var err error
	e.Client, err = st.c.seal(ctx, st.Tx, *e, full)
	return err
}

func (c *ClientSealer) retention() time.Duration {
	if c.Retention <= 0 {
		return DefaultClientRetention
	}
	return c.Retention
}

func keyOwner(realmID, day string) string { return realmID + ":" + day }

func (c *ClientSealer) seal(ctx context.Context, tx port.Tx, e audit.Event, full clientData) (string, error) {
	day := e.Time.UTC().Format(time.DateOnly)
	owner := keyOwner(e.RealmID, day)
	if _, err := tx.AuditKeys().Get(ctx, owner); errors.Is(err, errs.NotFound) {
		if err := c.Crypter.CreateDataKey(ctx, tx.AuditKeys(), owner, c.Clock.Now()); err != nil {
			return "", err
		}
		start, _ := time.Parse(time.DateOnly, day)
		if err := Schedule(ctx, tx, c.Clock, e.RealmID, "audit_client_key:"+owner, EventClientKeyExpired,
			start.Add(24*time.Hour+c.retention()), map[string]any{"day": day}); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	inner, err := json.Marshal(full)
	if err != nil {
		return "", err
	}
	layer := "n"
	if e.Actor.Type == "user" && e.Actor.ID != "" {
		u, err := tx.Users().GetByPublicID(ctx, e.RealmID, e.Actor.ID)
		switch {
		case errors.Is(err, errs.NotFound):
		case err != nil:
			return "", err
		default:
			inner, err = c.Crypter.Encrypt(ctx, tx.DataKeys(), u.ID, inner, clientAAD+"\x00"+e.ID)
			if errors.Is(err, pii.ErrShredded) {
				return "", nil // 削除したユーザーの全文は残さない
			}
			if err != nil {
				return "", err
			}
			layer = "u"
		}
	}
	outer, err := c.Crypter.Encrypt(ctx, tx.AuditKeys(), owner, inner, clientAAD+"\x00"+layer+"\x00"+e.ID)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{"v1", day, layer, base64.RawURLEncoding.EncodeToString(outer)}, "."), nil
}

// Open は e の IP と User-Agent の全文を返す（調査用）。保持期間の後、アカウントの削除の後は ErrClientUnreadable。
func (c *ClientSealer) Open(ctx context.Context, tx port.Tx, e audit.Event) (ip, userAgent string, err error) {
	parts := strings.Split(e.Client, ".")
	if len(parts) != 4 || parts[0] != "v1" || (parts[2] != "u" && parts[2] != "n") {
		return "", "", ErrClientUnreadable
	}
	day, layer := parts[1], parts[2]
	outer, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", "", ErrClientUnreadable
	}
	inner, err := c.Crypter.Decrypt(ctx, tx.AuditKeys(), keyOwner(e.RealmID, day), outer, clientAAD+"\x00"+layer+"\x00"+e.ID)
	if err != nil {
		return "", "", unreadable(err)
	}
	if layer == "u" {
		u, err := tx.Users().GetByPublicID(ctx, e.RealmID, e.Actor.ID)
		if err != nil {
			return "", "", unreadable(err)
		}
		if inner, err = c.Crypter.Decrypt(ctx, tx.DataKeys(), u.ID, inner, clientAAD+"\x00"+e.ID); err != nil {
			return "", "", unreadable(err)
		}
	}
	var full clientData
	if err := json.Unmarshal(inner, &full); err != nil {
		return "", "", err
	}
	return full.IP, full.UA, nil
}

func unreadable(err error) error {
	if errors.Is(err, pii.ErrShredded) || errors.Is(err, errs.NotFound) {
		return ErrClientUnreadable
	}
	return err
}

// Expire は保持期間の過ぎた日の鍵を消す（Scheduler の Handler）。
func (c *ClientSealer) Expire(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
	day, _ := details["day"].(string)
	if day == "" {
		return ErrSkip
	}
	return tx.AuditKeys().Delete(ctx, keyOwner(e.RealmID, day))
}
