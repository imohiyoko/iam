package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 保持期間とメールの最小化モード（design.md 6.5、9.6、ADR 0072）を確かめる。

func indexOnly(c *config.Config) { c.Realm.EmailStorage = "index_only" }

func (l *loginEnv) meGet(t *testing.T, cookie, path string) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", path, nil, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (l *loginEnv) emailsOf(t *testing.T, userPublicID string) []port.UserEmail {
	t.Helper()
	var es []port.UserEmail
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, userPublicID)
		if err != nil {
			return err
		}
		es, err = tx.Emails().ListByUser(ctx, l.a.realm.ID, u.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// index_only ではアドレスの暗号文を持たない。インデックスでログインでき、アドレスは表示しない。
func TestEmailIndexOnly(t *testing.T) {
	l := newLoginEnvWith(t, indexOnly, nil)
	first, _ := l.login(t, "ix@example.com")
	uid := first["user_id"].(string)
	es := l.emailsOf(t, uid)
	if len(es) != 1 || len(es[0].Ciphertext) != 0 || len(es[0].Index) == 0 {
		t.Fatalf("emails = %+v", es)
	}
	second, cookie := l.login(t, "IX@example.com")
	if second["created"] != false || second["user_id"] != uid {
		t.Fatalf("second login = %v", second)
	}
	status, out := l.meGet(t, cookie, "/v1/me/methods")
	if status != 200 {
		t.Fatalf("methods: %d %v", status, out)
	}
	if ms := out["emails"].([]any); len(ms) != 1 || ms[0].(map[string]any)["email"] != "" {
		t.Fatalf("emails in methods = %v", out["emails"])
	}
}

// 操作起点でない通知（復旧の完了）は、宛先なしで出す（外部が user_id から宛先を解決する）。
func TestIndexOnlyRecoveredNotificationHasNoAddress(t *testing.T) {
	l := newRecoveryEnv(t, indexOnly)
	_, cookie := l.login(t, "pat@example.com")
	if _, status, _, _ := l.enrollTOTP(t, cookie); status != 200 {
		t.Fatal("totp")
	}
	_, st := l.mePost(t, "", "/v1/recovery/email:start", map[string]string{"email": "pat@example.com"})
	code := l.claimLast(t)
	status, out, rec := l.post(t, "", "/v1/recovery/email:verify", map[string]string{"flow_id": st["flow_id"].(string), "code": code})
	if status != 200 || out["next"] != "recovery" {
		t.Fatalf("verify: %d %v", status, out)
	}
	l.advance(time.Second)
	if status, _ := l.registerPasskey(t, rec, passkeytest.New(passkeyOrigin), "Key"); status != 200 {
		t.Fatal("register in recovery")
	}
	before := l.notes.count()
	if status, out := l.mePost(t, rec, "/v1/recovery:complete", nil); status != 200 {
		t.Fatalf("complete: %d %v", status, out)
	}
	if _, err := l.a.notifier.Flush(context.Background()); err != nil || l.notes.count() != before+1 {
		t.Fatalf("recovered notification: %v %d", err, l.notes.count()-before)
	}
	if n := l.notes.last(t); n.Type != notify.TypeAccountRecovered || n.HasSecret || n.UserID == "" {
		t.Fatalf("recovered notification = %+v", n)
	}
}

// encrypted から index_only に切り替えると、掃除で残っている暗号文を消す。
func TestRetentionClearsAddressesAfterSwitch(t *testing.T) {
	l := newLoginEnv(t)
	first, cookie := l.login(t, "sw@example.com")
	uid := first["user_id"].(string)
	if es := l.emailsOf(t, uid); len(es[0].Ciphertext) == 0 {
		t.Fatal("encrypted mode stores the address")
	}
	l.a.retention.IndexOnlyRealms = []string{l.a.realm.ID}
	n, err := l.a.retention.Sweep(context.Background())
	if err != nil || n.Emails != 1 {
		t.Fatalf("Sweep = %+v, %v", n, err)
	}
	if es := l.emailsOf(t, uid); len(es[0].Ciphertext) != 0 {
		t.Fatal("address left after the sweep")
	}
	if status, out := l.meGet(t, cookie, "/v1/me/methods"); status != 200 {
		t.Fatalf("methods after the sweep: %d %v", status, out)
	}
}

// 失効したセッションは保持期間の後に消え、監査ログは切り詰めてもチェーンを検証でき、チェックポイントを SIEM に送る。
func TestRetentionSweep(t *testing.T) {
	l := newLoginEnv(t)
	ctx := context.Background()
	_, cookie := l.login(t, "old@example.com")
	if status, out := l.mePost(t, cookie, "/v1/logout", nil); status/100 != 2 {
		t.Fatalf("logout: %d %v", status, out)
	}
	l.advance(l.e.cfg.Realm.EndedRetention.D() + time.Hour)
	n, err := l.a.retention.Sweep(ctx)
	if err != nil || n.Sessions < 1 || n.Audit != 0 {
		t.Fatalf("Sweep = %+v, %v", n, err)
	}
	l.advance(l.e.cfg.Realm.AuditRetention.D())
	l.login(t, "new@example.com")
	if n, err = l.a.retention.Sweep(ctx); err != nil || n.Audit == 0 {
		t.Fatalf("Sweep after audit retention = %+v, %v", n, err)
	}
	if _, _, err := eventlog.Verify(ctx, l.a.deps.Storage); err != nil {
		t.Fatal(err)
	}
	// 新しいログインの記録は残り、古いものは消える。
	var types []string
	err = l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Scan(ctx, 1, 1000)
		for _, r := range rs {
			e, err := audit.Unmarshal(r.Payload)
			if err != nil {
				return err
			}
			if e.Time.Before(l.a.deps.Clock.Now().Add(-l.e.cfg.Realm.AuditRetention.D())) {
				t.Errorf("old event kept: %s %s", e.Type, e.Time)
			}
			types = append(types, e.Type)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if types[len(types)-1] != eventlog.EventAuditTruncated {
		t.Fatalf("events = %v", types)
	}
	if _, err := l.a.relay.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if out := l.e.out.String(); !strings.Contains(out, `"type":"audit.truncated"`) || !strings.Contains(out, `"through_seq"`) {
		t.Fatalf("checkpoint not sent to the sink: %s", out)
	}
}
