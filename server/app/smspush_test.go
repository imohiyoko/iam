package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method/push"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// SMS・音声の OTP とプッシュの承認（フィーチャー sms_otp・push_auth、ADR 0104）を HTTP で確かめる。

// smsOutbox はテスト用の SMSSender（送ったものを覚える）。
type smsOutbox struct {
	mu   sync.Mutex
	sent []port.SMSMessage
	fail bool
}

func (o *smsOutbox) Send(_ context.Context, m port.SMSMessage) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		return errors.New("provider down")
	}
	o.sent = append(o.sent, m)
	return nil
}

func (o *smsOutbox) last(t *testing.T) port.SMSMessage {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.sent) == 0 {
		t.Fatal("no sms sent")
	}
	return o.sent[len(o.sent)-1]
}

// pushOutbox はテスト用の PushSender。
type pushOutbox struct {
	mu   sync.Mutex
	sent []port.PushMessage
}

func (o *pushOutbox) Send(_ context.Context, m port.PushMessage) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sent = append(o.sent, m)
	return nil
}

func (o *pushOutbox) last(t *testing.T) port.PushMessage {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.sent) == 0 {
		t.Fatal("no push sent")
	}
	return o.sent[len(o.sent)-1]
}

func newSMSEnv(t *testing.T, edit func(*config.Config)) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &[]string{feature.Org, feature.Warnings, feature.SMSOTP}
		c.Security.Login.RateLimit.PerAccount, c.Security.Login.RateLimit.PerAccountTotal = 20, 20
		c.Methods = map[string]map[string]string{"sms": {"channels": "sms,voice", "allowed_country_codes": "81,1"}}
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

func (l *loginEnv) sms() *smsOutbox     { return l.e.deps.SMS.(*smsOutbox) }
func (l *loginEnv) pushes() *pushOutbox { return l.e.deps.Push.(*pushOutbox) }

func TestSMSSecondFactor(t *testing.T) {
	l := newSMSEnv(t, nil)
	_, full := l.login(t, "pat@example.com")
	// 形の誤った番号・許していない国番号は 400。
	for _, n := range []string{"090-1234-5678", "+0123456789", "+44 7700 900123"} {
		if status, res := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": n}}); status != 400 || res["error"] != "invalid_phone_number" {
			t.Fatalf("enroll %q: %d %v", n, status, res)
		}
	}
	status, st := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+81 90-1234-5678"}})
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	p := st["payload"].(map[string]any)
	if p["phone"] != "+**********78" || p["restricted"] != true || p["channel"] != "sms" {
		t.Fatalf("enroll payload: %v", p)
	}
	msg := l.sms().last(t)
	if msg.To != "+819012345678" || msg.Channel != "sms" || len(msg.Code) != 6 {
		t.Fatalf("sent: %+v", msg)
	}
	// 違うコードは通らない。
	if status, _, _ := l.post(t, full, "/v1/me/credentials/sms:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": "000000"}}); status != 401 && msg.Code != "000000" {
		t.Fatalf("wrong code: %d", status)
	}
	status, res, _ := l.post(t, full, "/v1/me/credentials/sms:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": msg.Code}})
	if status != 200 || res["recovery_codes"] == nil {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	credID := res["credential"].(map[string]any)["id"].(string)
	// 番号は暗号化して置く。
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Credentials().GetByPublicID(ctx, l.a.realm.ID, credID)
		if err == nil && bytes.Contains(c.Data, []byte("819012345678")) {
			t.Fatal("phone number stored in plaintext")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// 同じ番号は 2 度登録できない。
	l.advance(time.Minute)
	if status, res := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+819012345678"}}); status != 409 {
		t.Fatalf("duplicate number: %d %v", status, res)
	}

	login, restricted := l.login(t, "pat@example.com")
	if login["next"] != "second_factor" || !slices.Contains(login["second_factor_methods"].([]any), any("sms")) {
		t.Fatalf("login: %v", login)
	}
	status, first := l.mePost(t, restricted, "/v1/login/second-factor/sms:begin", nil)
	if status != 200 {
		t.Fatalf("begin: %d %v", status, first)
	}
	firstCode := l.sms().last(t).Code
	// 送り直しの間隔より早ければ 429。
	if status, _ := l.mePost(t, restricted, "/v1/login/second-factor/sms:begin", nil); status != 429 {
		t.Fatalf("resend too early: %d", status)
	}
	l.advance(31 * time.Second)
	status, second := l.mePost(t, restricted, "/v1/login/second-factor/sms:begin", map[string]any{"payload": map[string]any{"channel": "voice", "credential_id": credID}})
	if status != 200 {
		t.Fatalf("resend: %d %v", status, second)
	}
	voice := l.sms().last(t)
	if voice.Channel != "voice" {
		t.Fatalf("voice: %+v", voice)
	}
	// 送り直すと前のコードは通らない（正しいコードでも）。
	if firstCode != voice.Code {
		if status, _, _ := l.post(t, restricted, "/v1/login/second-factor/sms:complete", map[string]any{"flow_id": first["flow_id"], "payload": map[string]any{"code": firstCode}}); status != 401 {
			t.Fatalf("superseded code: %d", status)
		}
	}
	status, res, upgraded := l.post(t, restricted, "/v1/login/second-factor/sms:complete", map[string]any{"flow_id": second["flow_id"], "payload": map[string]any{"code": voice.Code}})
	if status != 200 || upgraded == "" {
		t.Fatalf("complete: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "tel", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	// 使ったコードは2度通らない。
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor/sms:complete", map[string]any{"flow_id": second["flow_id"], "payload": map[string]any{"code": voice.Code}}); status != 401 {
		t.Fatalf("reused code: %d", status)
	}
	if len(l.auditOf(t, "method.sms.code_sent")) != 3 {
		t.Fatalf("code_sent events: %v", l.auditOf(t, "method.sms.code_sent"))
	}
	// コードの期限の後は通らない。
	l.advance(time.Minute)
	_, again := l.login(t, "pat@example.com")
	_, st = l.mePost(t, again, "/v1/login/second-factor/sms:begin", nil)
	code := l.sms().last(t).Code
	l.advance(6 * time.Minute)
	if status, _, _ := l.post(t, again, "/v1/login/second-factor/sms:complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": code}}); status != 401 {
		t.Fatalf("expired code: %d", status)
	}
}

func TestSMSDeliveryFailureAndLimits(t *testing.T) {
	l := newSMSEnv(t, func(c *config.Config) {
		c.Methods["sms"]["per_user"] = "2"
	})
	_, full := l.login(t, "pat@example.com")
	l.sms().fail = true
	if status, res := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}}); status != 503 || res["error"] != "delivery_failed" {
		t.Fatalf("delivery failure: %d %v", status, res)
	}
	if len(l.auditOf(t, "method.delivery_failed")) != 1 {
		t.Fatal("delivery failure not audited")
	}
	l.sms().fail = false
	l.advance(time.Minute)
	if status, _ := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}}); status != 200 {
		t.Fatalf("second send: %d", status)
	}
	// ユーザーごとの送信の上限（per_user 2）。
	l.advance(time.Minute)
	if status, _ := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}}); status != 429 {
		t.Fatalf("per user limit: %d", status)
	}
}

func TestSMSDisabledByRealmAndDefault(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.login(t, "pat@example.com")
	if status, _ := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", nil); status != 404 {
		t.Fatalf("sms without the feature: %d", status)
	}
	l = newSMSEnv(t, func(c *config.Config) { c.Realm.DisabledMethods = []string{"sms"} })
	_, full = l.login(t, "pat@example.com")
	if status, _ := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}}); status != 404 {
		t.Fatalf("sms disabled by the realm: %d", status)
	}
}

func TestSMSPushNeedSenders(t *testing.T) {
	for _, f := range []string{feature.SMSOTP, feature.PushAuth} {
		e := newEnv(t)
		e.cfg.Features = &[]string{feature.Org, feature.Warnings, f}
		e.deps.SMS, e.deps.Push = nil, nil
		if _, err := New(context.Background(), e.cfg, e.deps, feature.Registered()); err == nil {
			t.Fatalf("%s started without a sender", f)
		}
	}
	e := newEnv(t)
	e.cfg.Features = &[]string{feature.Org, feature.Warnings, feature.SMSOTP}
	e.cfg.Methods = map[string]map[string]string{"sms": {"nosuch": "1"}}
	if _, err := New(context.Background(), e.cfg, e.deps, feature.Registered()); err == nil {
		t.Fatal("unknown method option accepted")
	}
}

func TestDisableSMSAndPushWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	_, st := l.mePost(t, cookie, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}})
	if status, res, _ := l.post(t, cookie, "/v1/me/credentials/sms:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": l.sms().last(t).Code}}); status != 200 {
		t.Fatalf("enroll sms: %d %v", status, res)
	}
	disableWithData(t, l, feature.SMSOTP, 1)
	l = allFeaturesEnv(t)
	_, cookie = l.login(t, "pat@example.com")
	d := newDevice(t)
	if status, res := d.enroll(t, l, cookie); status != 200 {
		t.Fatalf("enroll push: %d %v", status, res)
	}
	disableWithData(t, l, feature.PushAuth, 1)
}

// device はテスト用の端末（P-256 の鍵）。
type device struct {
	key *ecdsa.PrivateKey
	pub string
	id  string
}

func newDevice(t *testing.T) *device {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &device{key: k, pub: base64.RawURLEncoding.EncodeToString(der)}
}

func (d *device) sign(t *testing.T, kind string, fields ...string) string {
	t.Helper()
	msg, ok := push.Message(kind, fields...)
	if !ok {
		t.Fatalf("message fields: %v", fields)
	}
	h := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (d *device) enroll(t *testing.T, l *loginEnv, cookie string) (int, map[string]any) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/me/credentials/push:enroll-begin", nil)
	if status != 200 {
		return status, st
	}
	nonce := st["payload"].(map[string]any)["challenge"].(string)
	token := "fcm-token-1"
	status, res, _ := l.post(t, cookie, "/v1/me/credentials/push:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{
		"public_key": d.pub, "push_token": token, "platform": "fcm", "name": "Pixel",
		"signature": d.sign(t, "enroll", nonce, d.pub, push.TokenHash(token)),
	}})
	if status == 200 {
		d.id = res["payload"].(map[string]any)["device_id"].(string)
	}
	return status, res
}

func (d *device) respond(t *testing.T, l *loginEnv, challengeID, decision, number string) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/methods/push:callback", map[string]any{"payload": map[string]any{
		"action": "respond", "device_id": d.id, "challenge_id": challengeID, "decision": decision, "number": number,
		"signature": d.sign(t, "respond", challengeID, d.id, decision, number),
	}})
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func newPushEnv(t *testing.T, edit func(*config.Config)) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &[]string{feature.Org, feature.Warnings, feature.PushAuth}
		c.Methods = map[string]map[string]string{"push": {"per_user": "20"}}
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

func TestPushSecondFactor(t *testing.T) {
	l := newPushEnv(t, nil)
	_, full := l.login(t, "pat@example.com")
	d := newDevice(t)
	// 署名が登録の値に合わなければ登録できない。
	status, st := l.mePost(t, full, "/v1/me/credentials/push:enroll-begin", nil)
	if status != 200 {
		t.Fatalf("enroll-begin: %d", status)
	}
	if status, _, _ := l.post(t, full, "/v1/me/credentials/push:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{
		"public_key": d.pub, "push_token": "t", "signature": d.sign(t, "enroll", "other", d.pub, push.TokenHash("t")),
	}}); status != 401 {
		t.Fatalf("bad enrollment signature: %d", status)
	}
	if status, res := d.enroll(t, l, full); status != 200 {
		t.Fatalf("enroll: %d %v", status, res)
	}

	login, restricted := l.login(t, "pat@example.com")
	if !slices.Contains(login["second_factor_methods"].([]any), any("push")) {
		t.Fatalf("login: %v", login)
	}
	begin := func() (string, string, string) {
		status, ch := l.mePost(t, restricted, "/v1/login/second-factor/push:begin", nil)
		if status != 200 {
			t.Fatalf("begin: %d %v", status, ch)
		}
		m := l.pushes().last(t)
		if m.DeviceID != d.id || m.Token != "fcm-token-1" {
			t.Fatalf("push: %+v", m)
		}
		return ch["flow_id"].(string), m.ChallengeID, ch["payload"].(map[string]any)["number"].(string)
	}
	complete := func(flowID string) (int, map[string]any, string) {
		return l.post(t, restricted, "/v1/login/second-factor/push:complete", map[string]any{"flow_id": flowID})
	}

	// 応答の前は 202。何度呼んでも回数に数えない。
	flowID, chID, number := begin()
	for range 8 {
		if status, res, _ := complete(flowID); status != 202 || res["status"] != "pending" {
			t.Fatalf("pending: %d %v", status, res)
		}
	}
	// 署名が違う・別の端末の応答は受けない。
	other := newDevice(t)
	other.id = d.id
	if status, _ := other.respond(t, l, chID, "approve", number); status != 401 {
		t.Fatalf("forged response: %d", status)
	}
	// 番号が違えば拒否として扱う。
	wrong := "10"
	if number == wrong {
		wrong = "11"
	}
	if status, res := d.respond(t, l, chID, "approve", wrong); status != 200 || res["payload"].(map[string]any)["result"] != "denied" {
		t.Fatalf("number mismatch: %d %v", status, res)
	}
	// 応答は1回だけ。
	if status, _ := d.respond(t, l, chID, "approve", number); status != 401 {
		t.Fatalf("second response: %d", status)
	}
	if status, _, _ := complete(flowID); status != 401 {
		t.Fatalf("complete after mismatch: %d", status)
	}

	flowID, chID, number = begin()
	if status, _ := d.respond(t, l, chID, "approve", number); status != 200 {
		t.Fatalf("approve: %d", status)
	}
	status, res, upgraded := complete(flowID)
	if status != 200 || upgraded == "" {
		t.Fatalf("complete: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "swk", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	if len(l.auditOf(t, "method.push.approved")) != 1 || len(l.auditOf(t, "method.push.denied")) != 1 || len(l.auditOf(t, "method.push.challenge_sent")) != 2 {
		t.Fatal("push events not audited")
	}

	// 期限の後は失敗。
	_, restricted = l.login(t, "pat@example.com")
	flowID, _, _ = begin()
	l.advance(3 * time.Minute)
	if status, _, _ := complete(flowID); status != 401 {
		t.Fatalf("expired challenge: %d", status)
	}

	// 宛先の更新（時刻は前より新しく、今から 5 分以内）。
	update := func(token string, ts int64) int {
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/methods/push:callback", map[string]any{"payload": map[string]any{
			"action": "token", "device_id": d.id, "push_token": token, "timestamp": ts,
			"signature": d.sign(t, "token", d.id, push.TokenHash(token), strconv.FormatInt(ts, 10)),
		}})
		return w.Code
	}
	now := l.e.deps.Clock.Now().Unix()
	if status := update("fcm-token-2", now-int64(time.Hour/time.Second)); status != 401 {
		t.Fatalf("stale token update: %d", status)
	}
	if status := update("fcm-token-2", now); status != 200 {
		t.Fatalf("token update: %d", status)
	}
	if status := update("fcm-token-3", now); status != 401 {
		t.Fatalf("replayed timestamp: %d", status)
	}
	_, restricted = l.login(t, "pat@example.com")
	begin2, _ := l.mePost(t, restricted, "/v1/login/second-factor/push:begin", nil)
	if begin2 != 200 || l.pushes().last(t).Token != "fcm-token-2" {
		t.Fatalf("token not updated: %+v", l.pushes().last(t))
	}
	// 知らない操作・方式は 400 / 404。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/methods/push:callback", map[string]any{"payload": map[string]any{"action": "x", "device_id": d.id}}); w.Code != 400 {
		t.Fatalf("unknown action: %d", w.Code)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/methods/hotp:callback", map[string]any{"payload": map[string]any{}}); w.Code != 404 {
		t.Fatalf("unknown method: %d", w.Code)
	}
}

func TestPushFatigueLockout(t *testing.T) {
	l := newPushEnv(t, func(c *config.Config) { c.Methods["push"]["deny_limit"] = "2" })
	_, full := l.login(t, "pat@example.com")
	d := newDevice(t)
	if status, _ := d.enroll(t, l, full); status != 200 {
		t.Fatal("enroll")
	}
	_, restricted := l.login(t, "pat@example.com")
	for range 2 {
		status, _ := l.mePost(t, restricted, "/v1/login/second-factor/push:begin", nil)
		if status != 200 {
			t.Fatalf("begin: %d", status)
		}
		if status, _ := d.respond(t, l, l.pushes().last(t).ChallengeID, "deny", "00"); status != 200 {
			t.Fatalf("deny: %d", status)
		}
	}
	// 拒否が続いたら、しばらくチャレンジを送らない。
	if status, _ := l.mePost(t, restricted, "/v1/login/second-factor/push:begin", nil); status != 429 {
		t.Fatalf("after denies: %d", status)
	}
	l.advance(31 * time.Minute)
	_, restricted = l.login(t, "pat@example.com")
	if status, _ := l.mePost(t, restricted, "/v1/login/second-factor/push:begin", nil); status != 200 {
		t.Fatalf("after the deny window: %d", status)
	}
}

// Org のログインポリシーの deny_restricted_authenticators：SMS・音声の OTP で入った認証はその Org に入れない（ADR 0104）。
func TestOrgPolicyDeniesRestrictedAuthenticators(t *testing.T) {
	l := newSMSEnv(t, func(c *config.Config) {
		*c.Features = append(*c.Features, feature.OrgLoginPolicy)
	})
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	_, full := l.login(t, "pat@acme.example")
	_, st := l.mePost(t, full, "/v1/me/credentials/sms:enroll-begin", map[string]any{"payload": map[string]any{"phone_number": "+15555550100"}})
	if status, res, _ := l.post(t, full, "/v1/me/credentials/sms:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": l.sms().last(t).Code}}); status != 200 {
		t.Fatalf("enroll: %d %v", status, res)
	}
	code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"deny_restricted_authenticators": true}})
	if code != 200 || out["settings"].(map[string]any)["login_policy"].(map[string]any)["deny_restricted_authenticators"] != true {
		t.Fatalf("put policy: %d %v", code, out)
	}
	l.advance(time.Minute)
	_, restricted := l.login(t, "pat@acme.example")
	_, ch := l.mePost(t, restricted, "/v1/login/second-factor/sms:begin", nil)
	status, res, weak := l.post(t, restricted, "/v1/login/second-factor/sms:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"code": l.sms().last(t).Code}})
	if status != 200 || res["org_id"] == acme {
		t.Fatalf("second factor: %d %v", status, res)
	}
	if code, body, _ := l.post(t, weak, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.restricted_authenticator" {
		t.Fatalf("switch with sms: %d %v", code, body)
	}
}
