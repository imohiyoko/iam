package provider_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

func TestBackchannel(t *testing.T) {
	k := testkit.New(t)
	b := &provider.Backchannel{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	ctx := context.Background()
	req := provider.BackchannelRequest{RealmID: k.RealmID, ClientID: "cli_cc", UserID: "u1", Scopes: []string{"openid"}, Mode: port.CIBAPoll,
		BindingMessage: "W4SCT"}

	st, err := b.Start(ctx, req)
	if err != nil || st.AuthReqID == "" || st.ExpiresIn != provider.DefaultCIBATTL || st.Interval != provider.DefaultCIBAInterval || st.Request.ID == "" {
		t.Fatalf("start = %+v, %v", st, err)
	}
	// poll の要求は auth_req_id を持たない（ping だけ）。
	if st.Request.AuthReqID != "" {
		t.Fatal("auth_req_id kept for the poll mode")
	}
	poll := func(client, id string) (provider.Code, error) {
		c, _, err := b.Poll(ctx, k.RealmID, client, id)
		return c, err
	}
	if _, err := poll("cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrDevicePending) {
		t.Fatalf("pending: %v", err)
	}
	if _, err := poll("cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrDeviceSlowDown) {
		t.Fatalf("slow down: %v", err)
	}
	for name, id := range map[string]string{"unknown": "x", "empty": "", "long": strings.Repeat("a", 300)} {
		if _, err := poll("cli_cc", id); !errors.Is(err, provider.ErrInvalidGrant) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := poll("cli_other", st.AuthReqID); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("other client: %v", err)
	}

	// 本人の一覧と取得。別人・別 realm には見えない。
	if rs, err := b.Pending(ctx, k.RealmID, "u1"); err != nil || len(rs) != 1 || rs[0].ID != st.Request.ID || rs[0].BindingMessage != "W4SCT" {
		t.Fatalf("pending = %+v, %v", rs, err)
	}
	if rs, _ := b.Pending(ctx, k.RealmID, "u2"); len(rs) != 0 {
		t.Fatalf("other user sees %+v", rs)
	}
	if _, err := b.Get(ctx, k.RealmID, "u2", st.Request.ID); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("get by other user: %v", err)
	}
	if _, err := b.Get(ctx, "other-realm", "u1", st.Request.ID); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("get in other realm: %v", err)
	}
	// 別人の承認は記録しない。判断は1回だけ。
	if _, err := b.Decide(ctx, k.RealmID, st.Request.ID, &provider.Code{UserID: "u2", SID: "s2"}); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("approve by another user: %v", err)
	}
	if _, err := b.Decide(ctx, k.RealmID, st.Request.ID, &provider.Code{UserID: "u1", SID: "s1", AMR: []string{"otp"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decide(ctx, k.RealmID, st.Request.ID, nil); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("decide twice: %v", err)
	}
	if rs, _ := b.Pending(ctx, k.RealmID, "u1"); len(rs) != 0 {
		t.Fatalf("decided request listed: %+v", rs)
	}
	k.Clock.Advance(10 * time.Second)
	c, err := poll("cli_cc", st.AuthReqID)
	if err != nil || c.UserID != "u1" || c.SID != "s1" || c.ClientID != "cli_cc" || c.GrantType != provider.GrantTypeCIBA || c.Scopes[0] != "openid" {
		t.Fatalf("approved = %+v, %v", c, err)
	}
	// トークンは1回だけ。
	k.Clock.Advance(10 * time.Second)
	if _, err := poll("cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("poll after tokens: %v", err)
	}

	// 拒否と期限切れ。requested_expiry は上限より短くするときだけ効く。
	st, _ = b.Start(ctx, req)
	_, _ = b.Decide(ctx, k.RealmID, st.Request.ID, nil)
	if _, err := poll("cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrDeviceDenied) {
		t.Fatalf("denied: %v", err)
	}
	short := req
	short.ExpiresAt = k.Clock.Now().Add(30 * time.Second)
	st, _ = b.Start(ctx, short)
	if st.ExpiresIn != 30*time.Second {
		t.Fatalf("requested expiry: %v", st.ExpiresIn)
	}
	long := req
	long.ExpiresAt = k.Clock.Now().Add(time.Hour)
	if st2, _ := b.Start(ctx, long); st2.ExpiresIn != provider.DefaultCIBATTL {
		t.Fatalf("long expiry: %v", st2.ExpiresIn)
	}
	k.Clock.Advance(31 * time.Second)
	if _, err := poll("cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrDeviceExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := b.Decide(ctx, k.RealmID, st.Request.ID, nil); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("decide after expiry: %v", err)
	}
}

func TestBackchannelChannelAndPing(t *testing.T) {
	k := testkit.New(t)
	b := &provider.Backchannel{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	ctx := context.Background()
	req := provider.BackchannelRequest{RealmID: k.RealmID, ClientID: "cli_cc", UserID: "u1", Scopes: []string{"openid"}, Mode: port.CIBAPing,
		NotificationToken: "tok"}
	st, err := b.Start(ctx, req)
	if err != nil || st.Request.AuthReqID != st.AuthReqID {
		t.Fatalf("start = %+v, %v", st, err)
	}
	if _, err := b.ByRef(ctx, k.RealmID, "push", "ref1"); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("unknown ref: %v", err)
	}
	if err := b.Attach(ctx, st.AuthReqID, provider.BackchannelChannel{Method: "push", Ref: "ref1", State: []byte("s")}); err != nil {
		t.Fatal(err)
	}
	r, err := b.ByRef(ctx, k.RealmID, "push", "ref1")
	if err != nil || r.ID != st.Request.ID || r.Channel == nil || string(r.Channel.State) != "s" || r.NotificationToken != "tok" {
		t.Fatalf("by ref = %+v, %v", r, err)
	}
	for name, f := range map[string]func() error{
		"other method": func() error { _, err := b.ByRef(ctx, k.RealmID, "sms", "ref1"); return err },
		"other realm":  func() error { _, err := b.ByRef(ctx, "other", "push", "ref1"); return err },
	} {
		if err := f(); !errors.Is(err, provider.ErrBackchannelRequest) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// 未決なら Retake も authorization_pending。判断の後は取り出せる。
	if _, err := b.Retake(ctx, k.RealmID, "cli_cc", st.AuthReqID); !errors.Is(err, provider.ErrDevicePending) {
		t.Fatalf("retake pending: %v", err)
	}
	_, _ = b.Decide(ctx, k.RealmID, st.Request.ID, &provider.Code{UserID: "u1", SID: "s1"})
	if _, err := b.ByRef(ctx, k.RealmID, "push", "ref1"); !errors.Is(err, provider.ErrBackchannelRequest) {
		t.Fatalf("decided by ref: %v", err)
	}
	if c, err := b.Retake(ctx, k.RealmID, "cli_cc", st.AuthReqID); err != nil || c.UserID != "u1" {
		t.Fatalf("retake = %+v, %v", c, err)
	}
}

// TestBackchannelSlots は、本人宛ての未決の要求が CIBASlots 件までで、期限切れ・判断済みの枠を使い直すことを確かめる。
func TestBackchannelSlots(t *testing.T) {
	k := testkit.New(t)
	b := &provider.Backchannel{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	ctx := context.Background()
	req := provider.BackchannelRequest{RealmID: k.RealmID, ClientID: "cli_cc", UserID: "u1", Scopes: []string{"openid"}, Mode: port.CIBAPoll}
	var first provider.BackchannelStart
	for i := range provider.CIBASlots {
		st, err := b.Start(ctx, req)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if i == 0 {
			first = st
		}
		k.Clock.Advance(time.Millisecond)
	}
	if _, err := b.Start(ctx, req); err == nil {
		t.Fatal("more pending requests than slots")
	} else if _, ok := errors.AsType[*ratelimit.ExceededError](err); !ok {
		t.Fatalf("full: %v", err)
	}
	// 別人の枠は別。
	other := req
	other.UserID = "u2"
	if _, err := b.Start(ctx, other); err != nil {
		t.Fatalf("other user: %v", err)
	}
	rs, _ := b.Pending(ctx, k.RealmID, "u1")
	if len(rs) != provider.CIBASlots || rs[0].CreatedAt.Before(rs[len(rs)-1].CreatedAt) {
		t.Fatalf("pending: %d", len(rs))
	}
	// 判断すれば枠が空く。
	_, _ = b.Decide(ctx, k.RealmID, first.Request.ID, nil)
	if _, err := b.Start(ctx, req); err != nil {
		t.Fatalf("after a decision: %v", err)
	}
	// 期限が過ぎれば全部空く。
	k.Clock.Advance(provider.DefaultCIBATTL)
	for range provider.CIBASlots {
		if _, err := b.Start(ctx, req); err != nil {
			t.Fatalf("after expiry: %v", err)
		}
	}
}

func TestBindingMessageAndNotificationToken(t *testing.T) {
	for _, s := range []string{"W4SCT", "注文 42", strings.Repeat("あ", provider.MaxBindingMessage)} {
		if !provider.ValidBindingMessage(s) {
			t.Fatalf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "a\nb", "a\x00", strings.Repeat("x", provider.MaxBindingMessage+1), "\xff"} {
		if provider.ValidBindingMessage(s) {
			t.Fatalf("%q accepted", s)
		}
	}
	for _, s := range []string{"abc", "a-b_c.d~e+f/g=", strings.Repeat("x", provider.MaxNotificationToken)} {
		if !provider.ValidNotificationToken(s) {
			t.Fatalf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "a b", "a\r\nX: y", "ä", strings.Repeat("x", provider.MaxNotificationToken+1)} {
		if provider.ValidNotificationToken(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

// FuzzBackchannelParams は、連携先から来る binding_message と client_notification_token の検査が、通したものに制御文字・
// ヘッダーを壊す文字を含まないことを確かめる。
func FuzzBackchannelParams(f *testing.F) {
	f.Add("W4SCT")
	f.Add("a\r\nb")
	f.Add("\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		if provider.ValidBindingMessage(s) {
			if !utf8.ValidString(s) || strings.ContainsAny(s, "\r\n\x00") || utf8.RuneCountInString(s) > provider.MaxBindingMessage {
				t.Fatalf("binding message %q accepted", s)
			}
		}
		if provider.ValidNotificationToken(s) && (strings.ContainsAny(s, " \r\n\t,\"") || len(s) > provider.MaxNotificationToken) {
			t.Fatalf("notification token %q accepted", s)
		}
	})
}
