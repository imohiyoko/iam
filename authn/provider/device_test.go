package provider_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
)

func TestUserCodeFormat(t *testing.T) {
	for in, want := range map[string]string{"bcdf-ghjk": "BCDFGHJK", " BCDF GHJK ": "BCDFGHJK", "BCDFGHJK": "BCDFGHJK"} {
		if got, ok := provider.NormalizeUserCode(in); !ok || got != want {
			t.Fatalf("%q = %q, %v", in, got, ok)
		}
	}
	// 母音・数字・長さの違い・非 ASCII は受けない。
	for _, in := range []string{"", "BCDF-GHJA", "BCDF-GHJ1", "BCDF-GHJ", "BCDF-GHJKL", "ＢCDF-GHJK", strings.Repeat("-", 100) + "BCDFGHJK"} {
		if _, ok := provider.NormalizeUserCode(in); ok {
			t.Fatalf("%q accepted", in)
		}
	}
	if got := provider.FormatUserCode("BCDFGHJK"); got != "BCDF-GHJK" {
		t.Fatal(got)
	}
}

func TestDeviceFlow(t *testing.T) {
	k := testkit.New(t)
	d := &provider.Device{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	ctx := context.Background()
	req := provider.DeviceRequest{RealmID: k.RealmID, ClientID: "cli_tv", Scopes: []string{"openid"}}

	st, err := d.Start(ctx, req)
	if err != nil || st.DeviceCode == "" || st.ExpiresIn != provider.DefaultDeviceTTL || st.Interval != provider.DefaultDeviceInterval {
		t.Fatalf("start = %+v, %v", st, err)
	}
	if code, ok := provider.NormalizeUserCode(st.UserCode); !ok || provider.FormatUserCode(code) != st.UserCode {
		t.Fatalf("user code %q", st.UserCode)
	}
	// 毎回違う値を作る。
	if st2, _ := d.Start(ctx, req); st2.DeviceCode == st.DeviceCode || st2.UserCode == st.UserCode {
		t.Fatal("codes repeat")
	}

	poll := func() (provider.Code, error) { return d.Poll(ctx, k.RealmID, "cli_tv", st.DeviceCode) }
	if _, err := poll(); !errors.Is(err, provider.ErrDevicePending) {
		t.Fatalf("first poll: %v", err)
	}
	// 間隔より速ければ slow_down で、間隔を 5 秒ずつ延ばす。
	k.Clock.Advance(time.Second)
	if _, err := poll(); !errors.Is(err, provider.ErrDeviceSlowDown) {
		t.Fatalf("fast poll: %v", err)
	}
	k.Clock.Advance(provider.DefaultDeviceInterval + time.Second)
	if _, err := poll(); !errors.Is(err, provider.ErrDeviceSlowDown) {
		t.Fatalf("still too fast for the longer interval: %v", err)
	}
	k.Clock.Advance(3 * provider.DefaultDeviceInterval)
	if _, err := poll(); !errors.Is(err, provider.ErrDevicePending) {
		t.Fatalf("paced poll: %v", err)
	}
	// 知らない・別の連携先・別の realm の device_code は invalid_grant。
	for name, try := range map[string]func() error{
		"unknown":      func() error { _, err := d.Poll(ctx, k.RealmID, "cli_tv", "nope"); return err },
		"empty":        func() error { _, err := d.Poll(ctx, k.RealmID, "cli_tv", ""); return err },
		"other client": func() error { _, err := d.Poll(ctx, k.RealmID, "cli_other", st.DeviceCode); return err },
		"other realm":  func() error { _, err := d.Poll(ctx, "rlm_other", "cli_tv", st.DeviceCode); return err },
	} {
		if err := try(); !errors.Is(err, provider.ErrInvalidGrant) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// user_code で要求を読み、承認する。user_code は1回だけ使える。
	if got, err := d.Lookup(ctx, k.RealmID, strings.ToLower(st.UserCode)); err != nil || got.ClientID != "cli_tv" {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	if _, err := d.Lookup(ctx, "rlm_other", st.UserCode); !errors.Is(err, provider.ErrUserCode) {
		t.Fatalf("lookup other realm: %v", err)
	}
	if _, err := d.Lookup(ctx, k.RealmID, "BCDF-GHJA"); !errors.Is(err, provider.ErrUserCode) {
		t.Fatalf("lookup malformed: %v", err)
	}
	approved := &provider.Code{UserID: "usr_1", SID: "ses_1", AuthTime: k.Clock.Now(), AMR: []string{"email"},
		// 連携先とスコープは端末の要求のものにする（渡した値は使わない）。
		AuthRequest: provider.AuthRequest{ClientID: "cli_evil", Scopes: []string{"openid", "email"}}}
	if _, err := d.Decide(ctx, k.RealmID, st.UserCode, approved); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decide(ctx, k.RealmID, st.UserCode, nil); !errors.Is(err, provider.ErrUserCode) {
		t.Fatalf("decide twice: %v", err)
	}
	k.Clock.Advance(time.Minute)
	c, err := poll()
	if err != nil || c.UserID != "usr_1" || c.SID != "ses_1" || c.ClientID != "cli_tv" || c.RealmID != k.RealmID || len(c.Scopes) != 1 ||
		c.GrantType != provider.GrantTypeDeviceCode {
		t.Fatalf("approved poll = %+v, %v", c, err)
	}
	// 1回だけ返す。
	k.Clock.Advance(time.Minute)
	if _, err := poll(); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("poll after tokens: %v", err)
	}

	// 拒否。
	st, _ = d.Start(ctx, req)
	if _, err := d.Decide(ctx, k.RealmID, st.UserCode, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Poll(ctx, k.RealmID, "cli_tv", st.DeviceCode); !errors.Is(err, provider.ErrDeviceDenied) {
		t.Fatalf("denied: %v", err)
	}
	if _, err := d.Poll(ctx, k.RealmID, "cli_tv", st.DeviceCode); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("after denied: %v", err)
	}

	// 期限。期限の後のポーリングは expired_token で、user_code はもう使えない。
	st, _ = d.Start(ctx, req)
	k.Clock.Advance(provider.DefaultDeviceTTL)
	if _, err := d.Poll(ctx, k.RealmID, "cli_tv", st.DeviceCode); !errors.Is(err, provider.ErrDeviceExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := d.Decide(ctx, k.RealmID, st.UserCode, approved); !errors.Is(err, provider.ErrUserCode) {
		t.Fatalf("decide after expiry: %v", err)
	}
	// 承認の後でも、期限を過ぎてからのポーリングにはトークンを出さない。
	st, _ = d.Start(ctx, req)
	if _, err := d.Decide(ctx, k.RealmID, st.UserCode, approved); err != nil {
		t.Fatal(err)
	}
	k.Clock.Advance(provider.DefaultDeviceTTL)
	if _, err := d.Poll(ctx, k.RealmID, "cli_tv", st.DeviceCode); !errors.Is(err, provider.ErrDeviceExpired) {
		t.Fatalf("approved but expired: %v", err)
	}
}
