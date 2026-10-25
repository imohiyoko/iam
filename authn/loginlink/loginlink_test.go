package loginlink_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/loginlink"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/errs"
)

func setup(t *testing.T) (*testkit.Kit, *loginlink.Service) {
	k := testkit.New(t)
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	return k, &loginlink.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Sessions: sm}
}

func TestRedeem(t *testing.T) {
	k, s := setup(t)
	u := k.SeedUser(t)
	ctx := context.Background()
	tok, err := loginlink.Issue(ctx, k.Crypter, k.RealmID, u.PublicID, k.Clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fail := func(name, realm, tok string) {
		t.Helper()
		if _, _, err := s.Redeem(ctx, realm, tok, loginlink.Client{}, ""); !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// 別の realm では使えず、使えなかった試行で消費もしない。
	fail("other realm", "rlm_other", tok)
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[len(raw)-1] ^= 1
	fail("tampered", k.RealmID, base64.RawURLEncoding.EncodeToString(raw))

	is, uid, err := s.Redeem(ctx, k.RealmID, tok, loginlink.Client{}, "")
	if err != nil || uid != u.PublicID || is.Session.PrincipalID != u.ID || is.Session.AuthMethods[0] != loginlink.AMR {
		t.Fatalf("redeem = %+v %q %v", is.Session, uid, err)
	}
	fail("reuse", k.RealmID, tok)

	tok2, _ := loginlink.Issue(ctx, k.Crypter, k.RealmID, u.PublicID, k.Clock.Now().Add(time.Minute))
	k.Clock.Advance(time.Minute)
	fail("expired", k.RealmID, tok2)
	tok3, _ := loginlink.Issue(ctx, k.Crypter, k.RealmID, "usr_unknown", k.Clock.Now().Add(time.Minute))
	fail("unknown user", k.RealmID, tok3)
}
