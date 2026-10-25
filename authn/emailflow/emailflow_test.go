package emailflow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type env struct {
	k     *testkit.Kit
	svc   *emailflow.Service
	notif *notify.Service
}

var allVia = []port.VerifiedVia{port.VerifiedViaCode, port.VerifiedViaOAuthProvider, port.VerifiedViaAdmin}

func setup(t *testing.T, via ...port.VerifiedVia) *env {
	t.Helper()
	if via == nil {
		via = allVia
	}
	k := testkit.New(t)
	n := &notify.Service{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	sm := &session.Manager{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Config: session.Config{AbsoluteLifetime: 24 * time.Hour, ValidityMaxDelay: 30 * time.Second, RotationGrace: time.Minute}}
	svc := &emailflow.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock,
		Accounts: &account.Service{Crypter: k.Crypter, Clock: k.Clock, VerifiedVia: via}, Sessions: sm, Notify: n}
	return &env{k: k, svc: svc, notif: n}
}

// notifications は outbox の通知を返す。
func (e *env) notifications(t *testing.T) []port.Notification {
	t.Helper()
	var out []port.Notification
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		ms, err := tx.Outbox().Pending(ctx, notify.Topic, 1000)
		for _, m := range ms {
			var n port.Notification
			if err := json.Unmarshal(m.Payload, &n); err != nil {
				return err
			}
			out = append(out, n)
		}
		return err
	})
	return out
}

func (e *env) start(t *testing.T, email string) (emailflow.Started, port.Notification, notify.Secret) {
	t.Helper()
	before := len(e.notifications(t))
	st, err := e.svc.Start(context.Background(), e.k.RealmID, email, emailflow.Client{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	ns := e.notifications(t)
	if len(ns) != before+1 {
		t.Fatalf("want one new notification, got %d", len(ns)-before)
	}
	n := ns[len(ns)-1]
	sec, err := e.notif.Claim(context.Background(), e.k.RealmID, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	return st, n, sec
}

func TestSignupWithCode(t *testing.T) {
	e := setup(t)
	st, n, sec := e.start(t, "Alice@Example.com")
	if n.Type != notify.TypeEmailVerification || n.UserID != "" || !n.HasSecret {
		t.Fatalf("notification = %+v", n)
	}
	if sec.To != "alice@example.com" || len(sec.Code) != 6 || sec.Token == "" {
		t.Fatalf("secret = %+v", sec)
	}
	v, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Created || v.Session.Token == "" {
		t.Fatalf("verified = %+v", v)
	}
	// 不変条件：全ユーザーが確認済みのメールを1つ以上持つ（13.5）。
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		es, err := tx.Emails().ListByUser(ctx, e.k.RealmID, v.Session.Session.PrincipalID)
		if err != nil || len(es) != 1 || es[0].VerifiedAt == nil || es[0].VerifiedVia != port.VerifiedViaCode || !es[0].IsPrimary {
			t.Fatalf("emails = %+v, %v", es, err)
		}
		return nil
	})
	if _, err := e.svc.Sessions.Validate(context.Background(), e.k.RealmID, v.Session.Token); err != nil {
		t.Fatal(err)
	}
}

func TestLoginWithLink(t *testing.T) {
	e := setup(t)
	st, _, sec := e.start(t, "bob@example.com")
	first, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code})
	if err != nil {
		t.Fatal(err)
	}
	st, n, sec := e.start(t, "BOB@example.com")
	if n.Type != notify.TypeMagicLink || n.UserID != first.UserID {
		t.Fatalf("login notification = %+v", n)
	}
	v, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, LinkToken: sec.Token})
	if err != nil {
		t.Fatal(err)
	}
	if v.Created || v.UserID != first.UserID {
		t.Fatalf("login = %+v", v)
	}
}

// 不変条件：本人確認の前は、アカウントの有無で応答が変わらない（4.9、13.5）。
func TestStartDoesNotRevealAccount(t *testing.T) {
	e := setup(t)
	st, _, sec := e.start(t, "carol@example.com")
	if _, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code}); err != nil {
		t.Fatal(err)
	}
	known, _, _ := e.start(t, "carol@example.com")
	unknown, _, _ := e.start(t, "dave@example.com")
	if len(known.FlowID) != len(unknown.FlowID) || !known.ExpiresAt.Equal(unknown.ExpiresAt) {
		t.Fatalf("responses differ: %+v vs %+v", known, unknown)
	}
}

// 不変条件：メールのコード・リンクは要求したフローの外で通らない（4.1、13.5）。
func TestCodeOnlyWorksInItsFlow(t *testing.T) {
	e := setup(t)
	a, _, secA := e.start(t, "erin@example.com")
	b, _, secB := e.start(t, "frank@example.com")
	ctx := context.Background()
	for _, in := range []emailflow.Verify{
		{FlowID: b.FlowID, Code: secA.Code},
		{FlowID: b.FlowID, LinkToken: secA.Token},
		{FlowID: "not-a-flow", Code: secA.Code},
		{Code: secA.Code},
		{FlowID: a.FlowID},
		{FlowID: a.FlowID, Code: secA.Code, LinkToken: secA.Token},
	} {
		if _, err := e.svc.Verify(ctx, e.k.RealmID, in); !errors.Is(err, emailflow.ErrAuthFailed) || !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("%+v: want authentication_failed, got %v", in, err)
		}
	}
	if secA.Code == secB.Code {
		t.Skip("codes collided (1 in a million)")
	}
	// 別の realm でも通らない。
	if _, err := e.svc.Verify(ctx, "rlm_other", emailflow.Verify{FlowID: a.FlowID, Code: secA.Code}); !errors.Is(err, emailflow.ErrAuthFailed) {
		t.Fatalf("other realm: %v", err)
	}
	if _, err := e.svc.Verify(ctx, e.k.RealmID, emailflow.Verify{FlowID: a.FlowID, Code: secA.Code}); err != nil {
		t.Fatal(err)
	}
	// 1回限り。
	if _, err := e.svc.Verify(ctx, e.k.RealmID, emailflow.Verify{FlowID: a.FlowID, Code: secA.Code}); !errors.Is(err, emailflow.ErrAuthFailed) {
		t.Fatalf("reuse: %v", err)
	}
}

func TestAttemptLimit(t *testing.T) {
	e := setup(t)
	st, _, sec := e.start(t, "gina@example.com")
	wrong := "000000"
	if sec.Code == wrong {
		wrong = "111111"
	}
	for range 5 {
		if _, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: wrong}); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	if _, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code}); err == nil {
		t.Fatal("correct code must fail after too many attempts")
	}
}

func TestFlowExpires(t *testing.T) {
	e := setup(t)
	st, _, sec := e.start(t, "hank@example.com")
	e.k.Clock.Advance(10 * time.Minute)
	if _, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code}); err == nil {
		t.Fatal("expired flow accepted")
	}
}

func TestConcurrentVerifyOnlyOneSucceeds(t *testing.T) {
	e := setup(t)
	st, _, sec := e.start(t, "ivy@example.com")
	var ok atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			if _, err := e.svc.Verify(context.Background(), e.k.RealmID, emailflow.Verify{FlowID: st.FlowID, Code: sec.Code}); err == nil {
				ok.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d verifications succeeded, want 1", ok.Load())
	}
}

// メールを送れない構成（code が無効）では通知を送らず、応答は同じ。
func TestCodeDisabledSendsNothing(t *testing.T) {
	e := setup(t, port.VerifiedViaOAuthProvider, port.VerifiedViaAdmin)
	st, err := e.svc.Start(context.Background(), e.k.RealmID, "jo@example.com", emailflow.Client{})
	if err != nil || st.FlowID == "" {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	if ns := e.notifications(t); len(ns) != 0 {
		t.Fatalf("notifications sent: %+v", ns)
	}
}

func TestNotificationCarriesNoSecretOrAddress(t *testing.T) {
	e := setup(t)
	_, _, sec := e.start(t, "kim@example.com")
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		ms, err := tx.Outbox().Pending(ctx, notify.Topic, 10)
		for _, m := range ms {
			for _, s := range []string{sec.Code, sec.Token, "kim@example.com"} {
				if bytes.Contains(m.Payload, []byte(s)) {
					t.Fatalf("payload leaks %q: %s", s, m.Payload)
				}
			}
		}
		recs, _ := tx.Audit().Scan(ctx, 1, 1000)
		for _, r := range recs {
			for _, s := range []string{sec.Code, sec.Token, "kim@example.com"} {
				if bytes.Contains(r.Payload, []byte(s)) {
					t.Fatalf("audit leaks %q: %s", s, r.Payload)
				}
			}
		}
		return err
	})
}

func TestClaimOnce(t *testing.T) {
	e := setup(t)
	_, err := e.svc.Start(context.Background(), e.k.RealmID, "lee@example.com", emailflow.Client{})
	if err != nil {
		t.Fatal(err)
	}
	n := e.notifications(t)[0]
	if _, err := e.notif.Claim(context.Background(), "rlm_other", n.ID); !errors.Is(err, notify.ErrNotClaimable) {
		t.Fatalf("claim from another realm: %v", err)
	}
	// 別の realm からの claim は失敗し、秘密も消費しない。
	if _, err := e.notif.Claim(context.Background(), e.k.RealmID, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.notif.Claim(context.Background(), e.k.RealmID, n.ID); !errors.Is(err, notify.ErrNotClaimable) {
		t.Fatalf("second claim: %v", err)
	}
}
