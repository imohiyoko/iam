package eventsub_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

var operator = eventsub.Actor{Audit: audit.Actor{Type: "user", ID: "usr_op"}, RequestID: "req_1"}

func ptr[T any](v T) *T { return &v }

func newService(k *testkit.Kit) *eventsub.Service {
	return &eventsub.Service{Crypter: k.Crypter, Clock: k.Clock}
}

func TestCheckURLAndTypes(t *testing.T) {
	s := &eventsub.Service{}
	for _, u := range []string{"", "http://example.com/", "https://user:pw@example.com/", "https://example.com/#x", "ftp://example.com/",
		"https://127.0.0.1/", "https://[::1]/", "https://10.0.0.1/hook", "https://169.254.169.254/", "mailto:x@example.com", "https:///x"} {
		if _, err := s.CheckURL(u); !errors.Is(err, errs.Invalid) {
			t.Errorf("CheckURL(%q) = %v, want Invalid", u, err)
		}
	}
	for _, u := range []string{"https://hooks.example.com/iam?token=x", "https://203.0.114.1:8443/"} {
		if _, err := s.CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v", u, err)
		}
	}
	dev := &eventsub.Service{Dev: true, AllowPrivateNetworks: true}
	if _, err := dev.CheckURL("http://127.0.0.1:8080/"); err != nil {
		t.Errorf("dev CheckURL = %v", err)
	}
	got, err := eventsub.CheckEventTypes([]string{"user.", "login.succeeded", "user."})
	if err != nil || strings.Join(got, ",") != "login.succeeded,user." {
		t.Errorf("CheckEventTypes = %v, %v", got, err)
	}
	for _, ts := range [][]string{{""}, {"Login"}, {".user"}, {"user..x"}, {"a b"}, make([]string, 21)} {
		if _, err := eventsub.CheckEventTypes(ts); !errors.Is(err, errs.Invalid) {
			t.Errorf("CheckEventTypes(%q) = %v, want Invalid", ts, err)
		}
	}
	sub := port.EventSubscription{EventTypes: []string{"login.", "user.deleted"}}
	for typ, want := range map[string]bool{"login.succeeded": true, "login": false, "user.deleted": true, "user.deleted.x": false, "org.created": false} {
		if eventsub.Wants(sub, typ) != want {
			t.Errorf("Wants(%q) != %v", typ, want)
		}
	}
	if !eventsub.Wants(port.EventSubscription{}, "anything") {
		t.Error("empty event_types must match everything")
	}
}

func TestLifecycle(t *testing.T) {
	k := testkit.New(t)
	s := newService(k)
	var sub port.EventSubscription
	var secret string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if _, err := eventlog.Record(ctx, tx, k.Clock, audit.Event{Type: "before", RealmID: k.RealmID}); err != nil {
			return err
		}
		var err error
		sub, secret, err = s.Create(ctx, tx, k.RealmID, eventsub.Input{URL: ptr("https://hooks.example.com/iam"), EventTypes: ptr([]string{"login."})}, operator)
		return err
	})
	if !strings.HasPrefix(secret, "whsec_") || len(secret) < 40 || sub.PII != eventsub.PIIOmit || !sub.Enabled || sub.CursorSeq != 1 {
		t.Fatalf("Create = %+v, %q", sub, secret)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		got, err := tx.EventSubscriptions().Get(ctx, k.RealmID, sub.ID)
		if err != nil {
			return err
		}
		// 秘密は平文で持たない。
		if strings.Contains(string(got.SecretCiphertext), secret) {
			t.Error("secret stored in plaintext")
		}
		b, err := s.Secret(ctx, tx, got)
		if err != nil || string(b) != secret {
			t.Errorf("Secret = %q, %v", b, err)
		}
		return nil
	})
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		up, err := s.Update(ctx, tx, k.RealmID, sub.ID, eventsub.Input{Enabled: ptr(false), PII: ptr("pseudonymize")}, operator)
		if err != nil || up.Enabled || up.PII != "pseudonymize" || up.URL != sub.URL {
			t.Errorf("Update = %+v, %v", up, err)
		}
		if _, err := s.Update(ctx, tx, k.RealmID, sub.ID, eventsub.Input{PII: ptr("raw")}, operator); !errors.Is(err, errs.Invalid) {
			t.Errorf("Update pii raw = %v", err)
		}
		_, rotated, err := s.RotateSecret(ctx, tx, k.RealmID, sub.ID, operator)
		if err != nil || rotated == secret {
			t.Errorf("RotateSecret = %q, %v", rotated, err)
		}
		if _, err := s.Update(ctx, tx, "other-realm", sub.ID, eventsub.Input{}, operator); !errors.Is(err, errs.NotFound) {
			t.Errorf("Update from another realm = %v", err)
		}
		return nil
	})
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if err := s.Delete(ctx, tx, k.RealmID, sub.ID, operator); err != nil {
			return err
		}
		if _, err := tx.DataKeys().Get(ctx, sub.ID); !errors.Is(err, errs.NotFound) {
			t.Errorf("data key after delete = %v", err)
		}
		return nil
	})
	// 操作は監査ログに残り、URL の経路は残さない。
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().Query(ctx, port.AuditQuery{RealmID: k.RealmID, Filter: audit.Filter{TypePrefix: "event_subscription."}, Limit: 10})
		if err != nil {
			return err
		}
		var types []string
		for _, r := range rs {
			e, _ := audit.Unmarshal(r.Payload)
			types = append(types, e.Type)
			if strings.Contains(string(r.Payload), "/iam") || strings.Contains(string(r.Payload), "whsec_") {
				t.Errorf("audit payload leaks url path or secret: %s", r.Payload)
			}
		}
		if strings.Join(types, ",") != "event_subscription.deleted,event_subscription.secret_rotated,event_subscription.updated,event_subscription.created" {
			t.Errorf("audit types = %v", types)
		}
		return nil
	})
}

func TestLimit(t *testing.T) {
	k := testkit.New(t)
	s := newService(k)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for i := range eventsub.MaxPerRealm {
			if _, _, err := s.Create(ctx, tx, k.RealmID, eventsub.Input{URL: ptr("https://hooks.example.com/")}, operator); err != nil {
				t.Fatalf("create %d: %v", i, err)
			}
		}
		if _, _, err := s.Create(ctx, tx, k.RealmID, eventsub.Input{URL: ptr("https://hooks.example.com/")}, operator); !errors.Is(err, errs.Conflict) {
			t.Errorf("over the limit = %v", err)
		}
		n, err := eventsub.Purge(ctx, tx, 100)
		if err != nil || n != eventsub.MaxPerRealm {
			t.Errorf("Purge = %d, %v", n, err)
		}
		return nil
	})
}

type receiver struct {
	mu     sync.Mutex
	status int
	bodies [][]byte
	sigs   []string
	subs   []string
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies, r.sigs, r.subs = append(r.bodies, b), append(r.sigs, req.Header.Get(eventsub.SignatureHeader)), append(r.subs, req.Header.Get(eventsub.SubscriptionHeader))
	w.WriteHeader(r.status)
}

func (r *receiver) events(t *testing.T, i int) []audit.Event {
	t.Helper()
	var body struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.Unmarshal(r.bodies[i], &body); err != nil {
		t.Fatal(err)
	}
	return body.Events
}

func TestDelivery(t *testing.T) {
	k := testkit.New(t)
	s := newService(k)
	s.Dev, s.AllowPrivateNetworks = true, true
	rcv := &receiver{status: http.StatusOK}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	d := &eventsub.Deliverer{Storage: k.Storage, Service: s, Clock: k.Clock, Interval: time.Second, Batch: 2, HTTP: srv.Client()}
	var sub port.EventSubscription
	var secret string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		sub, secret, err = s.Create(ctx, tx, k.RealmID, eventsub.Input{URL: ptr(srv.URL), EventTypes: ptr([]string{"login."}), PII: ptr("pseudonymize")}, operator)
		return err
	})
	record := func(realmID, typ string) {
		k.Tx(t, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, k.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: realmID, IP: "198.51.100.7"})
			return err
		})
	}
	record(k.RealmID, "login.succeeded")
	record("other-realm", "login.succeeded") // 別の realm のイベントは送らない
	record(k.RealmID, "org.created")         // 種類で外す
	record(k.RealmID, "login.failed")
	// 1回目：2件ずつ読む。1件目（login.succeeded）と、別の realm を飛ばした org.created。
	if n, err := d.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("Flush = %d, %v", n, err)
	}
	// 読み切れていないので、すぐに次を送る。
	if n, err := d.Flush(context.Background()); err != nil || n != 1 {
		t.Fatalf("second Flush = %d, %v", n, err)
	}
	if len(rcv.bodies) != 2 {
		t.Fatalf("requests = %d", len(rcv.bodies))
	}
	first, second := rcv.events(t, 0), rcv.events(t, 1)
	if len(first) != 1 || first[0].Type != "login.succeeded" || first[0].Chain == nil || first[0].Client != "" ||
		!strings.HasPrefix(first[0].IP, "p_") || first[0].RealmID != k.RealmID {
		t.Errorf("first batch = %+v", first)
	}
	if len(second) != 1 || second[0].Type != "login.failed" {
		t.Errorf("second batch = %+v", second)
	}
	// 署名は秘密の鍵の HMAC。
	if want := eventsub.Sign([]byte(secret), k.Clock.Now(), rcv.bodies[0]); rcv.sigs[0] != want || rcv.subs[0] != sub.ID {
		t.Errorf("signature = %q (%q), want %q", rcv.sigs[0], rcv.subs[0], want)
	}
	// 新しいイベントが無ければ送らず、Interval の後にまた見る。
	if n, err := d.Flush(context.Background()); err != nil || n != 0 || len(rcv.bodies) != 2 {
		t.Fatalf("idle Flush = %d, %v, %d requests", n, err, len(rcv.bodies))
	}

	// 失敗すれば位置を進めず、待ちを伸ばす（少なくとも1回）。
	rcv.status = http.StatusInternalServerError
	record(k.RealmID, "login.succeeded")
	k.Clock.Advance(2 * time.Second)
	if n, err := d.Flush(context.Background()); err != nil || n != 0 {
		t.Fatalf("failing Flush = %d, %v", n, err)
	}
	var st port.EventSubscription
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		st, err = tx.EventSubscriptions().Get(ctx, k.RealmID, sub.ID)
		return err
	})
	if st.Failures != 1 || st.LastError != "status_500" || st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(k.Clock.Now().Add(10*time.Second)) {
		t.Fatalf("after failure = %+v", st.EventSubscriptionDelivery)
	}
	// 待ちの間は送らない。
	if n, _ := d.Flush(context.Background()); n != 0 || len(rcv.bodies) != 3 {
		t.Fatalf("Flush while backing off sent %d (%d requests)", n, len(rcv.bodies))
	}
	rcv.status = http.StatusNoContent
	k.Clock.Advance(10 * time.Second)
	if n, err := d.Flush(context.Background()); err != nil || n != 1 || len(rcv.bodies) != 4 {
		t.Fatalf("retry Flush = %d, %v", n, err)
	}
	if again := rcv.events(t, 3); len(again) != 1 || again[0].ID != rcv.events(t, 2)[0].ID {
		t.Errorf("retry must resend the same event: %+v", again)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		st, err = tx.EventSubscriptions().Get(ctx, k.RealmID, sub.ID)
		return err
	})
	if st.Failures != 0 || st.LastError != "" || st.LastDeliveredAt == nil {
		t.Errorf("after success = %+v", st.EventSubscriptionDelivery)
	}

	// テスト送信は監査ログに載らないイベントを送る。
	res := d.Test(context.Background(), st, []byte(secret))
	if !res.Delivered || res.Status != http.StatusNoContent {
		t.Errorf("Test = %+v", res)
	}
	if ev := rcv.events(t, 4); len(ev) != 1 || ev[0].Type != eventsub.TestEventType {
		t.Errorf("test event = %+v", ev)
	}
}

func TestDeliveryOmitsPII(t *testing.T) {
	k := testkit.New(t)
	s := newService(k)
	s.Dev, s.AllowPrivateNetworks = true, true
	rcv := &receiver{status: http.StatusOK}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	d := &eventsub.Deliverer{Storage: k.Storage, Service: s, Clock: k.Clock, Interval: time.Second, HTTP: srv.Client()}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, _, err := s.Create(ctx, tx, k.RealmID, eventsub.Input{URL: ptr(srv.URL)}, operator)
		return err
	})
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, k.Clock, audit.Event{Type: "login.succeeded", RealmID: k.RealmID, IP: "198.51.100.7", UserAgent: "curl/8"})
		return err
	})
	if _, err := d.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 作成の監査ログ（作成の前の位置から送る）と login.succeeded。
	ev := rcv.events(t, 0)
	if len(ev) != 2 || ev[1].IP != "" || ev[1].UserAgent != "" || strings.Contains(string(rcv.bodies[0]), "198.51.100") {
		t.Errorf("events = %+v", ev)
	}
}

// 既定のクライアントは、公開でないアドレスにつながない（名前の解決の後でも）。
func TestPublicClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	k := testkit.New(t)
	d := &eventsub.Deliverer{Storage: k.Storage, Service: &eventsub.Service{}, Clock: k.Clock, Interval: time.Second}
	for _, u := range []string{srv.URL, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)} {
		res := d.Send(context.Background(), port.EventSubscription{ID: "evs_x", URL: u}, []byte("k"), nil)
		if res.Delivered || res.Error != eventsub.ErrAddressNotAllowed {
			t.Errorf("Send(%s) = %+v", u, res)
		}
	}
	allowed := &eventsub.Deliverer{Storage: k.Storage, Service: &eventsub.Service{AllowPrivateNetworks: true}, Clock: k.Clock}
	if res := allowed.Send(context.Background(), port.EventSubscription{ID: "evs_x", URL: srv.URL}, []byte("k"), nil); !res.Delivered {
		t.Errorf("Send with private networks allowed = %+v", res)
	}
}
