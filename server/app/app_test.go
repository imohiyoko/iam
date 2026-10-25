package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ephemeral "github.com/imohiyoko/iam/adapters/ephemeral/memory"
	"github.com/imohiyoko/iam/adapters/eventsink/stdout"
	"github.com/imohiyoko/iam/adapters/keystore/file"
	"github.com/imohiyoko/iam/adapters/notifier/dev"
	"github.com/imohiyoko/iam/adapters/storage/memory"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

type env struct {
	cfg  config.Config
	deps Deps
	out  *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	keys, err := file.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := file.FromKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	out := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.Dev = true
	// 応答時間の下限は guard_test で確かめる。ほかのテストでは待たない。
	cfg.Security.Login.MinResponseTime = 0
	return &env{cfg: cfg, out: out, deps: Deps{
		Storage: memory.New(clk), Ephemeral: ephemeral.New(clk), KeyStore: ks,
		EventSink: stdout.New(out), Notifier: &dev.Notifier{Log: log}, Clock: clk, Logger: log,
	}}
}

// 台帳にあるがバイナリに無いフィーチャーのデータがあると、起動を拒否する（roadmap M0 の完了条件）。
func TestStartupRejectsLedgerFeatureMissingFromBinary(t *testing.T) {
	e := newEnv(t)
	err := e.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		return tx.Features().Put(ctx, port.FeatureRecord{Feature: feature.Quota, State: port.FeatureActive, DataVersion: 1})
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(context.Background(), e.cfg, e.deps, []feature.Feature{{Name: feature.Org, DataVersion: 1}})
	if !errors.Is(err, feature.ErrLedgerMismatch) {
		t.Fatalf("want ErrLedgerMismatch, got %v", err)
	}
}

func TestStartupCreatesRealmOnce(t *testing.T) {
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Realm().ID != b.Realm().ID || a.Realm().Slug != "default" {
		t.Fatalf("realm %v vs %v", a.Realm(), b.Realm())
	}
	if _, n, err := eventlog.Verify(context.Background(), e.deps.Storage); err != nil || n != 1 {
		t.Fatalf("audit: n=%d err=%v", n, err)
	}
}

func TestStartupRejectsUnsharedEphemeralForMultiInstance(t *testing.T) {
	e := newEnv(t)
	e.cfg.Server.MultiInstance = true
	if _, err := New(context.Background(), e.cfg, e.deps, nil); err == nil {
		t.Fatal("want error")
	}
}

type brokenStorage struct{ port.Storage }

func (brokenStorage) Ping(context.Context) error { return errors.New("down") }

func TestHealth(t *testing.T) {
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Handler{"public": a.PublicHandler(), "admin": a.AdminHandler()} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(`"ok"`)) {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if rec.Header().Get("X-Request-Id") == "" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: headers %v", name, rec.Header())
		}
	}
	a.deps.Storage = brokenStorage{a.deps.Storage}
	rec := httptest.NewRecorder()
	a.PublicHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 503 {
		t.Fatalf("broken storage: %d", rec.Code)
	}
}

func TestServe(t *testing.T) {
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := net.Listen("tcp", "127.0.0.1:0")
	adm, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Serve(ctx, pub, adm) }()

	for _, l := range []net.Listener{pub, adm} {
		resp, err := http.Get("http://" + l.Addr().String() + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]string
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != 200 || body["status"] != "ok" {
			t.Fatalf("%s: %d %v", l.Addr(), resp.StatusCode, body)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// 起動時の監査イベントが、個人情報を外して EventSink に出ている。
	if !bytes.Contains(e.out.Bytes(), []byte(`"type":"system.started"`)) || !bytes.Contains(e.out.Bytes(), []byte(`"type":"realm.created"`)) {
		t.Fatalf("event sink output: %s", e.out)
	}
}

func TestResponseErrorHidesInternalMessage(t *testing.T) {
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.responseError(rec, httptest.NewRequest("GET", "/x", nil), errors.New("data key for usr_secret: sql: no rows"))
	if rec.Code != 500 || bytes.Contains(rec.Body.Bytes(), []byte("usr_secret")) || !bytes.Contains(rec.Body.Bytes(), []byte(`"internal"`)) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
