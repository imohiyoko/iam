package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// `iam serve` が SQLite + インメモリで起動し、ヘルスチェックに応答する（roadmap M0 の完了条件）。
func TestServeSQLiteAndMemory(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.json")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"keys", "generate", "-out", keys}, &out, &out); err != nil {
		t.Fatal(err)
	}
	pub, adm := freeAddr(t), freeAddr(t)
	cfgPath := filepath.Join(dir, "iam.yaml")
	cfg := fmt.Sprintf(`dev: true
server: {public_addr: %q, admin_addr: %q}
storage: {driver: sqlite, path: %q}
ephemeral: {driver: memory}
keystore: {driver: file, path: %q}
event_sink: {driver: stdout}
notifier: {driver: dev}
`, pub, adm, filepath.Join(dir, "iam.db"), keys)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"migrate", "-config", cfgPath}, &out, &out); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "-config", cfgPath}, &stdout, &stderr) }()

	for _, addr := range []string{pub, adm} {
		var resp *http.Response
		var err error
		for range 100 {
			if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("serve exited: %v\n%s", err, stderr.String())
			case <-time.After(50 * time.Millisecond):
			}
		}
		if err != nil {
			t.Fatalf("%s: %v\n%s", addr, err, stderr.String())
		}
		var body map[string]string
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != 200 || body["status"] != "ok" {
			t.Fatalf("%s: %d %v", addr, resp.StatusCode, body)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"type":"system.started"`) {
		t.Fatalf("audit events not emitted to stdout: %s", stdout.String())
	}
}

func TestVersionManifest(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"version", "-manifest"}, &out, &out); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Adapters map[string][]string `json:"adapters"`
		Features []any               `json:"features"`
	}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if fmt.Sprint(m.Adapters["storage"]) != "[memory postgres sqlite]" || fmt.Sprint(m.Adapters["ephemeral"]) != "[memory redis]" || m.Features == nil {
		t.Fatalf("manifest = %s", out.String())
	}
}

func TestServeRejectsDevNotifierInProduction(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "iam.yaml")
	os.WriteFile(cfgPath, []byte("notifier: {driver: dev}\n"), 0o600)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"serve", "-config", cfgPath}, &out, &out); err == nil {
		t.Fatal("want error")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServeRejectsUnknownAdapterOption(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "iam.yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf("dev: true\nstorage: {driver: sqlite, paht: %q}\n", filepath.Join(dir, "x.db"))), 0o600)
	var out bytes.Buffer
	err := run(context.Background(), []string{"serve", "-config", cfgPath}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "paht") {
		t.Fatalf("want unknown option error, got %v", err)
	}
}

// setupDir は鍵と設定を作り、マイグレーションを適用する。
func setupDir(t *testing.T) (cfgPath, pub, adm string) {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.json")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"keys", "generate", "-out", keys}, &out, &out); err != nil {
		t.Fatal(err)
	}
	pub, adm = freeAddr(t), freeAddr(t)
	cfgPath = filepath.Join(dir, "iam.yaml")
	cfg := fmt.Sprintf(`dev: true
server: {public_addr: %q, admin_addr: %q}
storage: {driver: sqlite, path: %q}
keystore: {driver: file, path: %q}
notifier: {driver: dev}
`, pub, adm, filepath.Join(dir, "iam.db"), keys)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"migrate", "-config", cfgPath}, &out, &out); err != nil {
		t.Fatal(err)
	}
	return cfgPath, pub, adm
}

func postJSON(t *testing.T, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// 最初の運営者を CLI で作り、ログイン用リンクでログインし、そのセッションで管理 API を使う（design.md 2.5、4.11）。
func TestOperatorCreateThenAdminAPI(t *testing.T) {
	cfgPath, pub, adm := setupDir(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"operator", "create", "-config", cfgPath, "-email", "Ops@Example.com"}, &out, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var token string
	for i, l := range lines {
		if strings.HasPrefix(l, "one-time login token") && i+1 < len(lines) {
			token = lines[i+1]
		}
	}
	if !strings.HasPrefix(out.String(), "created operator usr_") || token == "" {
		t.Fatalf("output:\n%s", out.String())
	}
	// 2回目は既存のユーザー（ロールは重ねない）。
	var out2 bytes.Buffer
	if err := run(context.Background(), []string{"operator", "create", "-config", cfgPath, "-email", "ops@example.com"}, &out2, &out2); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out2.String(), "added role to existing user") {
		t.Fatalf("second run:\n%s", out2.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "-config", cfgPath}, &stdout, &stderr) }()
	for range 100 {
		if resp, err := http.Get("http://" + pub + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	status, res := postJSON(t, "http://"+pub+"/v1/login/link:redeem", "", map[string]any{"token": token, "return_token": true})
	if status != 200 || res["token"] == nil {
		t.Fatalf("redeem: %d %v\n%s", status, res, stderr.String())
	}
	session := res["token"].(string)
	// 1回限り。
	if status, _ := postJSON(t, "http://"+pub+"/v1/login/link:redeem", "", map[string]any{"token": token}); status != 401 {
		t.Fatalf("reuse: %d", status)
	}
	if status, res := postJSON(t, "http://"+adm+"/v1/admin/users", session, map[string]any{"email": "new@example.com"}); status != 201 || res["user_id"] == nil {
		t.Fatalf("create user: %d %v", status, res)
	}
	if status, _ := postJSON(t, "http://"+adm+"/v1/admin/users", "", map[string]any{"email": "x@example.com"}); status != 401 {
		t.Fatalf("unauthenticated: %d", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatal("login link token leaked to logs")
	}
}
