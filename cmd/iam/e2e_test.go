package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 2つの構成（SQLite + インメモリ、PostgreSQL + Redis）で、`iam serve` を HTTP から通しで使う（roadmap M6 の完了条件）。
// PostgreSQL + Redis は IAM_TEST_POSTGRES と IAM_TEST_REDIS があるときだけ動く。

func TestE2ESQLiteAndMemory(t *testing.T) {
	dir := t.TempDir()
	runE2E(t, dir, fmt.Sprintf("storage: {driver: sqlite, path: %q}\nephemeral: {driver: memory}\n", filepath.Join(dir, "iam.db")))
}

func TestE2EPostgresAndRedis(t *testing.T) {
	base, rd := os.Getenv("IAM_TEST_POSTGRES"), os.Getenv("IAM_TEST_REDIS")
	if base == "" || rd == "" {
		t.Skip("IAM_TEST_POSTGRES and IAM_TEST_REDIS are not set")
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup は後入れ先出しなので、DROP DATABASE の後に閉じる。
	t.Cleanup(func() { _ = admin.Close() })
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "iam_e2e_" + hex.EncodeToString(b)
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`) })
	u, _ := url.Parse(base)
	u.Path = "/" + name
	runE2E(t, t.TempDir(), fmt.Sprintf("storage: {driver: postgres, dsn: %q}\nephemeral: {driver: redis, url: %q, prefix: %q}\n", u.String(), rd, name+":"))
}

type e2eServer struct {
	pub, adm string
	logs     *syncBuffer
	seen     map[string]string // 宛先ごとに使ったコード
	codes    []string          // 使ったコード（イベントに出ないことを確かめる）
}

// code は dev の Notifier がログに出した、to 宛ての最新のコードを返す。
func (s *e2eServer) code(t *testing.T, to string) string {
	t.Helper()
	for range 100 {
		var code string
		sc := bufio.NewScanner(strings.NewReader(s.logs.String()))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var l struct{ Msg, To, Code string }
			if json.Unmarshal(sc.Bytes(), &l) == nil && l.Msg == "dev notifier: secret (development only)" && strings.EqualFold(l.To, to) {
				code = l.Code
			}
		}
		if code != "" {
			return code
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no code for %s:\n%s", to, s.logs.String())
	return ""
}

// login はメールのコードでログインし、確認の応答（return_token でトークンを含む）を返す。
func (s *e2eServer) login(t *testing.T, email string) (int, map[string]any) {
	t.Helper()
	status, st := postJSON(t, "http://"+s.pub+"/v1/login/email:start", "", map[string]any{"email": email})
	if status != 200 {
		t.Fatalf("start %s: %d %v", email, status, st)
	}
	code := s.waitNewCode(t, email, st["flow_id"].(string))
	return postJSON(t, "http://"+s.pub+"/v1/login/email:verify", "", map[string]any{"flow_id": st["flow_id"], "code": code, "return_token": true})
}

// waitNewCode は flow ごとに新しいコードが出るまで待つ（同じ宛先の前のコードを使わない）。
func (s *e2eServer) waitNewCode(t *testing.T, email, flowID string) string {
	t.Helper()
	seen := s.seen[strings.ToLower(email)]
	for range 100 {
		if c := s.code(t, email); c != seen {
			s.seen[strings.ToLower(email)] = c
			s.codes = append(s.codes, c)
			return c
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no new code for %s (flow %s)", email, flowID)
	return ""
}

func getJSON(t *testing.T, url, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func runE2E(t *testing.T, dir, adapters string) {
	ctx := context.Background()
	keys := filepath.Join(dir, "keys.json")
	var out bytes.Buffer
	if err := run(ctx, []string{"keys", "generate", "-out", keys}, &out, &out); err != nil {
		t.Fatal(err)
	}
	s := &e2eServer{pub: freeAddr(t), adm: freeAddr(t), logs: &syncBuffer{}, seen: map[string]string{}}
	cfgPath := filepath.Join(dir, "iam.yaml")
	cfg := fmt.Sprintf(`dev: true
server: {public_addr: %q, admin_addr: %q, public_url: "http://localhost:%s"}
%skeystore: {driver: file, path: %q}
event_sink: {driver: stdout}
notifier: {driver: dev}
outbox: {interval: 50ms}
`, s.pub, s.adm, s.pub[strings.LastIndex(s.pub, ":")+1:], adapters, keys)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"migrate", "-config", cfgPath}, &out, &out); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run(ctx, []string{"operator", "create", "-config", cfgPath, "-email", "ops@example.com"}, &out, &out); err != nil {
		t.Fatalf("operator: %v\n%s", err, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var link string
	for i, l := range lines {
		if strings.HasPrefix(l, "one-time login token") && i+1 < len(lines) {
			link = lines[i+1]
		}
	}

	// 通知の配信用のサービスアカウント（2.4、ADR 0074）。
	out.Reset()
	if err := run(ctx, []string{"service-account", "create", "-config", cfgPath, "-name", "delivery"}, &out, &out); err != nil {
		t.Fatalf("service-account: %v\n%s", err, out.String())
	}
	saLines := strings.Split(strings.TrimSpace(out.String()), "\n")
	deliveryKey := saLines[len(saLines)-1]
	if !strings.HasPrefix(deliveryKey, "sac_") {
		t.Fatalf("service-account output:\n%s", out.String())
	}

	sctx, cancel := context.WithCancel(ctx)
	var stdout syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(sctx, []string{"serve", "-config", cfgPath}, &stdout, s.logs) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	for i := 0; ; i++ {
		if resp, err := http.Get("http://" + s.pub + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if i > 200 {
			t.Fatalf("not ready:\n%s", s.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	pub, adm := "http://"+s.pub, "http://"+s.adm

	// 運営者のログイン。
	status, res := postJSON(t, pub+"/v1/login/link:redeem", "", map[string]any{"token": link, "return_token": true})
	if status != 200 {
		t.Fatalf("operator redeem: %d %v", status, res)
	}
	op := res["token"].(string)

	// 登録とログイン。2回目は同じユーザー。
	status, res = s.login(t, "alice@example.com")
	if status != 200 || res["created"] != true {
		t.Fatalf("signup: %d %v", status, res)
	}
	alice, aliceID := res["token"].(string), res["user_id"].(string)
	if status, res = s.login(t, "Alice@Example.com"); status != 200 || res["user_id"] != aliceID {
		t.Fatalf("login: %d %v", status, res)
	}
	if status, res = getJSON(t, pub+"/v1/me/sessions", alice); status != 200 {
		t.Fatalf("sessions: %d %v", status, res)
	}

	// Org と招待。
	status, res = postJSON(t, pub+"/v1/me/orgs", alice, map[string]any{"name": "Acme"})
	if status != 201 {
		t.Fatalf("create org: %d %v", status, res)
	}
	acme := res["id"].(string)
	if status, res = postJSON(t, pub+"/v1/me/orgs/"+acme+"/invitations", alice, map[string]any{"email": "bob@example.com", "role": "member"}); status != 201 {
		t.Fatalf("invite: %d %v", status, res)
	}
	if status, res = getJSON(t, pub+"/v1/me/orgs", alice); status != 200 || len(res["orgs"].([]any)) != 2 {
		t.Fatalf("my orgs: %d %v", status, res)
	}

	// 運営者がユーザーを作り、停止する。停止中はログインできない。
	status, res = postJSON(t, adm+"/v1/admin/users", op, map[string]any{"email": "carol@example.com"})
	if status != 201 {
		t.Fatalf("admin create user: %d %v", status, res)
	}
	carol := res["user_id"].(string)
	if status, res = s.login(t, "carol@example.com"); status != 200 {
		t.Fatalf("carol login: %d %v", status, res)
	}
	if status, res = postJSON(t, adm+"/v1/admin/users/"+carol+"/suspensions", op, map[string]any{"category": "tos_violation", "reason": "e2e"}); status != 201 {
		t.Fatalf("suspend: %d %v", status, res)
	}
	if status, res = s.login(t, "carol@example.com"); status == 200 {
		t.Fatalf("suspended login: %d %v", status, res)
	}

	// 配信用のキーで管理 API の通知の取り出しを呼べる（無い通知は 404。認可は通っている）。
	if status, res = postJSON(t, adm+"/v1/admin/notifications/ntf_00000000000000000000000000:claim", deliveryKey, nil); status != 404 {
		t.Fatalf("delivery claim: %d %v", status, res)
	}

	// ログアウトしたトークンは使えない。
	if status, res = postJSON(t, pub+"/v1/logout", alice, nil); status/100 != 2 {
		t.Fatalf("logout: %d %v", status, res)
	}
	if status, _ = getJSON(t, pub+"/v1/me/sessions", alice); status != 401 {
		t.Fatalf("after logout: %d", status)
	}

	// 監査ログは外部出力（stdout）に届き、秘密は出ない。
	for range 100 {
		if strings.Contains(stdout.String(), `"type":"user.suspended"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), `"type":"user.suspended"`) {
		t.Fatalf("audit events not delivered:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), alice) || strings.Contains(stdout.String(), link) {
		t.Fatal("a secret reached the event sink")
	}
	// メールのコードは数字だけなので、時刻などとの部分一致を避けて JSON の文字列として探す。
	if len(s.codes) == 0 {
		t.Fatal("no codes were used")
	}
	for _, c := range s.codes {
		if strings.Contains(stdout.String(), `"`+c+`"`) {
			t.Fatalf("email code %s reached the event sink", c)
		}
	}
}
