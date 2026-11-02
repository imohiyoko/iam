package pat_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// rules は authz/role の規則の写し（authn のテストは authz を import できない）。
var permRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}:(\*|[a-z0-9_.-]{1,64})$`)

var rules = pat.ScopeRules{
	Valid: permRE.MatchString,
	Covered: func(granted []string, want string) bool {
		return slices.ContainsFunc(granted, func(g string) bool {
			res, ok := strings.CutSuffix(g, ":*")
			return g == want || (ok && strings.HasPrefix(want, res+":"))
		})
	},
}

type fixture struct {
	k   *testkit.Kit
	s   *pat.Service
	u   port.User
	req pat.Request
}

func newFixture(t *testing.T, cfg pat.Config) *fixture {
	k := testkit.New(t)
	u := k.SeedUser(t)
	return &fixture{k: k, s: &pat.Service{Clock: k.Clock, Config: cfg, Scopes: rules}, u: u,
		req: pat.Request{Actor: audit.Actor{Type: "user", ID: u.PublicID}, RequestID: "req-1"}}
}

func (f *fixture) create(t *testing.T, in pat.CreateInput) (pat.Created, error) {
	t.Helper()
	in.RealmID, in.User, in.Request = f.k.RealmID, f.u, f.req
	if in.Name == "" {
		in.Name = "ci"
	}
	var out pat.Created
	err := f.k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = f.s.Create(ctx, tx, in)
		return err
	})
	return out, err
}

func (f *fixture) auth(token string) (pat.Authenticated, error) {
	var out pat.Authenticated
	err := f.k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = f.s.Authenticate(ctx, tx, f.k.RealmID, token)
		return err
	})
	return out, err
}

func (f *fixture) setPolicy(t *testing.T, p pat.Policy) error {
	t.Helper()
	return f.k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		_, err := f.s.SetPolicy(ctx, tx, f.k.RealmID, p, f.req)
		return err
	})
}

func code(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestTokenFormat(t *testing.T) {
	f := newFixture(t, pat.Config{MaxPerUser: 10})
	c, err := f.create(t, pat.CreateInput{Scopes: []string{"users:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Token) != pat.TokenLength || !regexp.MustCompile(`^`+pat.Pattern+`$`).MatchString(c.Token) {
		t.Fatalf("token %q does not match %s", c.Token, pat.Pattern)
	}
	tid, secret, ok := pat.Parse(c.Token)
	if !ok || tid != c.PAT.ID || len(secret) != 43 || !id.Valid(id.PAT, tid) {
		t.Fatalf("Parse = %q %q %v", tid, secret, ok)
	}
	// 秘密は平文で持たない。
	if strings.Contains(string(c.PAT.Hash), secret) || len(c.PAT.Hash) != 32 {
		t.Fatalf("hash = %x", c.PAT.Hash)
	}
	// 1 文字でも変えれば検査で落ちる（DB を引かない）。
	for i := len(pat.Prefix); i < len(c.Token); i++ {
		if c.Token[i] == '_' {
			continue
		}
		b := []byte(c.Token)
		b[i] = map[bool]byte{true: '1', false: '2'}[b[i] != '1']
		if _, _, ok := pat.Parse(string(b)); ok {
			t.Errorf("Parse accepted a token changed at %d", i)
		}
	}
	for _, bad := range []string{"", pat.Prefix, strings.ToLower(c.Token), c.Token + "x", c.Token[:len(c.Token)-1], "iampat-" + c.Token[7:],
		strings.Replace(c.Token, "_", "-", 2)} {
		if _, _, ok := pat.Parse(bad); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("iampat_01JB0000000000000000000000_" + strings.Repeat("a", 49))
	f.Add("iampat_")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		tid, secret, ok := pat.Parse(s)
		if !ok {
			return
		}
		if len(s) != pat.TokenLength || !id.Valid(id.PAT, tid) || len(secret) != 43 || !strings.HasPrefix(s, pat.Prefix) {
			t.Fatalf("Parse(%q) = %q %q", s, tid, secret)
		}
	})
}

func TestCreateAndAuthenticate(t *testing.T) {
	f := newFixture(t, pat.Config{MaxPerUser: 10})
	exp := f.k.Clock.Now().Add(24 * time.Hour)
	c, err := f.create(t, pat.CreateInput{Scopes: []string{"users:read", "docs:*", "users:read"}, ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.PAT.Scopes, []string{"docs:*", "users:read"}) {
		t.Fatalf("scopes = %v", c.PAT.Scopes)
	}
	a, err := f.auth(c.Token)
	if err != nil {
		t.Fatal(err)
	}
	if a.User.ID != f.u.ID || !slices.Equal(a.Scopes, c.PAT.Scopes) || a.ExpiresAt == nil || !a.ExpiresAt.Equal(exp) {
		t.Fatalf("Authenticate = %+v", a)
	}
	if a.Token.LastUsedAt == nil || !a.Token.LastUsedAt.Equal(f.k.Clock.Now()) {
		t.Fatalf("last used = %v", a.Token.LastUsedAt)
	}
	// 1 分以内は書き直さない。
	f.k.Clock.Advance(30 * time.Second)
	if a, _ = f.auth(c.Token); !a.Token.LastUsedAt.Equal(f.k.Clock.Now().Add(-30 * time.Second)) {
		t.Fatalf("last used rewritten too early: %v", a.Token.LastUsedAt)
	}
	f.k.Clock.Advance(time.Minute)
	if a, _ = f.auth(c.Token); !a.Token.LastUsedAt.Equal(f.k.Clock.Now()) {
		t.Fatalf("last used not rewritten: %v", a.Token.LastUsedAt)
	}

	// 秘密の違い・他の realm・期限切れ。
	_, secret, _ := pat.Parse(c.Token)
	other, err := f.create(t, pat.CreateInput{Scopes: []string{"users:read"}})
	if err != nil {
		t.Fatal(err)
	}
	_, otherSecret, _ := pat.Parse(other.Token)
	// 検査の文字は正しいが、秘密が別のトークンのもの。
	swapped := pat.Format(c.PAT.ID, otherSecret)
	if _, _, ok := pat.Parse(swapped); !ok {
		t.Fatal("swapped token should parse")
	}
	if _, err := f.auth(swapped); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("swapped secret: %v", err)
	}
	if _, err := f.auth(pat.Format(id.NewExternal(id.PAT), secret)); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("unknown id: %v", err)
	}
	f.k.Clock.Set(exp)
	if _, err := f.auth(c.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	f := newFixture(t, pat.Config{MaxPerUser: 2, MaxLifetime: 30 * 24 * time.Hour})
	past := f.k.Clock.Now().Add(-time.Second)
	far := f.k.Clock.Now().Add(31 * 24 * time.Hour)
	for name, c := range map[string]struct {
		in   pat.CreateInput
		code string
	}{
		"no scopes":      {pat.CreateInput{}, "invalid_scope"},
		"bad scope":      {pat.CreateInput{Scopes: []string{"Users:read"}}, "invalid_scope"},
		"star":           {pat.CreateInput{Scopes: []string{"*"}}, "invalid_scope"},
		"too many":       {pat.CreateInput{Scopes: manyScopes(21)}, "invalid_scope"},
		"blank name":     {pat.CreateInput{Name: " ", Scopes: []string{"a:b"}}, "invalid_name"},
		"control name":   {pat.CreateInput{Name: "a\nb", Scopes: []string{"a:b"}}, "invalid_name"},
		"long name":      {pat.CreateInput{Name: strings.Repeat("x", 101), Scopes: []string{"a:b"}}, "invalid_name"},
		"past expiry":    {pat.CreateInput{Scopes: []string{"a:b"}, ExpiresAt: &past}, "invalid_expiry"},
		"beyond max age": {pat.CreateInput{Scopes: []string{"a:b"}, ExpiresAt: &far}, "invalid_expiry"},
	} {
		if _, err := f.create(t, c.in); code(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	// ホスト先の上限があれば、期限を省くと上限の期限を付ける。
	c, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}})
	if err != nil || c.PAT.ExpiresAt == nil || !c.PAT.ExpiresAt.Equal(f.k.Clock.Now().Add(30*24*time.Hour)) {
		t.Fatalf("default expiry = %+v, %v", c.PAT.ExpiresAt, err)
	}
	if _, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}}); code(err) != "token_limit" || !errors.Is(err, errs.Conflict) {
		t.Fatalf("limit: %v", err)
	}
	// 取り消せば数えない。
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return f.s.Revoke(ctx, tx, f.k.RealmID, f.u, c.PAT.ID, pat.ReasonUser, f.req)
	})
	if _, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}}); err != nil {
		t.Fatalf("after revoke: %v", err)
	}
}

func manyScopes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "r" + strings.Repeat("x", i) + ":read"
	}
	return out
}

func TestPolicy(t *testing.T) {
	f := newFixture(t, pat.Config{MaxPerUser: 10, MaxLifetime: 90 * 24 * time.Hour})
	if err := f.setPolicy(t, pat.Policy{MaxLifetime: 91 * 24 * time.Hour}); code(err) != "invalid_policy" {
		t.Fatalf("beyond host max: %v", err)
	}
	if err := f.setPolicy(t, pat.Policy{AllowedScopes: []string{"bad"}}); code(err) != "invalid_policy" {
		t.Fatalf("bad allowed scope: %v", err)
	}
	if err := f.setPolicy(t, pat.Policy{MaxLifetime: 1500 * time.Millisecond}); code(err) != "invalid_policy" {
		t.Fatalf("sub-second lifetime: %v", err)
	}
	// 期限なしのトークン（ホスト先の上限が無い構成）。
	g := newFixture(t, pat.Config{MaxPerUser: 10})
	forever, err := g.create(t, pat.CreateInput{Scopes: []string{"docs:read", "users:read"}})
	if err != nil || forever.PAT.ExpiresAt != nil {
		t.Fatalf("forever = %+v, %v", forever.PAT.ExpiresAt, err)
	}
	if err := g.setPolicy(t, pat.Policy{RequireExpiry: true, AllowedScopes: []string{"docs:*"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.create(t, pat.CreateInput{Scopes: []string{"docs:read"}}); code(err) != "expiry_required" {
		t.Fatalf("require expiry: %v", err)
	}
	exp := g.k.Clock.Now().Add(time.Hour)
	if _, err := g.create(t, pat.CreateInput{Scopes: []string{"users:read"}, ExpiresAt: &exp}); code(err) != "scope_not_allowed" {
		t.Fatalf("scope not allowed: %v", err)
	}
	if _, err := g.create(t, pat.CreateInput{Scopes: []string{"docs:read"}, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	// 厳しくしたポリシーは既存のトークンにも効く：期限の無いトークンは使えない。
	if _, err := g.auth(forever.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("forever token under require_expiry: %v", err)
	}
	// 寿命の上限を置けば期限なしのトークンも作成から上限までで、スコープは許すものだけが効く。
	if err := g.setPolicy(t, pat.Policy{MaxLifetime: 48 * time.Hour, AllowedScopes: []string{"docs:*"}}); err != nil {
		t.Fatal(err)
	}
	a, err := g.auth(forever.Token)
	if err != nil || !slices.Equal(a.Scopes, []string{"docs:read"}) || a.ExpiresAt == nil || !a.ExpiresAt.Equal(forever.PAT.CreatedAt.Add(48*time.Hour)) {
		t.Fatalf("narrowed = %+v, %v", a, err)
	}
	g.k.Clock.Advance(48 * time.Hour)
	if _, err := g.auth(forever.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("beyond realm max lifetime: %v", err)
	}
	// 許すスコープが全部外れたトークンは使えない。
	h := newFixture(t, pat.Config{MaxPerUser: 10})
	only, err := h.create(t, pat.CreateInput{Scopes: []string{"users:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.setPolicy(t, pat.Policy{AllowedScopes: []string{"docs:read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.auth(only.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("no effective scope: %v", err)
	}
}

func TestRevokeAndAccountState(t *testing.T) {
	f := newFixture(t, pat.Config{MaxPerUser: 10})
	a, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}})
	if err != nil {
		t.Fatal(err)
	}
	other := f.k.SeedUser(t)
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		// 他の人のトークン・形の違う ID は見つからない。
		if err := f.s.Revoke(ctx, tx, f.k.RealmID, other, a.PAT.ID, pat.ReasonUser, f.req); !errors.Is(err, pat.ErrNotFound) {
			t.Errorf("revoke other's token: %v", err)
		}
		if err := f.s.Revoke(ctx, tx, f.k.RealmID, f.u, "nope", pat.ReasonUser, f.req); !errors.Is(err, pat.ErrNotFound) {
			t.Errorf("revoke bad id: %v", err)
		}
		if err := f.s.Revoke(ctx, tx, f.k.RealmID, f.u, a.PAT.ID, pat.ReasonUser, f.req); err != nil {
			return err
		}
		// 2 回目も成功（何もしない）。
		return f.s.Revoke(ctx, tx, f.k.RealmID, f.u, a.PAT.ID, pat.ReasonOperator, f.req)
	})
	if _, err := f.auth(a.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := f.auth(b.Token); err != nil {
		t.Fatal(err)
	}
	// 停止中は使えず、解いた後も（作成の後の停止をまたいだので）使えない。
	sp := port.Suspension{ID: id.New(id.Suspension), PublicID: id.NewExternal(id.Suspension), RealmID: f.k.RealmID, TargetType: port.SuspensionTargetUser,
		TargetID: f.u.ID, Category: "security_risk", StartsAt: f.k.Clock.Now(), CreatedAt: f.k.Clock.Now()}
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Suspensions().Create(ctx, sp) })
	f.k.Clock.Advance(time.Minute)
	if _, err := f.auth(b.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("suspended: %v", err)
	}
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return tx.Suspensions().Lift(ctx, f.k.RealmID, sp.ID, f.k.Clock.Now(), "")
	})
	f.k.Clock.Advance(time.Minute)
	if _, err := f.auth(b.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("after lift: %v", err)
	}
	// 新しく作ったトークンは使える。RevokeAll は取り消していないものを数える。
	c, err := f.create(t, pat.CreateInput{Scopes: []string{"a:b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth(c.Token); err != nil {
		t.Fatal(err)
	}
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		n, err := f.s.RevokeAll(ctx, tx, f.k.RealmID, f.u, pat.ReasonRevokeAll, f.req)
		if err == nil && n != 2 {
			t.Errorf("RevokeAll = %d", n)
		}
		return err
	})
	if _, err := f.auth(c.Token); !errors.Is(err, pat.ErrInvalid) {
		t.Fatalf("after revoke all: %v", err)
	}
	// 監査ログ。
	var types []string
	f.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, f.k.RealmID, 1, 1000)
		for _, r := range rs {
			var e audit.Event
			if err := json.Unmarshal(r.Payload, &e); err != nil {
				return err
			}
			types = append(types, e.Type)
		}
		return err
	})
	if n := countOf(types, pat.EventCreated); n != 3 {
		t.Errorf("created events = %d (%v)", n, types)
	}
	if n := countOf(types, pat.EventRevoked); n != 2 {
		t.Errorf("revoked events = %d (%v)", n, types)
	}
}

func countOf(xs []string, v string) int {
	n := 0
	for _, x := range xs {
		if x == v {
			n++
		}
	}
	return n
}
