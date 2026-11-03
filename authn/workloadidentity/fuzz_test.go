package workloadidentity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

var fuzzClaims = map[string]any{
	"sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app", "ref": "refs/heads/main", "n": 1.0, "b": true,
	"a/b": "slash", "t~x": "tilde", "kubernetes.io": map[string]any{"namespace": "prod", "serviceaccount": map[string]any{"name": "ci"}},
	"list": []any{"x"},
}

func FuzzParseConditions(f *testing.F) {
	for _, s := range []string{
		`[{"claim":"/repository","equals":"acme/app"}]`,
		`[{"claim":"/ref","in":["refs/heads/main","refs/heads/dev"]},{"claim":"/sub","prefix":"repo:acme/"}]`,
		`[{"claim":"/kubernetes.io/serviceaccount/name","equals":"ci"}]`,
		`[{"claim":"/a~1b","equals":"slash"},{"claim":"/t~0x","equals":"tilde"}]`,
		`[{"claim":"/n","equals":"1"}]`, `[{"claim":"/a~","equals":"x"}]`, `[]`, `{}`, `null`, `[{"claim":"/x","equals":"y","in":["y"]}]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		cs, err := ParseConditions(b)
		if err != nil {
			if cs != nil {
				t.Fatal("conditions returned with an error")
			}
			return
		}
		if len(cs) == 0 || len(cs) > MaxConditions {
			t.Fatalf("accepted %d conditions", len(cs))
		}
		for _, c := range cs {
			ops := 0
			for _, set := range []bool{c.Equals != nil, c.In != nil, c.Prefix != nil} {
				if set {
					ops++
				}
			}
			if ops != 1 {
				t.Fatalf("accepted a condition with %d operators: %+v", ops, c)
			}
		}
		_ = MatchAll(cs, fuzzClaims)
		// 保存の形にして読み直しても同じ条件になる。
		out, err := MarshalConditions(cs)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseConditions(out)
		if err != nil {
			t.Fatalf("re-parse %s: %v", out, err)
		}
		if !reflect.DeepEqual(cs, again) {
			t.Fatalf("round trip changed the conditions: %+v != %+v", cs, again)
		}
		if MatchAll(cs, fuzzClaims) != MatchAll(again, fuzzClaims) {
			t.Fatal("round trip changed the result")
		}
	})
}

func FuzzParsePointer(f *testing.F) {
	for _, s := range []string{"/sub", "/a~1b", "/t~0x", "/kubernetes.io/namespace", "", "/", "//", "/a~", "/a~2", "sub"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := parsePointer(s)
		if err != nil {
			return
		}
		if len(p) == 0 || len(p) > MaxPointerDepth || !strings.HasPrefix(s, "/") {
			t.Fatalf("accepted %q as %q", s, p)
		}
		// エスケープし直すと元に戻る。
		var b strings.Builder
		for _, seg := range p {
			if seg == "" {
				t.Fatalf("empty segment in %q", s)
			}
			b.WriteString("/" + strings.ReplaceAll(strings.ReplaceAll(seg, "~", "~0"), "/", "~1"))
		}
		if b.String() != s {
			t.Fatalf("%q -> %q -> %q", s, p, b.String())
		}
	})
}

func TestMatch(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		c    Condition
		want bool
	}{
		{Condition{Claim: "/repository", Equals: str("acme/app")}, true},
		{Condition{Claim: "/repository", Equals: str("ACME/app")}, false},
		{Condition{Claim: "/repository", Prefix: str("acme/")}, true},
		{Condition{Claim: "/repository", Prefix: str("acme/app/")}, false},
		{Condition{Claim: "/ref", In: []string{"refs/heads/dev", "refs/heads/main"}}, true},
		{Condition{Claim: "/kubernetes.io/serviceaccount/name", Equals: str("ci")}, true},
		{Condition{Claim: "/kubernetes.io/namespace/x", Equals: str("prod")}, false},
		{Condition{Claim: "/a~1b", Equals: str("slash")}, true},
		{Condition{Claim: "/t~0x", Equals: str("tilde")}, true},
		{Condition{Claim: "/n", Equals: str("1")}, false},
		{Condition{Claim: "/b", Equals: str("true")}, false},
		{Condition{Claim: "/list", In: []string{"x"}}, false},
		{Condition{Claim: "/missing", Prefix: str("x")}, false},
		{Condition{Claim: "/sub", Equals: str("")}, false},
		{Condition{Claim: "/sub"}, false},
	} {
		if got := tc.c.Match(fuzzClaims); got != tc.want {
			t.Errorf("%+v: got %v", tc.c, got)
		}
	}
	if MatchAll(nil, fuzzClaims) {
		t.Error("no conditions must not match")
	}
}

func TestGuardedClientDial(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := guardedClient(false).Get(srv.URL) // #nosec G107 -- テストのサーバー
	if !errors.Is(err, errNotPublic) {
		t.Fatalf("loopback: want errNotPublic, got %v", err)
	}
}
