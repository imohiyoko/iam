package ldap

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// FuzzLoginFilter は、どんな名前でも絞り込みが「設定の絞り込み AND (属性 = 名前)」の形のままで、名前が等しさの値にだけ入ることを確かめる
// （絞り込みの注入を防ぐ）。
func FuzzLoginFilter(f *testing.F) {
	for _, s := range []string{"alice", "*", "alice)(uid=*", "a\\2a", "(|(uid=*))", "\x00", "日本語", "a*b", ")"} {
		f.Add(s)
	}
	cfg := Config{UserFilter: "(objectClass=inetOrgPerson)", LoginAttribute: "uid"}
	f.Fuzz(func(t *testing.T, name string) {
		if !ValidUsername(name) {
			return
		}
		p, err := ldap.CompileFilter(loginFilter(cfg, name))
		if err != nil {
			t.Fatalf("filter for %q does not compile: %v", name, err)
		}
		if p.Tag != ldap.FilterAnd || len(p.Children) != 2 {
			t.Fatalf("filter for %q is not a two-term AND", name)
		}
		eq := p.Children[1]
		if eq.Tag != ldap.FilterEqualityMatch || len(eq.Children) != 2 {
			t.Fatalf("filter for %q: second term is not an equality match", name)
		}
		if got := eq.Children[0].Data.String(); got != "uid" {
			t.Fatalf("attribute = %q", got)
		}
		if got := eq.Children[1].Data.String(); got != name {
			t.Fatalf("value = %q, want %q", got, name)
		}
	})
}

// FuzzSubject は識別子の値が、空でなく、255 バイトまでの印字できる UTF-8 になるか、誤りになることを確かめる。
// 違う値が同じ subject にならないこと（単射）も確かめる。
func FuzzSubject(f *testing.F) {
	f.Add("objectGUID", []byte("0123456789abcdef"), []byte("0123456789abcdeg"))
	f.Add("entryUUID", []byte("x:00"), []byte{0})
	f.Add("entryUUID", []byte("abc"), []byte("abc\x00"))
	f.Fuzz(func(t *testing.T, attr string, a, b []byte) {
		sa, errA := subjectOf(attr, a)
		sb, errB := subjectOf(attr, b)
		for _, s := range []struct {
			v   string
			err error
		}{{sa, errA}, {sb, errB}} {
			if s.err != nil {
				continue
			}
			if s.v == "" || len(s.v) > 255 || !utf8.ValidString(s.v) {
				t.Fatalf("subject %q", s.v)
			}
		}
		if errA == nil && errB == nil && sa == sb && string(a) != string(b) {
			t.Fatalf("%x and %x map to the same subject %q", a, b, sa)
		}
	})
}

// FuzzGroupOf は所属の値の読み方が、base の下の DN だけを、名前の空でない Group として受けることを確かめる。
func FuzzGroupOf(f *testing.F) {
	for _, s := range []string{"cn=eng,ou=groups,dc=example,dc=com", "cn=x,ou=other,dc=example,dc=com", "ou=groups,dc=example,dc=com",
		"cn=a+sn=b,ou=groups,dc=example,dc=com", "cn=\\00,ou=groups,dc=example,dc=com", "cn=#0403616263,ou=groups,dc=example,dc=com", "=", ""} {
		f.Add(s)
	}
	base, err := ldap.ParseDN("ou=groups,dc=example,dc=com")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, dn string) {
		key, name, ok := groupOf(dn, base)
		if !ok {
			return
		}
		if name == "" || strings.TrimSpace(name) != name || !utf8.ValidString(name) || len(key) > maxDN {
			t.Fatalf("group %q: name %q key %q", dn, name, key)
		}
		d, err := ldap.ParseDN(dn)
		if err != nil || !base.AncestorOfFold(d) {
			t.Fatalf("accepted %q outside the base", dn)
		}
		// 鍵は正規化したもので、同じ DN の書き方の違いは同じ鍵になる。
		if k2, _, ok2 := groupOf(strings.ToUpper(dn), base); ok2 && strings.ToLower(dn) == dn && k2 != key && utf8.ValidString(dn) && !strings.Contains(dn, "\\") {
			t.Fatalf("key differs by case: %q vs %q", key, k2)
		}
	})
}
