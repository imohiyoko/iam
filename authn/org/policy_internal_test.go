package org

import (
	"slices"
	"testing"
)

func TestCheckPolicyMappedCIDR(t *testing.T) {
	s := &Service{LoginPolicies: true}
	out, err := s.checkPolicy(&LoginPolicy{IPAllowlist: []string{"::ffff:192.0.2.0/120", "192.0.2.0/24"}}, nil)
	if err != nil || !slices.Equal(out.IPAllowlist, []string{"192.0.2.0/24"}) {
		t.Fatalf("checkPolicy = %v, %v", out, err)
	}
	if !ipAllowed("::ffff:192.0.2.1", out.IPAllowlist) || !ipAllowed("192.0.2.1", out.IPAllowlist) {
		t.Fatal("192.0.2.1 should be allowed")
	}
	if _, err := s.checkPolicy(&LoginPolicy{IPAllowlist: []string{"::ffff:0.0.0.0/95"}}, nil); err == nil {
		t.Fatal("a mapped prefix shorter than /96 should be rejected")
	}
}

func TestCheckPolicyFeatureOffKeepsStored(t *testing.T) {
	s := &Service{}
	prev := &LoginPolicy{RequirePasskey: true, IPAllowlist: []string{"10.0.0.0/8"}}
	// 止めている間も、保存済みのポリシーをそのまま残す更新は受ける（入力の書き方が違っても正規化して比べる）。
	if out, err := s.checkPolicy(&LoginPolicy{RequirePasskey: true, IPAllowlist: []string{" 10.1.2.3/8 "}}, prev); err != nil || out == nil {
		t.Fatalf("keep stored: %v, %v", out, err)
	}
	// 新しいポリシー・変えたポリシーは受けない。
	for _, p := range []*LoginPolicy{{RequirePasskey: true}, {RequirePasskey: true, IPAllowlist: []string{"10.0.0.0/8", "192.0.2.0/24"}}} {
		if _, err := s.checkPolicy(p, prev); err == nil {
			t.Fatalf("changed policy %v should be rejected", p)
		}
		if _, err := s.checkPolicy(p, nil); err == nil {
			t.Fatalf("new policy %v should be rejected", p)
		}
	}
	// 外すのは受ける。
	if out, err := s.checkPolicy(nil, prev); err != nil || out != nil {
		t.Fatalf("remove: %v, %v", out, err)
	}
}
