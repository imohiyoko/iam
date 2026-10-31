package keyfile

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateWriteLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, k); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, k); err == nil {
		t.Fatal("must not overwrite existing keys")
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mid, _ := s.CurrentMasterKeyID(ctx)
	iid, _ := s.CurrentIndexKeyID(ctx)
	mk, err := s.MasterKey(ctx, mid)
	if err != nil || len(mk) != KeySize {
		t.Fatalf("master key: %v", err)
	}
	ik, _ := s.IndexKey(ctx, iid)
	if string(ik) == string(mk) {
		t.Fatal("master and index keys must differ")
	}
	if _, err := s.MasterKey(ctx, iid); err == nil {
		t.Fatal("index key id must not resolve as master key")
	}
	// 新しく作る鍵の組には監査の鍵（ADR 0086）も入る。
	aid, _ := s.CurrentAuditKeyID(ctx)
	if ak, err := s.AuditKey(ctx, aid); err != nil || len(ak) != KeySize || string(ak) == string(mk) || string(ak) == string(ik) {
		t.Fatalf("audit key %q: %v", aid, err)
	}
}

// 監査の鍵は省ける（鍵なしのチェーン）。置くなら current が要る。
func TestAuditKeyOptional(t *testing.T) {
	k, _ := Generate()
	ak := k.AuditKeys[k.CurrentAuditKey]
	k.CurrentAuditKey, k.AuditKeys = "", nil
	s, err := FromKeys(k)
	if err != nil {
		t.Fatal(err)
	}
	if aid, err := s.CurrentAuditKeyID(context.Background()); err != nil || aid != "" {
		t.Fatalf("no audit key: %q, %v", aid, err)
	}
	k.AuditKeys = map[string]string{"ak_old": ak}
	if _, err := FromKeys(k); err == nil {
		t.Fatal("audit keys without current must be rejected")
	}
	k.CurrentAuditKey, k.AuditKeys = k.CurrentMasterKey, map[string]string{k.CurrentMasterKey: ak}
	if _, err := FromKeys(k); err == nil {
		t.Fatal("audit key id shared with a master key must be rejected")
	}
}

// audit_unkeyed_until は監査の鍵があるときだけ書ける（ADR 0086）。
func TestAuditUnkeyedUntil(t *testing.T) {
	k, _ := Generate()
	k.AuditUnkeyedUntil = 42
	s, err := FromKeys(k)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.AuditUnkeyedUntil(context.Background()); err != nil || n != 42 {
		t.Fatalf("AuditUnkeyedUntil = %d, %v", n, err)
	}
	k.AuditUnkeyedUntil = -1
	if _, err := FromKeys(k); err == nil {
		t.Fatal("negative audit_unkeyed_until must be rejected")
	}
	k.AuditUnkeyedUntil, k.CurrentAuditKey, k.AuditKeys = 42, "", nil
	if _, err := FromKeys(k); err == nil {
		t.Fatal("audit_unkeyed_until without an audit key must be rejected")
	}
}

func TestRejectLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	k, _ := Generate()
	Write(path, k)
	os.Chmod(path, 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("must reject world-readable key file")
	}
}

func TestRejectInvalidKeys(t *testing.T) {
	cases := map[string]Keys{
		"missing current": {CurrentMasterKey: "a", MasterKeys: map[string]string{}, CurrentIndexKey: "b", IndexKeys: map[string]string{"b": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		"short key":       {CurrentMasterKey: "a", MasterKeys: map[string]string{"a": "AAAA"}, CurrentIndexKey: "b", IndexKeys: map[string]string{"b": "AAAA"}},
	}
	for name, k := range cases {
		if _, err := FromKeys(k); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
