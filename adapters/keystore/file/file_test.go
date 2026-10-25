package file

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
