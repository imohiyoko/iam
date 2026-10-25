package pii

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

type keys struct {
	master, index map[string][]byte
	mkid, ikid    string
}

func newKeys() *keys {
	k := &keys{master: map[string][]byte{}, index: map[string][]byte{}, mkid: "mk1", ikid: "ik1"}
	k.master["mk1"], k.index["ik1"] = random(), random()
	return k
}

func random() []byte { b := make([]byte, KeySize); rand.Read(b); return b }

func (k *keys) MasterKey(_ context.Context, id string) ([]byte, error) {
	if v, ok := k.master[id]; ok {
		return v, nil
	}
	return nil, errs.NotFound
}
func (k *keys) CurrentMasterKeyID(context.Context) (string, error) { return k.mkid, nil }
func (k *keys) IndexKey(_ context.Context, id string) ([]byte, error) {
	if v, ok := k.index[id]; ok {
		return v, nil
	}
	return nil, errs.NotFound
}
func (k *keys) CurrentIndexKeyID(context.Context) (string, error) { return k.ikid, nil }

type dataKeys map[string]port.DataKey

func (d dataKeys) Create(_ context.Context, k port.DataKey) error {
	if _, ok := d[k.UserID]; ok {
		return errs.Conflict
	}
	d[k.UserID] = k
	return nil
}
func (d dataKeys) Get(_ context.Context, u string) (port.DataKey, error) {
	if k, ok := d[u]; ok {
		return k, nil
	}
	return port.DataKey{}, errs.NotFound
}
func (d dataKeys) Delete(_ context.Context, u string) error { delete(d, u); return nil }

func TestEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	c, repo := New(newKeys()), dataKeys{}
	if err := c.CreateDataKey(ctx, repo, "usr_a", time.Now()); err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt(ctx, repo, "usr_a", []byte("alice@example.com"), "user_emails.email")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("alice")) {
		t.Fatal("plaintext leaked")
	}
	pt, err := c.Decrypt(ctx, repo, "usr_a", ct, "user_emails.email")
	if err != nil || string(pt) != "alice@example.com" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	// 用途（AAD）が違えば復号できない。
	if _, err := c.Decrypt(ctx, repo, "usr_a", ct, "users.display_name"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong purpose: %v", err)
	}
}

// データ鍵を消すと、そのユーザーの暗号化データが復号できなくなる（roadmap M0 の完了条件）。
func TestCryptoShredding(t *testing.T) {
	ctx := context.Background()
	c, repo := New(newKeys()), dataKeys{}
	for _, u := range []string{"usr_a", "usr_b"} {
		if err := c.CreateDataKey(ctx, repo, u, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	ctA, _ := c.Encrypt(ctx, repo, "usr_a", []byte("a@example.com"), "x")
	ctB, _ := c.Encrypt(ctx, repo, "usr_b", []byte("b@example.com"), "x")

	if err := repo.Delete(ctx, "usr_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(ctx, repo, "usr_a", ctA, "x"); !errors.Is(err, ErrShredded) {
		t.Fatalf("want ErrShredded, got %v", err)
	}
	// 新しいデータ鍵を作っても、古い暗号文は戻らない。
	if err := c.CreateDataKey(ctx, repo, "usr_a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(ctx, repo, "usr_a", ctA, "x"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
	// ほかのユーザーには影響しない。
	if pt, err := c.Decrypt(ctx, repo, "usr_b", ctB, "x"); err != nil || string(pt) != "b@example.com" {
		t.Fatalf("other user: %q, %v", pt, err)
	}
}

// 別のユーザーのデータ鍵の暗号文を差し替えても使えない。
func TestWrappedKeyBoundToUser(t *testing.T) {
	ctx := context.Background()
	c, repo := New(newKeys()), dataKeys{}
	c.CreateDataKey(ctx, repo, "usr_a", time.Now())
	c.CreateDataKey(ctx, repo, "usr_b", time.Now())
	ctA, _ := c.Encrypt(ctx, repo, "usr_a", []byte("secret"), "x")
	b := repo["usr_b"]
	b.WrappedKey = repo["usr_a"].WrappedKey
	repo["usr_b"] = b
	if _, err := c.Decrypt(ctx, repo, "usr_b", ctA, "x"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestMasterKeyRotation(t *testing.T) {
	ctx := context.Background()
	k := newKeys()
	c, repo := New(k), dataKeys{}
	c.CreateDataKey(ctx, repo, "usr_a", time.Now())
	ct, _ := c.Encrypt(ctx, repo, "usr_a", []byte("v"), "x")
	k.master["mk2"], k.mkid = random(), "mk2"
	c.CreateDataKey(ctx, repo, "usr_b", time.Now())
	if repo["usr_b"].KeyID != "mk2" {
		t.Fatal("new data key should use current master key")
	}
	if pt, err := c.Decrypt(ctx, repo, "usr_a", ct, "x"); err != nil || string(pt) != "v" {
		t.Fatalf("old data key: %q, %v", pt, err)
	}
}

func TestBlindIndex(t *testing.T) {
	ctx := context.Background()
	k := newKeys()
	c := New(k)
	a, _ := c.EmailIndex(ctx, " Alice@Example.COM ")
	b, _ := c.EmailIndex(ctx, "alice@example.com")
	if !bytes.Equal(a.Value, b.Value) || a.KeyID != "ik1" {
		t.Fatal("index should be case-insensitive")
	}
	plus, _ := c.EmailIndex(ctx, "alice+x@example.com")
	if bytes.Equal(a.Value, plus.Value) {
		t.Fatal("plus addressing must not be normalized")
	}
	d1, _ := c.DomainIndex(ctx, "alice@example.com")
	d2, _ := c.DomainIndex(ctx, "bob@EXAMPLE.com")
	if !bytes.Equal(d1.Value, d2.Value) {
		t.Fatal("domain index mismatch")
	}
	// メールとドメインで用途が分かれている。
	dom, _ := c.IndexWith(ctx, "ik1", "email", "example.com")
	if bytes.Equal(dom.Value, d1.Value) {
		t.Fatal("purposes must be separated")
	}
	if _, err := c.DomainIndex(ctx, "no-at-sign"); !errors.Is(err, errs.Invalid) {
		t.Fatalf("want invalid, got %v", err)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	ctx := context.Background()
	c, repo := New(newKeys()), dataKeys{}
	c.CreateDataKey(ctx, repo, "usr_a", time.Now())
	ct, _ := c.Encrypt(ctx, repo, "usr_a", []byte("alice@example.com"), "x")
	for b.Loop() {
		if _, err := c.Decrypt(ctx, repo, "usr_a", ct, "x"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEmailIndex(b *testing.B) {
	ctx := context.Background()
	c := New(newKeys())
	for b.Loop() {
		if _, err := c.EmailIndex(ctx, "alice@example.com"); err != nil {
			b.Fatal(err)
		}
	}
}
