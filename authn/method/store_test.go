package method_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// rotatingKeys はインデックス鍵を切り替えられる KeyStore。
type rotatingKeys struct {
	index   map[string][]byte
	current string
}

func (k *rotatingKeys) MasterKey(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{1}, pii.KeySize), nil
}
func (k *rotatingKeys) CurrentMasterKeyID(context.Context) (string, error) { return "mk_1", nil }
func (k *rotatingKeys) IndexKey(_ context.Context, kid string) ([]byte, error) {
	if b, ok := k.index[kid]; ok {
		return b, nil
	}
	return nil, errs.New(errs.KindNotFound, "index key")
}
func (k *rotatingKeys) CurrentIndexKeyID(context.Context) (string, error) { return k.current, nil }

// インデックス鍵を切り替えた後も、前の鍵で作った検索キーで引け、同じ値を重ねて登録できない（ADR 0092、0103）。
func TestStoreLookupSurvivesIndexKeyRotation(t *testing.T) {
	ctx := context.Background()
	keys := &rotatingKeys{index: map[string][]byte{"ik_1": bytes.Repeat([]byte{2}, pii.KeySize)}, current: "ik_1"}
	st := testkit.New(t).Storage
	realm, alice, bob := id.New(id.Realm), id.New(id.User), id.New(id.User)
	info := port.MethodInfo{Name: "x509", Feature: "x509", Kind: port.FactorPossession, AMR: []string{"pop"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageFirstFactor}, DataVersion: 1}
	run := func(fn func(s *method.Store) error) error {
		return st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			return fn(&method.Store{Tx: tx, Crypter: pii.New(keys), RealmID: realm, Info: info, Now: time.Now()})
		})
	}
	var created port.MethodCredential
	if err := run(func(s *method.Store) (err error) {
		for _, u := range []string{alice, bob} {
			if err := s.Crypter.CreateDataKey(ctx, s.Tx.DataKeys(), u, s.Now); err != nil {
				return err
			}
		}
		created, err = s.Create(ctx, alice, "sha256:aa", []byte(`{}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	keys.index["ik_2"], keys.current = bytes.Repeat([]byte{3}, pii.KeySize), "ik_2"
	if err := run(func(s *method.Store) error {
		got, err := s.FindByLookup(ctx, "sha256:aa")
		if err != nil || got.ID != created.ID {
			t.Errorf("FindByLookup after rotation = %+v, %v", got, err)
		}
		if _, err := s.Create(ctx, bob, "sha256:aa", []byte(`{}`)); !errors.Is(err, errs.Conflict) {
			t.Errorf("duplicate under the old key = %v, want conflict", err)
		}
		if _, err := s.FindByLookup(ctx, "sha256:bb"); !errors.Is(err, errs.NotFound) {
			t.Errorf("unknown lookup = %v", err)
		}
		c, err := s.Create(ctx, bob, "sha256:bb", []byte(`{}`))
		if err != nil {
			return err
		}
		raw, err := s.Tx.Credentials().Get(ctx, realm, c.ID)
		if err != nil || raw.LookupKeyID != "ik_2" {
			t.Errorf("new credential lookup key = %q, %v", raw.LookupKeyID, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 前の鍵を消すと、その鍵で作った検索キーでは引けない（登録し直す）。
	delete(keys.index, "ik_1")
	if err := run(func(s *method.Store) error {
		if _, err := s.FindByLookup(ctx, "sha256:aa"); !errors.Is(err, errs.NotFound) {
			t.Errorf("lookup with a removed key = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
