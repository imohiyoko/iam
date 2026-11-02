// Package methodtest は認証方式のテスト用の部品を持つ。
package methodtest

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Store は port.CredentialStore のテスト用の実装。暗号化せず、Sealed にデータの写しを入れて比較と交換を真似る。
type Store struct {
	Creds   []port.MethodCredential
	Revoked []string
	n       int
}

var _ port.CredentialStore = (*Store)(nil)

// List は有効な認証情報を返す。
func (f *Store) List(_ context.Context, userID string) ([]port.MethodCredential, error) {
	var out []port.MethodCredential
	for _, c := range f.Creds {
		if c.UserID == userID && !slices.Contains(f.Revoked, c.ID) {
			out = append(out, c)
		}
	}
	return out, nil
}

// FindByLookup は使わない。
func (f *Store) FindByLookup(context.Context, string) (port.MethodCredential, error) {
	return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
}

// Create は認証情報を足す。
func (f *Store) Create(_ context.Context, userID, _ string, data []byte) (port.MethodCredential, error) {
	f.n++
	c := port.MethodCredential{ID: fmt.Sprintf("crd_%d", f.n), PublicID: fmt.Sprintf("crd_pub%d", f.n), UserID: userID, Data: bytes.Clone(data),
		Sealed: bytes.Clone(data), CreatedAt: time.Unix(int64(f.n), 0)}
	f.Creds = append(f.Creds, c)
	return c, nil
}

func (f *Store) find(c port.MethodCredential) (int, error) {
	for i, x := range f.Creds {
		if x.ID == c.ID {
			if !bytes.Equal(x.Sealed, c.Sealed) || slices.Contains(f.Revoked, c.ID) {
				return 0, errs.New(errs.KindConflict, "changed")
			}
			return i, nil
		}
	}
	return 0, errs.New(errs.KindNotFound, "credential")
}

// Update は比較と交換で置き換える。
func (f *Store) Update(_ context.Context, c port.MethodCredential, data []byte) (port.MethodCredential, error) {
	i, err := f.find(c)
	if err != nil {
		return port.MethodCredential{}, err
	}
	x := f.Creds[i]
	x.Data, x.Sealed = bytes.Clone(data), bytes.Clone(data)
	f.Creds[i] = x
	return x, nil
}

// Revoke は比較して無効化する。
func (f *Store) Revoke(_ context.Context, c port.MethodCredential, _ string) error {
	if _, err := f.find(c); err != nil {
		return err
	}
	f.Revoked = append(f.Revoked, c.ID)
	return nil
}
