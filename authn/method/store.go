package method

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Store は port.CredentialStore の実装。トランザクションと realm と方式に閉じ、データはユーザーのデータ鍵で暗号化する（9.5）。
// 削除（データ鍵の消去）でクリプトシュレッドされる。
type Store struct {
	Tx      port.Tx
	Crypter *pii.Crypter
	RealmID string
	Info    port.MethodInfo
	Now     time.Time
}

var _ port.CredentialStore = (*Store)(nil)

// DataAAD は方式固有のデータの暗号文の AAD の用途。認証情報の ID に結び付け、別の認証情報のデータと入れ替えられないようにする。
func DataAAD(method, credentialID string) string {
	return "authn.credential." + method + "." + credentialID
}

// LookupPurpose は検索キーのブラインドインデックスの用途（方式ごとに分ける）。
func LookupPurpose(method string) string { return "authn.credential." + method }

// Open は認証情報のデータを復号し、方式に渡す形にする。
func Open(ctx context.Context, tx port.Tx, crypter *pii.Crypter, c port.Credential) (port.MethodCredential, error) {
	pt, err := crypter.Decrypt(ctx, tx.DataKeys(), c.UserID, c.Data, DataAAD(c.Method, c.ID))
	if err != nil {
		return port.MethodCredential{}, fmt.Errorf("method: open credential: %w", err)
	}
	return port.MethodCredential{ID: c.ID, PublicID: c.PublicID, UserID: c.UserID, Data: pt, DataVersion: c.DataVersion,
		CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt, Sealed: c.Data}, nil
}

// Reseal は認証情報のデータを別のユーザーのデータ鍵で暗号化し直す（統合。11.6）。
func Reseal(ctx context.Context, tx port.Tx, crypter *pii.Crypter, c port.Credential, toUserID string) ([]byte, error) {
	pt, err := crypter.Decrypt(ctx, tx.DataKeys(), c.UserID, c.Data, DataAAD(c.Method, c.ID))
	if err != nil {
		return nil, err
	}
	return crypter.Encrypt(ctx, tx.DataKeys(), toUserID, pt, DataAAD(c.Method, c.ID))
}

// List はユーザーの、この方式の有効な認証情報を復号して返す。
func (s *Store) List(ctx context.Context, userID string) ([]port.MethodCredential, error) {
	cs, err := s.Tx.Credentials().ListByUser(ctx, s.RealmID, userID, s.Info.Name)
	if err != nil {
		return nil, err
	}
	var out []port.MethodCredential
	for _, c := range cs {
		if c.RevokedAt != nil {
			continue
		}
		mc, err := Open(ctx, s.Tx, s.Crypter, c)
		if err != nil {
			return nil, err
		}
		out = append(out, mc)
	}
	return out, nil
}

func (s *Store) lookup(ctx context.Context, lookup string) ([]byte, error) {
	ix, err := s.Crypter.Index(ctx, LookupPurpose(s.Info.Name), lookup)
	if err != nil {
		return nil, err
	}
	return ix.Value, nil
}

// FindByLookup は検索キーで有効な認証情報を返す。持ち主が active でなくても返す（呼び出し側が状態を確かめる）。
func (s *Store) FindByLookup(ctx context.Context, lookup string) (port.MethodCredential, error) {
	if lookup == "" {
		return port.MethodCredential{}, errs.New(errs.KindNotFound, "credential")
	}
	ix, err := s.lookup(ctx, lookup)
	if err != nil {
		return port.MethodCredential{}, err
	}
	c, err := s.Tx.Credentials().GetByLookup(ctx, s.RealmID, s.Info.Name, ix)
	if err != nil {
		return port.MethodCredential{}, err
	}
	return Open(ctx, s.Tx, s.Crypter, c)
}

// Create は認証情報を作る。
func (s *Store) Create(ctx context.Context, userID, lookup string, data []byte) (port.MethodCredential, error) {
	c := port.Credential{ID: id.New(id.Credential), PublicID: id.NewExternal(id.Credential), RealmID: s.RealmID, UserID: userID,
		Method: s.Info.Name, DataVersion: s.Info.DataVersion, CreatedAt: s.Now}
	if lookup != "" {
		ix, err := s.lookup(ctx, lookup)
		if err != nil {
			return port.MethodCredential{}, err
		}
		c.Lookup = ix
	}
	ct, err := s.Crypter.Encrypt(ctx, s.Tx.DataKeys(), userID, data, DataAAD(c.Method, c.ID))
	if err != nil {
		return port.MethodCredential{}, err
	}
	c.Data = ct
	if err := s.Tx.Credentials().Create(ctx, c); err != nil {
		return port.MethodCredential{}, err
	}
	return port.MethodCredential{ID: c.ID, PublicID: c.PublicID, UserID: userID, Data: data, DataVersion: c.DataVersion,
		CreatedAt: c.CreatedAt, Sealed: ct}, nil
}

// Update はデータを置き換える。読んだ後に別の書き込みか無効化があれば errs.Conflict。
func (s *Store) Update(ctx context.Context, c port.MethodCredential, data []byte) (port.MethodCredential, error) {
	if len(c.Sealed) == 0 {
		return port.MethodCredential{}, errors.New("method: update of a credential not read from the store")
	}
	ct, err := s.Crypter.Encrypt(ctx, s.Tx.DataKeys(), c.UserID, data, DataAAD(s.Info.Name, c.ID))
	if err != nil {
		return port.MethodCredential{}, err
	}
	if err := s.Tx.Credentials().UpdateData(ctx, s.RealmID, c.ID, c.Sealed, ct, s.Info.DataVersion); err != nil {
		return port.MethodCredential{}, err
	}
	c.Data, c.DataVersion, c.Sealed = data, s.Info.DataVersion, ct
	return c, nil
}
