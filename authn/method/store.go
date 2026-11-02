package method

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Store は port.CredentialStore の実装。realm と方式に閉じ、データはユーザーのデータ鍵で暗号化する（9.5）。
// 削除（データ鍵の消去）でクリプトシュレッドされる。
//
// Tx があればそのトランザクションで動く。無ければ操作ごとに Storage の短いトランザクションで動く（方式の重い計算を、直列にした
// トランザクションの外で行うため。ADR 0101）。書き込みは比較と交換なので、操作の間の別の書き込みは errs.Conflict になる。
type Store struct {
	Tx      port.Tx
	Storage port.Storage
	Crypter *pii.Crypter
	RealmID string
	Info    port.MethodInfo
	Now     time.Time
}

var _ port.CredentialStore = (*Store)(nil)

// do は fn を Tx か、Tx が無ければ短いトランザクションで呼ぶ。
func (s *Store) do(ctx context.Context, fn func(context.Context, port.Tx) error) error {
	if s.Tx != nil {
		return fn(ctx, s.Tx)
	}
	if s.Storage == nil {
		return errors.New("method: credential store has no transaction")
	}
	return s.Storage.Tx(ctx, fn)
}

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
	var out []port.MethodCredential
	err := s.do(ctx, func(ctx context.Context, tx port.Tx) error {
		out = nil
		cs, err := tx.Credentials().ListByUser(ctx, s.RealmID, userID, s.Info.Name)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.RevokedAt != nil {
				continue
			}
			mc, err := Open(ctx, tx, s.Crypter, c)
			if err != nil {
				return err
			}
			out = append(out, mc)
		}
		return nil
	})
	return out, err
}

func (s *Store) lookup(ctx context.Context, lookup string) (pii.Index, error) {
	return s.Crypter.Index(ctx, LookupPurpose(s.Info.Name), lookup)
}

// find は検索キーで有効な認証情報を引く。今のインデックス鍵で無ければ、有効な認証情報が使っている前の鍵でも引く
// （インデックス鍵の切り替えの後も、前に登録したものを使えるように。ADR 0092、0103）。
func (s *Store) find(ctx context.Context, tx port.Tx, lookup string, cur pii.Index) (port.Credential, error) {
	c, err := tx.Credentials().GetByLookup(ctx, s.RealmID, s.Info.Name, cur.Value)
	if err == nil || !errors.Is(err, errs.NotFound) {
		return c, err
	}
	kids, err := tx.Credentials().LookupKeyIDs(ctx, s.RealmID, s.Info.Name)
	if err != nil {
		return port.Credential{}, err
	}
	for _, kid := range kids {
		if kid == "" || kid == cur.KeyID {
			continue
		}
		ix, err := s.Crypter.IndexWith(ctx, kid, LookupPurpose(s.Info.Name), lookup)
		if errors.Is(err, errs.NotFound) {
			continue // 鍵を消した後のものは引けない（登録し直す）
		}
		if err != nil {
			return port.Credential{}, err
		}
		c, err := tx.Credentials().GetByLookup(ctx, s.RealmID, s.Info.Name, ix.Value)
		if err == nil || !errors.Is(err, errs.NotFound) {
			return c, err
		}
	}
	return port.Credential{}, errs.New(errs.KindNotFound, "credential")
}

// retired は検索キーが退役済みか（無効化した認証情報の検索キーを再登録させない方式。ADR 0106）を、今の鍵と、退役に使った前の
// 鍵で確かめる。Storage の Create も今の鍵の値で確かめる。
func (s *Store) retired(ctx context.Context, tx port.Tx, lookup string, cur pii.Index) (bool, error) {
	if !s.Info.ReserveRevokedLookups {
		return false, nil
	}
	if ok, err := tx.Credentials().LookupRetired(ctx, s.RealmID, s.Info.Name, cur.Value); err != nil || ok {
		return ok, err
	}
	kids, err := tx.Credentials().RetiredLookupKeyIDs(ctx, s.RealmID, s.Info.Name)
	if err != nil {
		return false, err
	}
	for _, kid := range kids {
		if kid == "" || kid == cur.KeyID {
			continue
		}
		ix, err := s.Crypter.IndexWith(ctx, kid, LookupPurpose(s.Info.Name), lookup)
		if errors.Is(err, errs.NotFound) {
			continue // 鍵を消した後のものは確かめられない（鍵の消去は運用の判断。ADR 0103）
		}
		if err != nil {
			return false, err
		}
		if ok, err := tx.Credentials().LookupRetired(ctx, s.RealmID, s.Info.Name, ix.Value); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
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
	var out port.MethodCredential
	err = s.do(ctx, func(ctx context.Context, tx port.Tx) error {
		c, err := s.find(ctx, tx, lookup, ix)
		if err != nil {
			return err
		}
		out, err = Open(ctx, tx, s.Crypter, c)
		return err
	})
	return out, err
}

// Create は認証情報を作る。検索キーが、今の鍵か前の鍵で作った有効なものと重なれば errs.Conflict。
func (s *Store) Create(ctx context.Context, userID, lookup string, data []byte) (port.MethodCredential, error) {
	c := port.Credential{ID: id.New(id.Credential), PublicID: id.NewExternal(id.Credential), RealmID: s.RealmID, UserID: userID,
		Method: s.Info.Name, DataVersion: s.Info.DataVersion, CreatedAt: s.Now, ReserveLookup: s.Info.ReserveRevokedLookups && lookup != ""}
	var ix pii.Index
	if lookup != "" {
		var err error
		if ix, err = s.lookup(ctx, lookup); err != nil {
			return port.MethodCredential{}, err
		}
		c.Lookup, c.LookupKeyID = ix.Value, ix.KeyID
	}
	err := s.do(ctx, func(ctx context.Context, tx port.Tx) error {
		if lookup != "" {
			if _, err := s.find(ctx, tx, lookup, ix); err == nil {
				return errs.New(errs.KindConflict, "credential lookup exists")
			} else if !errors.Is(err, errs.NotFound) {
				return err
			}
			if retired, err := s.retired(ctx, tx, lookup, ix); err != nil {
				return err
			} else if retired {
				return errs.New(errs.KindConflict, "credential lookup retired")
			}
		}
		ct, err := s.Crypter.Encrypt(ctx, tx.DataKeys(), userID, data, DataAAD(c.Method, c.ID))
		if err != nil {
			return err
		}
		c.Data = ct
		return tx.Credentials().Create(ctx, c)
	})
	if err != nil {
		return port.MethodCredential{}, err
	}
	return port.MethodCredential{ID: c.ID, PublicID: c.PublicID, UserID: userID, Data: data, DataVersion: c.DataVersion,
		CreatedAt: c.CreatedAt, Sealed: c.Data}, nil
}

// Update はデータを置き換える。読んだ後に別の書き込みか無効化があれば errs.Conflict。
func (s *Store) Update(ctx context.Context, c port.MethodCredential, data []byte) (port.MethodCredential, error) {
	if len(c.Sealed) == 0 {
		return port.MethodCredential{}, errors.New("method: update of a credential not read from the store")
	}
	var ct []byte
	err := s.do(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if ct, err = s.Crypter.Encrypt(ctx, tx.DataKeys(), c.UserID, data, DataAAD(s.Info.Name, c.ID)); err != nil {
			return err
		}
		return tx.Credentials().UpdateData(ctx, s.RealmID, c.ID, c.Sealed, ct, s.Info.DataVersion)
	})
	if err != nil {
		return port.MethodCredential{}, err
	}
	c.Data, c.DataVersion, c.Sealed = data, s.Info.DataVersion, ct
	return c, nil
}

// Revoke は認証情報を無効化する。読んだ後に別の書き込みか無効化があれば errs.Conflict（直列のトランザクションの中で比べる）。
func (s *Store) Revoke(ctx context.Context, c port.MethodCredential, reason string) error {
	if len(c.Sealed) == 0 {
		return errors.New("method: revoke of a credential not read from the store")
	}
	return s.do(ctx, func(ctx context.Context, tx port.Tx) error {
		cur, err := tx.Credentials().Get(ctx, s.RealmID, c.ID)
		if err != nil {
			return err
		}
		if cur.Method != s.Info.Name || cur.RevokedAt != nil || !bytes.Equal(cur.Data, c.Sealed) {
			return errs.New(errs.KindConflict, "credential changed")
		}
		return tx.Credentials().Revoke(ctx, s.RealmID, c.ID, s.Now, reason)
	})
}
