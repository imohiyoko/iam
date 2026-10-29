// Package keyfile は鍵の組の読み込み・検証・生成を持つ（file と env の KeyStore アダプタが共有する）。
// アダプタの登録はしないので、import しても KeyStore は増えない。
//
// 形式（JSON。鍵は base64 の 32 バイト）:
//
//	{
//	  "current_master_key": "mk_…", "master_keys": {"mk_…": "…"},
//	  "current_index_key":  "ik_…", "index_keys":  {"ik_…": "…"}
//	}
//
// ファイルは所有者だけが読める権限（0600 など）でなければ読み込みを拒否する。
// 鍵を失うと暗号化データは復元できないため、バックアップの手順を運用文書に含める（design.md 9.5）。
package keyfile

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// KeySize は鍵の長さ（AES-256 / HMAC-SHA-256）。
const KeySize = 32

// Keys はファイルの中身。
type Keys struct {
	CurrentMasterKey string            `json:"current_master_key"`
	MasterKeys       map[string]string `json:"master_keys"`
	CurrentIndexKey  string            `json:"current_index_key"`
	IndexKeys        map[string]string `json:"index_keys"`
}

// Store はメモリに読み込んだ鍵。
type Store struct {
	masterID, indexID string
	master, index     map[string][]byte
}

var _ port.KeyStore = (*Store)(nil)

// Load は path から鍵を読み込む。
func Load(path string) (*Store, error) {
	f, err := os.Open(path) // #nosec G304 -- パスはホスト先の設定ファイルで指定する
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// 開いたファイルそのものの権限を見る（確認と読み込みの間に差し替えられないように）。
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore file: %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore file: %s must not be readable by group or others (mode %v)", path, fi.Mode().Perm())
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var k Keys
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("keystore file: %w", err)
	}
	return FromKeys(k)
}

// FromKeys は Keys を検証して Store にする（環境変数のアダプタも使う）。
func FromKeys(k Keys) (*Store, error) {
	s := &Store{masterID: k.CurrentMasterKey, indexID: k.CurrentIndexKey}
	var err error
	if s.master, err = decodeAll("master", k.MasterKeys); err != nil {
		return nil, err
	}
	if s.index, err = decodeAll("index", k.IndexKeys); err != nil {
		return nil, err
	}
	if _, ok := s.master[s.masterID]; !ok {
		return nil, fmt.Errorf("keystore: current master key %q not found", s.masterID)
	}
	if _, ok := s.index[s.indexID]; !ok {
		return nil, fmt.Errorf("keystore: current index key %q not found", s.indexID)
	}
	for kid := range s.master {
		if _, dup := s.index[kid]; dup {
			return nil, fmt.Errorf("keystore: key id %q is used for both master and index keys", kid)
		}
	}
	return s, nil
}

func decodeAll(kind string, in map[string]string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for kid, v := range in {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(b) != KeySize {
			return nil, fmt.Errorf("keystore: %s key %q must be %d bytes of base64", kind, kid, KeySize)
		}
		out[kid] = b
	}
	return out, nil
}

func (s *Store) MasterKey(_ context.Context, kid string) ([]byte, error) {
	if k, ok := s.master[kid]; ok {
		return k, nil
	}
	return nil, errs.New(errs.KindNotFound, "master key %q", kid)
}

func (s *Store) CurrentMasterKeyID(context.Context) (string, error) { return s.masterID, nil }

func (s *Store) IndexKey(_ context.Context, kid string) ([]byte, error) {
	if k, ok := s.index[kid]; ok {
		return k, nil
	}
	return nil, errs.New(errs.KindNotFound, "index key %q", kid)
}

func (s *Store) CurrentIndexKeyID(context.Context) (string, error) { return s.indexID, nil }

// Generate は新しい鍵の組を作る（`iam keys generate`）。
func Generate() (Keys, error) {
	mk, ik := make([]byte, KeySize), make([]byte, KeySize)
	if _, err := rand.Read(mk); err != nil {
		return Keys{}, err
	}
	if _, err := rand.Read(ik); err != nil {
		return Keys{}, err
	}
	mid, iid := id.NewExternal(id.MasterKey), id.NewExternal(id.IndexKey)
	return Keys{
		CurrentMasterKey: mid, MasterKeys: map[string]string{mid: base64.StdEncoding.EncodeToString(mk)},
		CurrentIndexKey: iid, IndexKeys: map[string]string{iid: base64.StdEncoding.EncodeToString(ik)},
	}, nil
}

// Write は鍵を path に所有者だけが読める権限で書く。既にあれば上書きしない。
func Write(path string, k Keys) error {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
