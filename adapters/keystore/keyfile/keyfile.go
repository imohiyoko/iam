// Package keyfile は鍵の組の読み込み・検証・生成を持つ（file と env の KeyStore アダプタが共有する）。
// アダプタの登録はしないので、import しても KeyStore は増えない。
//
// 形式（JSON。鍵は base64 の 32 バイト）:
//
//	{
//	  "current_master_key": "mk_…", "master_keys": {"mk_…": "…"},
//	  "current_index_key":  "ik_…", "index_keys":  {"ik_…": "…"},
//	  "current_audit_key":  "ak_…", "audit_keys":  {"ak_…": "…"},
//	  "audit_unkeyed_until": 0
//	}
//
// 監査の鍵（監査ログのハッシュチェーン。ADR 0086）は省ける。省けばチェーンは鍵なし。audit_unkeyed_until は鍵なしで許す
// 最後の seq（鍵を置く前からの監査ログがあるときだけ書く）。
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
	CurrentMasterKey  string            `json:"current_master_key"`
	MasterKeys        map[string]string `json:"master_keys"`
	CurrentIndexKey   string            `json:"current_index_key"`
	IndexKeys         map[string]string `json:"index_keys"`
	CurrentAuditKey   string            `json:"current_audit_key,omitempty"`
	AuditKeys         map[string]string `json:"audit_keys,omitempty"`
	AuditUnkeyedUntil int64             `json:"audit_unkeyed_until,omitempty"`
}

// Store はメモリに読み込んだ鍵。
type Store struct {
	masterID, indexID, auditID string
	master, index, audit       map[string][]byte
	auditUnkeyed               int64
}

var (
	_ port.KeyStore      = (*Store)(nil)
	_ port.AuditKeyStore = (*Store)(nil)
)

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
	s := &Store{masterID: k.CurrentMasterKey, indexID: k.CurrentIndexKey, auditID: k.CurrentAuditKey, auditUnkeyed: k.AuditUnkeyedUntil}
	var err error
	if s.master, err = decodeAll("master", k.MasterKeys); err != nil {
		return nil, err
	}
	if s.index, err = decodeAll("index", k.IndexKeys); err != nil {
		return nil, err
	}
	if s.audit, err = decodeAll("audit", k.AuditKeys); err != nil {
		return nil, err
	}
	if _, ok := s.master[s.masterID]; !ok {
		return nil, fmt.Errorf("keystore: current master key %q not found", s.masterID)
	}
	if _, ok := s.index[s.indexID]; !ok {
		return nil, fmt.Errorf("keystore: current index key %q not found", s.indexID)
	}
	// 監査の鍵は省けるが、古い鍵だけを残して current を外すと、チェーンが鍵なしに戻って検証できなくなる。
	if _, ok := s.audit[s.auditID]; !ok && (s.auditID != "" || len(s.audit) > 0) {
		return nil, fmt.Errorf("keystore: current audit key %q not found", s.auditID)
	}
	if s.auditUnkeyed < 0 || (s.auditUnkeyed > 0 && s.auditID == "") {
		return nil, fmt.Errorf("keystore: audit_unkeyed_until %d needs a current audit key and must not be negative", s.auditUnkeyed)
	}
	seen := map[string]string{}
	for kind, keys := range map[string]map[string][]byte{"master": s.master, "index": s.index, "audit": s.audit} {
		for kid := range keys {
			if other, dup := seen[kid]; dup {
				return nil, fmt.Errorf("keystore: key id %q is used for both %s and %s keys", kid, other, kind)
			}
			seen[kid] = kind
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

func (s *Store) AuditKey(_ context.Context, kid string) ([]byte, error) {
	if k, ok := s.audit[kid]; ok {
		return k, nil
	}
	return nil, errs.New(errs.KindNotFound, "audit key %q", kid)
}

// CurrentAuditKeyID は監査の鍵を置いていなければ空を返す。
func (s *Store) CurrentAuditKeyID(context.Context) (string, error) { return s.auditID, nil }

// AuditUnkeyedUntil は鍵なしで許す最後の seq を返す（書いていなければ 0。先頭から鍵付き）。
func (s *Store) AuditUnkeyedUntil(context.Context) (int64, error) { return s.auditUnkeyed, nil }

// Generate は新しい鍵の組（マスター・インデックス・監査）を作る（`iam keys generate`）。
func Generate() (Keys, error) {
	mk, ik, ak := make([]byte, KeySize), make([]byte, KeySize), make([]byte, KeySize)
	for _, b := range [][]byte{mk, ik, ak} {
		if _, err := rand.Read(b); err != nil {
			return Keys{}, err
		}
	}
	mid, iid, aid := id.NewExternal(id.MasterKey), id.NewExternal(id.IndexKey), id.NewExternal(id.AuditKey)
	return Keys{
		CurrentMasterKey: mid, MasterKeys: map[string]string{mid: base64.StdEncoding.EncodeToString(mk)},
		CurrentIndexKey: iid, IndexKeys: map[string]string{iid: base64.StdEncoding.EncodeToString(ik)},
		CurrentAuditKey: aid, AuditKeys: map[string]string{aid: base64.StdEncoding.EncodeToString(ak)},
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
