// Package pii は個人情報の暗号化とブラインドインデックスを扱う（design.md 9.5）。
//
//   - 個人情報はユーザーごとのデータ鍵（AES-256-GCM）で暗号化する
//   - データ鍵は KeyStore のマスター鍵で包んで Storage に置く（エンベロープ暗号化）
//   - データ鍵を消すと、そのユーザーの暗号文は復号できなくなる（crypto-shredding）
//   - 検索はブラインドインデックス（HMAC-SHA-256）で行う。暗号化とは別の鍵を使う
//
// 暗号は Go 標準ライブラリのみを使う（design.md 13.2）。
package pii

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// KeySize は AES-256 の鍵の長さ。
const KeySize = 32

// ciphertextVersion は暗号文の先頭に付ける形式のバージョン。
const ciphertextVersion byte = 1

var (
	// ErrShredded はデータ鍵が削除済みで復号できないことを表す。
	ErrShredded = errors.New("pii: data key deleted")
	// ErrDecrypt は暗号文が壊れているか、鍵・文脈が違うことを表す。
	ErrDecrypt = errors.New("pii: decryption failed")
)

// Crypter は KeyStore を使ってデータ鍵とインデックスを扱う。
type Crypter struct {
	keys port.KeyStore
}

// New は Crypter を返す。
func New(keys port.KeyStore) *Crypter { return &Crypter{keys: keys} }

// CreateDataKey はユーザーのデータ鍵を作り、マスター鍵で包んで保存する。
// ユーザーの作成と同じトランザクションで呼ぶ。
func (c *Crypter) CreateDataKey(ctx context.Context, repo port.DataKeyRepo, userID string, now time.Time) error {
	dk := make([]byte, KeySize)
	if _, err := rand.Read(dk); err != nil {
		return err
	}
	kid, err := c.keys.CurrentMasterKeyID(ctx)
	if err != nil {
		return err
	}
	mk, err := c.keys.MasterKey(ctx, kid)
	if err != nil {
		return err
	}
	wrapped, err := seal(mk, dk, wrapAAD(userID, kid))
	if err != nil {
		return err
	}
	return repo.Create(ctx, port.DataKey{UserID: userID, WrappedKey: wrapped, KeyID: kid, CreatedAt: now})
}

// Encrypt はユーザーのデータ鍵で plaintext を暗号化する。
// aad には用途（"user_emails.email" など）を入れ、暗号文を別の列に移しても復号できないようにする。
func (c *Crypter) Encrypt(ctx context.Context, repo port.DataKeyRepo, userID string, plaintext []byte, aad string) ([]byte, error) {
	dk, err := c.dataKey(ctx, repo, userID)
	if err != nil {
		return nil, err
	}
	return seal(dk, plaintext, valueAAD(userID, aad))
}

// Decrypt は Encrypt の逆。データ鍵が削除済みなら ErrShredded を返す。
func (c *Crypter) Decrypt(ctx context.Context, repo port.DataKeyRepo, userID string, ciphertext []byte, aad string) ([]byte, error) {
	dk, err := c.dataKey(ctx, repo, userID)
	if err != nil {
		return nil, err
	}
	return open(dk, ciphertext, valueAAD(userID, aad))
}

func (c *Crypter) dataKey(ctx context.Context, repo port.DataKeyRepo, userID string) ([]byte, error) {
	k, err := repo.Get(ctx, userID)
	if errors.Is(err, errs.NotFound) {
		return nil, ErrShredded
	}
	if err != nil {
		return nil, err
	}
	mk, err := c.keys.MasterKey(ctx, k.KeyID)
	if err != nil {
		return nil, err
	}
	return open(mk, k.WrappedKey, wrapAAD(userID, k.KeyID))
}

// Index はブラインドインデックス。KeyID はインデックス鍵の ID で、ローテーション中は新旧両方で検索する。
type Index struct {
	KeyID string
	Value []byte
}

// EmailIndex はメールアドレスのインデックスを返す。正規化は小文字化（と前後の空白の除去）のみ。
func (c *Crypter) EmailIndex(ctx context.Context, email string) (Index, error) {
	return c.index(ctx, "email", NormalizeEmail(email))
}

// DomainIndex はメールアドレスのドメイン部分のインデックスを返す。
func (c *Crypter) DomainIndex(ctx context.Context, email string) (Index, error) {
	e := NormalizeEmail(email)
	at := strings.LastIndexByte(e, '@')
	if at < 0 {
		return Index{}, errs.New(errs.KindInvalid, "email without domain")
	}
	return c.index(ctx, "email_domain", e[at+1:])
}

// IndexWith は指定したインデックス鍵で計算する（ローテーション中の旧鍵での検索用）。
func (c *Crypter) IndexWith(ctx context.Context, keyID, purpose, normalized string) (Index, error) {
	k, err := c.keys.IndexKey(ctx, keyID)
	if err != nil {
		return Index{}, err
	}
	return Index{KeyID: keyID, Value: mac(k, purpose, normalized)}, nil
}

func (c *Crypter) index(ctx context.Context, purpose, normalized string) (Index, error) {
	kid, err := c.keys.CurrentIndexKeyID(ctx)
	if err != nil {
		return Index{}, err
	}
	return c.IndexWith(ctx, kid, purpose, normalized)
}

// Seal は短命のデータ（EphemeralStore に置くフローの状態や通知の秘密）を、現在のマスター鍵から
// 用途ごとに導いた鍵で暗号化する。ユーザーのデータ鍵に結び付かないため、crypto-shredding の対象外。
// 結果は keyID の長さ || keyID || seal(...)。
func (c *Crypter) Seal(ctx context.Context, purpose string, plaintext []byte) ([]byte, error) {
	kid, err := c.keys.CurrentMasterKeyID(ctx)
	if err != nil {
		return nil, err
	}
	k, err := c.ephemeralKey(ctx, kid, purpose)
	if err != nil {
		return nil, err
	}
	if len(kid) > 255 {
		return nil, errs.New(errs.KindInvalid, "pii: key id too long")
	}
	ct, err := seal(k, plaintext, ephemeralAAD(purpose, kid))
	if err != nil {
		return nil, err
	}
	return append(append([]byte{byte(len(kid))}, kid...), ct...), nil // #nosec G115 -- 上で 255 以下を確かめた
}

// Open は Seal の逆。
func (c *Crypter) Open(ctx context.Context, purpose string, sealed []byte) ([]byte, error) {
	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
		return nil, ErrDecrypt
	}
	kid := string(sealed[1 : 1+int(sealed[0])])
	k, err := c.ephemeralKey(ctx, kid, purpose)
	if err != nil {
		return nil, err
	}
	return open(k, sealed[1+int(sealed[0]):], ephemeralAAD(purpose, kid))
}

func (c *Crypter) ephemeralKey(ctx context.Context, kid, purpose string) ([]byte, error) {
	mk, err := c.keys.MasterKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, mk, nil, "iam/ephemeral/v1\x00"+purpose, KeySize)
}

func ephemeralAAD(purpose, kid string) []byte {
	return []byte("iam/eph/v1\x00" + purpose + "\x00" + kid)
}

// NormalizeEmail はメールアドレスを小文字化する。それ以外の正規化（ドットや + の除去）はしない。
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// mac は用途ごとに分離した HMAC-SHA-256。
func mac(key []byte, purpose, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return h.Sum(nil)
}

func wrapAAD(userID, keyID string) []byte { return []byte("iam/udk/v1\x00" + userID + "\x00" + keyID) }
func valueAAD(userID, purpose string) []byte {
	return []byte("iam/pii/v1\x00" + userID + "\x00" + purpose)
}

// seal は version || nonce || AES-256-GCM(plaintext) を返す。
func seal(key, plaintext, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+g.Overhead())
	out = append(append(out, ciphertextVersion), nonce...)
	return g.Seal(out, nonce, plaintext, aad), nil
}

func open(key, ciphertext, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+g.NonceSize() || ciphertext[0] != ciphertextVersion {
		return nil, ErrDecrypt
	}
	n := ciphertext[1 : 1+g.NonceSize()]
	pt, err := g.Open(nil, n, ciphertext[1+g.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("pii: key must be %d bytes", KeySize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
