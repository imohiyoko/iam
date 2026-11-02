package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Data は方式固有のデータ（コアがユーザーのデータ鍵で暗号化して authn_credentials に置く）。公開鍵は COSE の形で、秘密ではない。
// 移行（ADR 0106）でも作る。
type Data struct {
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"` // COSE_Key
	Alg          int64  `json:"alg"`        // COSE のアルゴリズム（ES256 = -7、EdDSA = -8）
	SignCount    uint32 `json:"sign_count"`
	// Flags は認証器のフラグ（UP、UV、BE、BS など）。BE は登録の後に変わらないことを検証に使う。
	Flags      uint8    `json:"flags"`
	AAGUID     []byte   `json:"aaguid,omitempty"`
	Transports []string `json:"transports,omitempty"`
	// UserHandle は登録時のユーザーハンドル（WebAuthn の user.id。登録した本人の公開 ID）。統合（11.6）で移した passkey も、
	// 認証器は元の持ち主の公開 ID を返すので、それを持ち続ける。
	UserHandle []byte `json:"user_handle"`
	Name       string `json:"name"`
	// AttestationFormat は登録のときの attestation の形式（none、packed など。ADR 0096）。空はこの項目の前に登録したもの。
	AttestationFormat string `json:"attestation_format,omitempty"`
	// Attested は登録のときに attestation の証明書の連なりを信頼の起点（MDS か設定）まで確かめたか。
	Attested bool `json:"attested,omitempty"`
}

// flagBackupEligible は認証器のフラグの BE（同期できる passkey）。
const flagBackupEligible = 0x08

// BackupEligible は同期できる passkey か（BE）。
func (d Data) BackupEligible() bool { return d.Flags&flagBackupEligible != 0 }

// Authenticator は判定（ADR 0096）の材料。
func (d Data) Authenticator() attestation.Authenticator {
	return attestation.Authenticator{AAGUID: d.AAGUID, Format: d.AttestationFormat, Attested: d.Attested}
}

// Decode は方式のデータを読む。
func Decode(raw []byte) (Data, error) {
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return Data{}, fmt.Errorf("passkey: data: %w", err)
	}
	if len(d.CredentialID) == 0 || len(d.PublicKey) == 0 {
		return Data{}, fmt.Errorf("passkey: data without a credential")
	}
	return d, nil
}

// Encode は方式のデータを書く。
func Encode(d Data) ([]byte, error) {
	if d.Transports == nil {
		d.Transports = []string{}
	}
	return json.Marshal(d)
}

// Lookup は credential ID の検索キー（コアがブラインドインデックスにする）。
func Lookup(credentialID []byte) string { return base64.RawURLEncoding.EncodeToString(credentialID) }

// Read は authn_credentials の行（方式 passkey）を復号して読む（コアの一覧・Org のポリシー・名前の変更が使う）。
func Read(ctx context.Context, tx port.Tx, crypter *pii.Crypter, c port.Credential) (port.MethodCredential, Data, error) {
	if c.Method != Name {
		return port.MethodCredential{}, Data{}, fmt.Errorf("passkey: credential %s is a %s", c.ID, c.Method)
	}
	mc, err := method.Open(ctx, tx, crypter, c)
	if err != nil {
		return port.MethodCredential{}, Data{}, err
	}
	d, err := Decode(mc.Data)
	return mc, d, err
}

// DefaultName は名前を指定しなかった passkey の名前。
const DefaultName = "Passkey"

// MaxName は passkey の名前の最大の長さ（文字数）。
const MaxName = 64

// ErrName は passkey の名前の誤り（空、長すぎる、制御文字を含む）。
var ErrName = errs.WithCode(errs.KindInvalid, "invalid_name", "invalid passkey name")

// ValidName は名前を確かめ、前後の空白を除いたものを返す。
func ValidName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxName ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", ErrName
	}
	return name, nil
}

// Attestation は attestation と認証器のポリシー（フィーチャー passkey_attestation。ADR 0096）。
type Attestation struct {
	// Metadata は認証器のメタデータ（MDS の BLOB と設定した信頼の起点）。全 realm で共有する。
	Metadata *attestation.Metadata
	// Conveyance は登録で求める attestation（none・indirect・direct・enterprise）。空なら none。
	Conveyance string
	// Policy は realm の段のポリシー。nil なら認証器の状態（status report）だけで判定する。
	Policy *attestation.Policy
}

// Evaluate は保存した passkey d を、realm の段のポリシーと追加の段 extra で判定する。
func (a *Attestation) Evaluate(now time.Time, d Data, extra ...attestation.Tiered) attestation.Decision {
	tiers := append([]attestation.Tiered{{Tier: "realm", Policy: a.Policy}}, extra...)
	return a.Metadata.Evaluate(now, d.Authenticator(), tiers...)
}
