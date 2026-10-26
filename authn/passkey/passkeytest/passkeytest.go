// Package passkeytest は、テストで使う擬似の認証器（WebAuthn の authenticator）を提供する。
//
// ES256 の鍵を作り、attestation は "none"。ブラウザの navigator.credentials の応答と同じ JSON を返す。
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// 認証器のデータのフラグ（WebAuthn §6.1）。
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
)

// Authenticator は1つの credential を持つ擬似の認証器。
type Authenticator struct {
	Origin string
	// Flags は応答に付けるフラグ（既定は UP と UV）。AT は登録のときに足す。
	Flags        byte
	SignCount    uint32
	CredentialID []byte
	UserHandle   []byte
	key          *ecdsa.PrivateKey
}

// New は origin の画面から使う認証器を作る。
func New(origin string) *Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Authenticator{Origin: origin, Flags: FlagUP | FlagUV, CredentialID: id, key: key}
}

var b64 = base64.RawURLEncoding

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

// Create は登録の options（{"publicKey": …}）に応え、navigator.credentials.create の応答の JSON を返す。
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.Challenge == "" || o.PublicKey.RP.ID == "" {
		return nil, errors.New("passkeytest: challenge and rp.id are required")
	}
	handle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, err
	}
	a.UserHandle = handle
	clientData, err := a.clientData("webauthn.create", o.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pad32(a.key.X.Bytes()), -3: pad32(a.key.Y.Bytes())})
	if err != nil {
		return nil, err
	}
	auth := a.authData(o.PublicKey.RP.ID, a.Flags|FlagAT)
	auth = append(auth, make([]byte, 16)...)                                // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.CredentialID))) // #nosec G115 -- 16 バイト
	auth = append(auth, a.CredentialID...)
	auth = append(auth, cose...)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.CredentialID), "rawId": b64.EncodeToString(a.CredentialID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(clientData), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"internal", "hybrid"},
		},
	})
}

// Get はログインの options（{"publicKey": …}）に応え、navigator.credentials.get の応答の JSON を返す。
// 署名の回数を1つ進める。
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.Challenge == "" || o.PublicKey.RPID == "" {
		return nil, errors.New("passkeytest: challenge and rpId are required")
	}
	clientData, err := a.clientData("webauthn.get", o.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	a.SignCount++
	auth := a.authData(o.PublicKey.RPID, a.Flags)
	h := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, auth...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.CredentialID), "rawId": b64.EncodeToString(a.CredentialID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(clientData), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.UserHandle),
		},
	})
}

func (a *Authenticator) clientData(typ, challenge string) ([]byte, error) {
	return json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
}

func (a *Authenticator) authData(rpID string, flags byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], flags)
	return binary.BigEndian.AppendUint32(out, a.SignCount)
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
