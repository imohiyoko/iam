// Package passkeyattestation はフィーチャー passkey_attestation（passkey の attestation と認証器のポリシー。ADR 0096）を
// バイナリに含める（design.md 11.11）。import すると登録される。
package passkeyattestation

import (
	impl "github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.AttestationFeature) }
