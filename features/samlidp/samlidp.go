// Package samlidp はフィーチャー saml_idp（SAML 2.0 の IdP。iam が IdP。ADR 0115）をバイナリに含める。
// import すると登録される。
package samlidp

import (
	impl "github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
