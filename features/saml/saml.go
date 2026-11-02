// Package saml はフィーチャー saml（外部 IdP としての SAML 2.0。ADR 0098）をバイナリに含める。import すると登録される。
package saml

import (
	impl "github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
