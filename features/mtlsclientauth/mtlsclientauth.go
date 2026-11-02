// Package mtlsclientauth はフィーチャー mtls_client_auth（OAuth の mTLS の連携先の認証と、証明書に結び付けたトークン。
// ADR 0113）をバイナリに含める。import すると登録される。
package mtlsclientauth

import (
	impl "github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.MTLSFeature) }
