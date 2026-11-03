// Package openid4vci はフィーチャー openid4vci（OpenID4VCI 1.0 の発行者。ADR 0119）をバイナリに含める。
// import すると登録される。
package openid4vci

import (
	impl "github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
