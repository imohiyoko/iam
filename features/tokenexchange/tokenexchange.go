// Package tokenexchange はフィーチャー token_exchange（Token Exchange の委任。ADR 0099）をバイナリに含める。import すると登録される。
package tokenexchange

import (
	impl "github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.TokenExchangeFeature) }
