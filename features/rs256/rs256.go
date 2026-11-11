// Package rs256 はフィーチャー rs256（ID トークン・Logout Token の RS256 の署名。ADR 0122）をバイナリに含める。
// import すると登録される。
package rs256

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.RS256Feature) }
