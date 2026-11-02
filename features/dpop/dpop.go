// Package dpop はフィーチャー dpop（DPoP の送信者制約トークン。ADR 0113）をバイナリに含める。import すると登録される。
package dpop

import (
	impl "github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
