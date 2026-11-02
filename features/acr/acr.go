// Package acr はフィーチャー acr（acr・AAL と step-up。ADR 0093）をバイナリに含める。import すると登録される。
package acr

import (
	impl "github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
