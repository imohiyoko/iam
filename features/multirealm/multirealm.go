// Package multirealm はフィーチャー multi_realm をバイナリに含める（design.md 11.1）。import すると登録される。
package multirealm

import (
	"github.com/imohiyoko/iam/shared/feature"
	impl "github.com/imohiyoko/iam/shared/realm"
)

func init() { feature.Register(impl.Feature) }
