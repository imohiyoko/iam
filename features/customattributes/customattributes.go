// Package customattributes はフィーチャー custom_attributes をバイナリに含める（design.md 11.7）。import すると登録される。
package customattributes

import (
	impl "github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
