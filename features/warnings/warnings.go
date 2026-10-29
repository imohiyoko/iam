// Package warnings はフィーチャー warnings（認証の警告）をバイナリに含める（design.md 11.11）。import すると登録される。
package warnings

import (
	impl "github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
