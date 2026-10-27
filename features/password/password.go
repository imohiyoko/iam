// Package password はフィーチャー passwordをバイナリに含める（design.md 11.11）。import すると登録される。
package password

import (
	impl "github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
