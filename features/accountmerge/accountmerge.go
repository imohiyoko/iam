// Package accountmerge はフィーチャー account_merge をバイナリに含める（design.md 11.6）。import すると登録される。
package accountmerge

import (
	impl "github.com/imohiyoko/iam/authn/merge"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
