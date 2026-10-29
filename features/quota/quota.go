// Package quota はフィーチャー quotaをバイナリに含める（design.md 11.11）。import すると登録される。
package quota

import (
	impl "github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.QuotaFeature) }
