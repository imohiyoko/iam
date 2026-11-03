// Package fapi2 はフィーチャー fapi2（FAPI 2.0 Security Profile。ADR 0117）をバイナリに含める。import すると登録される。
package fapi2

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.FAPI2Feature) }
