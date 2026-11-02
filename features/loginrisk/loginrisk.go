// Package loginrisk はフィーチャー login_risk（ログインのリスクの点数。ADR 0105）をバイナリに含める。import すると登録される。
package loginrisk

import (
	impl "github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.RiskFeature) }
