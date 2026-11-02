// Package deviceflow はフィーチャー device_flow（OAuth 2.0 Device Authorization Grant。RFC 8628、ADR 0095）をバイナリに含める。
// import すると登録される。
package deviceflow

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.DeviceFeature) }
