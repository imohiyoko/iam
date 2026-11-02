// Package par はフィーチャー par（Pushed Authorization Requests。RFC 9126、ADR 0112）をバイナリに含める。
// import すると登録される。
package par

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.PARFeature) }
