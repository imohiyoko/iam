// Package wsfed はフィーチャー wsfed（WS-Federation のパッシブ要求者プロファイル。iam が IdP。ADR 0110）をバイナリに含める。
// import すると登録される。
package wsfed

import (
	impl "github.com/imohiyoko/iam/authn/wsfed"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
