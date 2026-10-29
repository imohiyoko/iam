// Package flowhooks はフィーチャー flow_hooks をバイナリに含める（design.md 11.8）。import すると登録される。
package flowhooks

import (
	impl "github.com/imohiyoko/iam/authn/hook"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
