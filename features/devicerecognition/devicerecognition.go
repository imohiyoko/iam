// Package devicerecognition はフィーチャー device_recognition（端末の記憶。ADR 0105）をバイナリに含める。import すると登録される。
package devicerecognition

import (
	impl "github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
