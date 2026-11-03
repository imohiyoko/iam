// Package ssftransmitter はフィーチャー ssf_transmitter（OpenID Shared Signals Framework の送信側。ADR 0118）をバイナリに含める。
// import すると登録される。
package ssftransmitter

import (
	impl "github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.TransmitterFeature) }
