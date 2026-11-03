// Package ssfreceiver はフィーチャー ssf_receiver（OpenID Shared Signals Framework の受信側。ADR 0118）をバイナリに含める。
// import すると登録される。
package ssfreceiver

import (
	impl "github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.ReceiverFeature) }
