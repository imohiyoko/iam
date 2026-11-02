// Package eventsubscriptions はフィーチャー event_subscriptions をバイナリに含める（ADR 0100）。import すると登録される。
package eventsubscriptions

import (
	impl "github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
