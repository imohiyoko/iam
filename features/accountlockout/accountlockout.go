// Package accountlockout はフィーチャー account_lockout（アカウント単位のロックアウト。ADR 0105）をバイナリに含める。import すると登録される。
package accountlockout

import (
	impl "github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
