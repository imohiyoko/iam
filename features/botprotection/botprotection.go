// Package botprotection はフィーチャー bot_protection（ボット対策。ADR 0105）をバイナリに含める。import すると登録される。
package botprotection

import (
	impl "github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
