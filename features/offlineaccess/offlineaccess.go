// Package offlineaccess はフィーチャー offline_access（ログインの系列から切り離した認可。ADR 0126）をバイナリに含める。
// import すると登録される。
package offlineaccess

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.OfflineAccessFeature) }
