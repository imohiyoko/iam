// Package sessionbinding はフィーチャー session_binding（ログインの後のセッションの端末・接続元の変化の監視。ADR 0128）を
// バイナリに含める。import すると登録される。
package sessionbinding

import (
	impl "github.com/imohiyoko/iam/authn/sessionbinding"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
