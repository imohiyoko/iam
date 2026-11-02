// Package push はフィーチャー push_auth とプッシュの承認の認証方式をバイナリに含める（design.md 11.11、ADR 0104）。
// import すると登録される。送信のアダプタ（push_sender）は別に含める。
package push

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/push"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(impl.Method{})
}
