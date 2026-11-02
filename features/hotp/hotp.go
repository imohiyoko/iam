// Package hotp はフィーチャー hotp と HOTP の認証方式をバイナリに含める（design.md 11.11、ADR 0090）。import すると登録される。
package hotp

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/hotp"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(impl.Method{})
}
