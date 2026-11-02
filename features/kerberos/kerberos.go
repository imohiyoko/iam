// Package kerberos はフィーチャー kerberos と Kerberos / SPNEGO の認証方式をバイナリに含める（ADR 0107）。import すると登録される。
package kerberos

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/kerberos"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(&impl.Method{})
}
