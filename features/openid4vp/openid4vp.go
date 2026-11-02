// Package openid4vp はフィーチャー openid4vp と OpenID4VP の検証者の認証方式をバイナリに含める（ADR 0108）。import すると登録される。
package openid4vp

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/openid4vp"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(impl.Method{})
}
