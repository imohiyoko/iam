// Package sms はフィーチャー sms_otp と SMS・音声の OTP の認証方式をバイナリに含める（design.md 11.11、ADR 0104）。
// import すると登録される。送信のアダプタ（sms_sender）は別に含める。
package sms

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/sms"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(impl.Method{})
}
