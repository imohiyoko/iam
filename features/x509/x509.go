// Package x509 はフィーチャー x509 と X.509 のクライアント証明書の認証方式をバイナリに含める（ADR 0103）。import すると登録される。
package x509

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/x509"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(&impl.Method{})
}
