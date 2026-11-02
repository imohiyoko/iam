// Package impersonation はフィーチャー impersonation（運営者のなりすまし。ADR 0099）をバイナリに含める。import すると登録される。
package impersonation

import (
	impl "github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.ImpersonationFeature) }
