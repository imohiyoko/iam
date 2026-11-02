// Package oidclogout はフィーチャー oidc_logout（RP-Initiated Logout と Front-Channel Logout。ADR 0094）をバイナリに含める。
// import すると登録される。
package oidclogout

import (
	impl "github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.LogoutFeature) }
