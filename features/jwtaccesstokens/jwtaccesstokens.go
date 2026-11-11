// Package jwtaccesstokens はフィーチャー jwt_access_tokens（JWT のアクセストークン。RFC 9068、ADR 0123）をバイナリに含める。
// import すると登録される。
package jwtaccesstokens

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.JWTAccessFeature) }
