// Package ciba はフィーチャー ciba（OpenID Connect Client-Initiated Backchannel Authentication。ADR 0114）をバイナリに含める。
// import すると登録される。
package ciba

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.CIBAFeature) }
