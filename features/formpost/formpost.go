// Package formpost はフィーチャー form_post（OAuth 2.0 Form Post Response Mode。ADR 0124）をバイナリに含める。
// import すると登録される。
package formpost

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.FormPostFeature) }
