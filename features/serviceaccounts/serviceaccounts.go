// Package serviceaccounts はフィーチャー service_accounts をバイナリに含める（design.md 11.11）。import すると登録される。
package serviceaccounts

import (
	impl "github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
