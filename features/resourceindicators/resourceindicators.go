// Package resourceindicators はフィーチャー resource_indicators（自前の API 向けのトークン。RFC 8707、ADR 0112）を
// バイナリに含める。import すると登録される。
package resourceindicators

import (
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(provider.ResourceFeature) }
