// Package workloadidentity はフィーチャー workload_identity（Workload Identity Federation。ADR 0116）をバイナリに含める。
// import すると登録される。
package workloadidentity

import (
	impl "github.com/imohiyoko/iam/authn/workloadidentity"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
