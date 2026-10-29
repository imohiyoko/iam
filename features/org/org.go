// Package org はフィーチャー org（Org と個人 Org）をバイナリに含める（design.md 11.11）。import すると登録される。
package org

import (
	impl "github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
