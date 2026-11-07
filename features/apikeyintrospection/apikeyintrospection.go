// Package apikeyintrospection はフィーチャー api_key_introspection（サービスアカウントの API キーをイントロスペクションで
// 確かめる。ADR 0120）をバイナリに含める。import すると登録される。
package apikeyintrospection

import (
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(serviceaccount.IntrospectionFeature) }
