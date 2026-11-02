// Package password はフィーチャー password とパスワードの認証方式をバイナリに含める（design.md 11.11、ADR 0101）。
// import すると登録される。方式の設定（ハッシュのパラメータなど）は server/app が入れたものに置き換わる。
package password

import (
	"github.com/imohiyoko/iam/authn/method"
	impl "github.com/imohiyoko/iam/authn/method/password"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() {
	feature.Register(impl.Feature)
	method.Register(&impl.Method{})
}
