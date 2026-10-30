// Package realm は複数 realm（design.md 11.1、ADR 0083）のフィーチャーの宣言。振り分けと realm ごとのサービスの組は server/app が持つ。
package realm

import "github.com/imohiyoko/iam/shared/feature"

// Feature は複数 realm。既定以外の realm は実行中に管理 API で作り、ホスト名か /realms/{slug} で指す。
var Feature = feature.Feature{Name: feature.MultiRealm, DataVersion: 1}
