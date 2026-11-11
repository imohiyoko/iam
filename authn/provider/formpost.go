package provider

import "github.com/imohiyoko/iam/shared/feature"

// FormPostFeature は認可応答の response_mode=form_post（OAuth 2.0 Form Post Response Mode。ADR 0124）のフィーチャー（既定オフ）。
// 持つデータは無い（応答は EphemeralStore に 1 回限り・短い期限で預ける）。
var FormPostFeature = feature.Feature{Name: feature.FormPost, DataVersion: 1}
