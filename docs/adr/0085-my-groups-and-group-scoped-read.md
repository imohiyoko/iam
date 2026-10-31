# 0085. 本人の Group の一覧と、Group に限った所属の参照

- 状態: 承認
- 日付: 2026-10-31
- 関連: [design.md](../design.md) 3.2、4.11、11.5、[0064](0064-authz-roles-groups-check.md)、[0079](0079-nested-groups.md)

## 背景

連携先は Org の Group をクラスやチームとして使い、見せる範囲を絞りたい（例：講師は担当クラスの生徒だけを見る）。
これまで Org の Group と所属を読むには `org:groups` が要った。`org:groups` は Group の作成・削除・所属の変更もできるので、
メンバーや講師には渡せない。そのため次のことができなかった。

- メンバーが、自分がどの Group に所属しているかを知る
- 講師が、担当の Group に誰が所属しているかを知る（判定の `resource_type: group` で講師の権限は Group に限れるが、
  対象の人がその Group にいるかを確かめる方法が無い）

## 決定

- 公開 API `GET /v1/me/orgs/{id}/my-groups`：本人がこの Org の範囲で所属する Group を名前の順に返す。権限は要らない
  （この Org の使える所属が要る）。フィーチャー `nested_groups` が有効なら、所属する Group を含む Group も `direct: false`
  で返す（その付与も本人に効くため）。realm の Group と別の Org の Group は返さない
- 権限 `org:groups.read`：Org の Group と所属の参照だけ。`org:owner`・`org:admin` は持つ（独自のロールに入れて渡せるように）
  - Org 全体の付与なら、Group の一覧（`GET .../groups`）とどの Group の所属（`GET .../groups/{group_id}/members`）も読める
  - Group に限った付与（`resource_type: group`、`resource_id` は Group の公開 ID）なら、その Group の所属だけを読める
  - `org:groups` は今までどおり、一覧と所属の参照を含む
- 判定のリソースの種類 `group`（`check.ResourceGroup`）。判定の規則は変えない（リソースを限った付与は、そのリソースだけに効く）

連携先の使い方の例：講師の独自のロール（`org:groups.read` と連携先の権限）を、担当の Group に限って付与する。連携先は
講師の資格情報で、`POST /v1/me:check`（`resource_type: group`）で講師の権限を、`GET .../groups/{group_id}/members` で
対象の人の所属を確かめる。生徒は `my-groups` で自分のクラスを知る。

## 結果

- メンバーは自分の所属を、講師は担当の Group の所属を、管理の権限なしで読める
- 所属の参照は直接の所属だけ（ネストした Group は `principal_type: group` の1行）。ネストを展開したい連携先は、その Group の
  所属も読む（同じ付与では読めないので、含まれる Group にも付与する）
- 所属の変更は判定の材料のキャッシュと違い、参照のたびに表を読むので、すぐに反映する

## 検討した代替案

- 判定で「対象のユーザーが Group G にいれば、G に限った付与が効く」とする（`resource_type: user` の判定に Group の所属を
  使う）：判定の規則とキャッシュの材料に、対象の人の所属を入れることになり、変更が大きい。参照の API と組み合わせれば
  連携先で同じことができる
- `org:groups` を参照と管理に分ける：既存の独自のロールの意味が変わる。参照だけの権限を足し、`org:groups` は参照も含めたまま
  にした
