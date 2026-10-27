# 0064. ロール・付与・Group と認可の判定

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 3.2、4.5、4.11、11.5、5.3、[0045](0045-internal-and-external-ids.md)

## 背景

M4 で認可を組み込む。design.md は次を求める。

- `check(principal, action, resource, context) -> allow / deny`。主体はユーザー・サービスアカウント・Group（4.5）
- 組み込みのロールに加え、ホスト先と Org が独自のロールを足せる（4.11）
- 粒度は Org・realm 単位の RBAC と、リソース単位の権限（11.5）。Group のネストは M7
- Org の範囲の権限は、その Org の使える所属がある間だけ効く（3.2、4.7、4.8）

## 決定

- 表
  - `authz_roles`：独自のロール（realm 共通か Org のもの）。権限は `<リソース>:<操作>` の並び（`x:*` はそのリソースのすべて）
  - `role_bindings`：公開 ID と、範囲のリソース（`resource_type`・`resource_id`）を足す。`role` は組み込みの名前か、独自の
    ロールの内部 ID。主体に `group` を足す
  - `authz_groups`・`authz_group_members`：Group（realm 全体か Org のもの）と所属（ユーザーとサービスアカウント）
- 組み込みのロール（コードに持ち、表には置かない）
  - 運営者ロール（`realm:*`）は realm の範囲の付与だけで効く
  - Org のロール（`org:owner`・`org:admin`・`org:member`）は Membership の `org_role` から、その Org の範囲で効く。付与はしない
  - システムのロール（`system:*`）は組み込みのサービスアカウントだけ。管理の API からは付与できない
  - `realm:`・`org:`・`system:` は組み込みの名前空間で、独自のロールの名前には使えない
- 判定（`authz/check`）
  - 主体の直接の付与と、所属する Group の付与と、`org_role` を合算する。Org の付与・Org の Group は、その Org の使える所属
    （Org と Membership の停止・有効期間・削除を含む）がある間だけ効く。リソースを限った付与は、そのリソースだけに効く
  - Org がオフなら Org の範囲の付与は効かず、realm の範囲の RBAC になる
  - fail-closed：知らないロール・消えたロールは権限を持たない
  - 判定の材料（主体と範囲ごとの付与の一覧）はプロセスの中に `session.validity_max_delay` の間キャッシュする。このインスタンス
    での authz の変更は世代を進めてすぐに捨てる。所属の変更と他のインスタンスでの変更は、その上限の内に反映する
- 管理（`authz/manage`）
  - realm は `roles:manage`（ロールと付与。realm:owner）・`groups:manage`（Group。realm:owner・realm:admin）、Org は
    `org:roles`・`org:groups`（org:owner・org:admin）を求める
  - 加えて、渡す権限（作る・変えるロールの権限、付与するロールの権限、Group に入れるときはその Group の権限）をすべて、自分が
    その範囲全体で持っていなければならない（権限の引き上げを防ぐ）
  - Org の範囲のロールには、IAM 自身の realm の管理の権限（`users:`・`orgs:`・`roles:` など）は入れられない
  - Org の範囲の付与と Org の Group への所属は、その Org の使える所属を持つ主体だけ
  - 最後の `realm:owner` のユーザーの付与は消せない
  - 変更は監査ログに残す（`role.*`・`group.*`）。応答と監査ログには公開 ID だけを出す（0045）
  - Membership が終わると（退会・除名・アカウントの削除）、その Org の範囲の付与と Org の Group の所属を消す
    （戻ってきたときに古い権限が蘇らないように）
- API
  - realm の範囲は管理 API の `/v1/admin/roles`・`/role-bindings`・`/groups`、Org の範囲は公開 API の
    `/v1/me/orgs/{id}/roles`・`/role-bindings`・`/groups`。同じ処理で、形も同じ
  - 主体はユーザーと Group（サービスアカウントは公開 ID を持たないので、M4 では API から付与しない）
- 既存の判定の置き換え
  - 管理 API の認可と、なりすませる操作の前の「対象の権限をすべて持つか」は判定を使う。運営者の操作は数が少なく、
    取り消しをすぐ効かせたいので、キャッシュを使わない（`CheckTx`）
  - Org の操作（招待・除名・設定など）は Org の範囲の判定を使う。独自のロールで `org:invite` などを渡せる
  - Org の削除とその取り消しだけは `org_role` で見る（削除の予定がある Org は使えないので、Org の範囲の付与は効かない）

## 理由

- 組み込みのロールをコードに持てば、版の更新で権限を足しても表を書き換えなくてよい
- Org のロールを `org_role` から効かせれば、所属の停止・有効期間・削除がそのまま権限に効き、付与を別に消さなくてよい
- 判定のたびに表を読むと遅い（ベンチの目標 1µs）。所属の変更の反映の遅れは、セッションの検証と同じ上限で揃える

## 影響

- 既存の `role_bindings` の行には公開 ID を振る（マイグレーション 00016）
- `role.Allowed`・`role.Covers` は無くした。`role.OrgAllows` は Org の削除だけに残る
