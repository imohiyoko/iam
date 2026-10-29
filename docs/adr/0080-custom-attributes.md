# 0080. カスタム属性は realm ごとの定義と JSON の値で持ち、トークンにはスコープ attributes で載せる

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 3.1、5.3、11.7、[0045](0045-internal-and-external-ids.md)

## 背景

ホスト先は、社員番号・部署・会員の等級のような、realm ごとに違う属性をユーザーに持たせたい。design.md 11.7 は
「realm ごとに型・検証・本人による編集可否・トークンへの掲載・暗号化の有無を定義する。保存方法はアダプタが決める。」とする。

## 決定

- フィーチャー `custom_attributes`（依存なし）。定義（`authn_attribute_defs`）は realm と `key`（`^[a-z][a-z0-9_]{0,39}$`）で一意。
  型は `string`（`max_length` 1〜1024、既定 256）・`integer`（±2^53−1。JavaScript で安全に扱える範囲）・`boolean`・
  `enum`（選択肢 1〜50）。realm に 50 まで。`type` と `encrypted` は作成後に変えない（値の読み方が変わるため）。
  ほかを変えても既にある値はそのままで、次に書くときに確かめる
- 値（`authn_user_attributes`）はユーザーと key ごとの JSON。`encrypted` なら、ユーザーのデータ鍵で暗号化する
  （AAD は `user_attributes.<key>`。データ鍵を消せば読めない。4.10）。ユーザーの消去で値を消す
- 管理 API：定義は `attributes:manage`（realm:owner）、値の読みは `attributes:read`（owner・admin・support）、
  値の書きは `attributes:write`（owner・admin）。本人は `GET/PATCH /v1/me/attributes` で、`user_editable` の属性だけ書ける
- 書き込みは key ごとの置き換え（`null` で消す）。知らない key・型や制約に合わない値・編集できない属性がひとつでもあれば、
  何も書かない
- トークン：スコープ `attributes`（フィーチャーが動いているときだけ Discovery に出し、受け付ける）の ID トークンと UserInfo に、
  `in_token` の属性を `attributes` クレーム（key ごとの値のオブジェクト）で載せる。値が無ければクレームを出さない
- 監査ログ：`attribute.defined`・`attribute.updated`・`attribute.deleted`、値の書き込みは `user.attributes_updated`
  （key だけ。値は残さない）
- フィーチャーを無効にするときは、値を、その後に定義を消す

## 理由

- 定義と値を行で持てば、SQL・メモリのどれでも同じ形で扱え、検証は authn/attribute の1か所に置ける
- 値を JSON で持てば型ごとの列が要らず、型を変えないことで読み方が一意に決まる
- 標準のクレームと名前が衝突しないように、1つのクレームの下にまとめる。スコープで明示的に求めた連携先にだけ渡す
- 監査ログに値を残さない（属性は個人情報でありうる。暗号化した意味が無くなる）

## 影響

- 連携先は `attributes` スコープを求め、`attributes` クレームを読む
- 属性での検索・一覧は無い（必要になれば、暗号化しない属性の索引を足す）

## 検討した代替案

- 属性ごとにトップレベルのクレームにする：`email`・`name` などの標準クレームと衝突しうる
- users の行に JSON の列で持つ：属性ごとの暗号化と、定義の削除での値の片付けがしにくい
- 型ごとの列で持つ：型が増えるたびにスキーマが変わる
