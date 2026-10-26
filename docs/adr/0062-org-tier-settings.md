# 0062. 設定の Org の段（セッションの寿命と警告のアクション）

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 2.8、5.4、10章、[0007](0007-auth-warnings.md)、[0033](0033-security-settings-hierarchy.md)、[0057](0057-org-selection-and-switching.md)

## 背景

design.md 2.8 と ADR 0033 は、セキュリティ設定をホスト先 → realm → Org の階層で決め、Org は既定では厳しくする向きにしか
変えられないとする。5.4 はセッションの寿命をこの階層で設定し、切り替え先の Org の寿命を超えていれば再認証を求め、設定の変更を
既存のセッションにも反映するとする。10章は警告のアクションもこの階層で決め、Org で deny ならログインは成功してその Org に入れない
だけとする。M3 では Org の段のうち、セッションの寿命（`absolute_lifetime`、`idle_timeout`、`max_auth_age`）と警告のアクションを
扱う。realm の段の保存と変更の API はまだ無く、realm の値はホスト先の既定値とする。

## 決定

- 保存：`orgs.settings`（JSON。`absolute_lifetime`・`idle_timeout`・`max_auth_age`・`warnings`）。省いた項目は realm に従う。
  個人 Org は設定を持たない（`409 personal_org`）
- API：`GET`・`PUT /v1/me/orgs/{id}/settings`（`org:settings`、owner と admin）と `GET`・`PUT /v1/admin/orgs/{id}/settings`
  （`orgs:read`・`orgs:update`）。`PUT` は全体の置き換えで、`settings`（Org が設定した値）と `effective`（効く値）を返す。
  変更は `org.settings_changed`（前後の値）として監査ログに残す
- 検査：寿命は `settings.Rule.CheckOrg`（ホスト先の範囲の内で、realm より厳しい向きだけ。ホスト先が `org_may_relax` を許した項目は
  緩められる）。警告のアクションは常に厳しくする向きのみ（ignore < warn < deny）。外れれば `400 setting_invalid`
- セッションの寿命は認証の時刻から数え、active な Org の値に従う
  - 発行と切り替えでは `expires_at` を「認証の時刻 + その Org の `absolute_lifetime`」にする
  - 検証では active な Org の `absolute_lifetime`・`idle_timeout` を超えたセッションを拒む。設定の変更は検証のキャッシュの期限
    （`validity_max_delay`）の内に既存のセッションにも効く
  - 切り替え先の Org の寿命を超えていれば、切り替えを `401 reauthentication_required` で拒む。ログインし直せばその Org に入れる
  - 寿命を超えたセッションは Org の操作だけでなく全体を拒む（無操作の判定に使う `last_seen_at` は検証のたびに延びるため、
    「その Org にだけ入れない」状態を保てない）
- 重要な操作の直近の認証（`max_auth_age`）は、active な Org の値を検証の結果に載せて使う（運営者の API は realm の値のまま）
- 警告
  - ログインで該当した警告は、ignore のものも含めてすべて `sessions.warnings` に残す（`warning.Evaluator.Hits`）。
    本人と監査ログには、これまでどおり active な Org の段を当てはめた ignore でないものだけを返す（`Apply`）
  - realm の段で deny ならログインを拒む（これまでどおり）。Org の段で deny になる Org は、Org の決定（ADR 0057）の候補から外す。
    明示的な指定と切り替えは `403` と `warning_denied.<code>` で拒む
  - 既存のセッションは、Org の段の変更で deny になれば検証の結果の `OrgUnavailable` に `warning_denied.<code>` を載せる
  - realm の段のアクションも保存した警告から当て直すため、ホスト先の設定の変更も既存のセッションに効く

## 理由

- 寿命を認証の時刻から数えると、Org を切り替えても寿命は延びず、切り替え先の Org の値で「認証からどれだけ経ったか」を判定できる
- ignore の警告を残さないと、ログインの後に Org の段で厳しくしたとき（や切り替えのとき）に判定できない。残すのは
  コードと重さだけで、個人情報は含まない
- 警告を厳しくする向きだけに限るのは、realm の運営者が要求した警告を Org が黙らせられないようにするため

## 影響

- realm の段の保存と API は後で足す。そのときは realm の値を `Resolve` の realm に渡す
- 使える認証手段・パスワードの要件・2段階認証の要否など、2.8 の残りの項目は同じ `orgs.settings` に足していく
