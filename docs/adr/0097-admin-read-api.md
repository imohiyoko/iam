# 0097. 管理 API の一覧・取得・検索は運営者ロールに読み取りの権限を足し、メールはブラインドインデックスの完全一致で引く

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.11、4.13、9.5、[0014](0014-pii-encryption-minimization.md)、[0023](0023-admin-model.md)、
  [0052](0052-admin-credential-revocation.md)、[0064](0064-authz-roles-groups-check.md)、[0077](0077-org-sso.md)、[0083](0083-multi-realm.md)

## 背景

これまでの管理 API は、作成・変更・停止・削除が中心だった。運営者はユーザーの ID を知っている前提で、メールや外部 ID から
ユーザーを探す方法、ユーザーの状態をまとめて見る方法、誰にどのロールが効いているかを逆に引く方法が無かった。調査は
Storage を直接読む CLI に頼ることになり、権限で絞れず、監査ログにも残らない。

検索にはメールアドレスを使いたい。しかしアドレスは本人のデータ鍵で暗号化し、検索はブラインドインデックスで行う（9.5、0014）。
部分一致の検索は、暗号化の方針と両立しない。

## 決定

### 権限

- 運営者の参照のために権限を足し、既存の運営者ロール（4.11）に付ける。owner はすべてを持つ

  | 権限 | 対象 | admin | security | support |
  |---|---|---|---|---|
  | `users:read` | ユーザーの一覧・検索・詳細、ユーザーの Membership | ○ | ○ | ○ |
  | `sessions:read` | ユーザーのセッションの一覧 | ○ | ○ | ○ |
  | `roles:read`・`groups:read` | 主体のロールの付与と Group の所属の逆引き | ○ | ○ | ○ |
  | `connections:read` | IdP 接続の一覧と取得 | ○ | ○ | ― |
  | `signing_keys:read` | 署名鍵の一覧 | ― | ○ | ― |
  | `users:emails` | 運営者によるメールの追加・削除・primary の変更 | ○ | ― | ― |

- Org の一覧は既存の `orgs:read`、セッションの一括の失効は既存の `sessions:revoke`、connection の変更と削除は既存の
  `connections:manage` を使う
- admin は support の権限をすべて持つ（outranks の判定で、admin が support を扱えることを変えない）

### 検索

- `GET /v1/admin/users`：公開 ID の順のカーソル（`after`・`next_cursor`）。絞り込みはすべて AND
  - メールはブラインドインデックスで引く完全一致だけにする。正規化は登録と同じ小文字化だけ。部分一致・前方一致はしない
  - 外部 ID は connection（slug）と subject の組の完全一致
  - 状態は `active`（停止中でない）・`suspended`（今停止中）・`deleted`・`merged`。停止はユーザーの状態の列でなく停止の記録で
    表す（4.7）ので、検索の時刻に効いている停止があるかで判定する
  - Org（active な Membership がある）、作成の時刻の範囲
- `GET /v1/admin/orgs`：同じカーソル。名前は平文で持つので、前方一致を許す。正規化せずバイトで比べ、大文字と小文字を区別する
  （保存の形のまま比べる。SQLite と PostgreSQL の照合順序を揃えた `COLLATE "C"` と同じ）。親・種類・状態（`active`・
  `suspended`・`deleted`）でも絞る
- 無い Org・connection・アドレスを指したときは、404 でなく空の一覧を返す（検索の結果が無いことと区別しない）
- Storage には `UserRepo.Search`・`OrgRepo.Search` を足す。空の値は絞り込まない 1 つのクエリにし、索引は既存のもの
  （`(realm_id, public_id)`、Membership と停止の対象の索引）で足りるので足さない

### 取得と逆引き

- `GET /v1/admin/users/{id}`：状態・停止の一覧・有効期間・legal hold・削除の予定・管理する Org・統合先・メール・認証手段の
  概要・残りのリカバリーコードの数・Membership
- `GET /v1/admin/users/{id}/sessions`：本人の一覧と同じ判定で有効なものだけ。IP と User-Agent は出さない
- `GET /v1/admin/{users|service-accounts}/{id}/role-bindings`：判定と同じ材料（`ListEffective`）で、直接の付与と Group の付与
  （ネストを含む）を、realm と Org の範囲をまとめて返す。Group の付与には `via_group_id` を付ける
- `GET /v1/admin/{users|service-accounts}/{id}/groups`：realm と Org の範囲の Group。ネストで含む Group は `direct: false`
- `GET /v1/admin/connections`・`/{id}`：クライアントシークレットは出さない。有効な外部 ID の数を付ける
- `GET /v1/admin/signing-keys`：kid・アルゴリズム・状態（`active`・`retired`・`expired`）・作成と退役の時刻・JWKS に残す
  期限。秘密鍵は封をした形でも出さず、公開鍵は JWKS で配る

### 個人情報の出し方

- 一覧にはメールアドレスを出さない。詳細でも既定では出さず、`include_pii=true` のときだけ復号する。復号には独立した権限
  `pii:read`（0023）が要り、`user.pii_read` を監査ログに残す
- それ以外の読み取りは、既存の参照（Org、停止、認証情報の一覧）と同じく監査ログに残さない。既存の管理 API に読み取りの監査は
  無く、残すと監査ログの大半が参照になり、変更の追跡を妨げる。何を見たかを残す必要があるのは、復号した個人情報だけとした

### 変更を伴う操作

- `POST /v1/admin/users/{id}/sessions:revoke-all`：全セッションの失効だけ。認証情報は残す。侵害時の初動（認証情報も無効化する）
  は `credentials:revoke-all`（0052）、端末の紛失や停止・権限の変更をすぐに効かせるときはこちらを使う。セッションの失効は
  なりすましにならないので、個別の失効（`sessions/{id}:revoke`）と同じく outranks の判定はしない
- 運営者によるメール（確認の経路 `admin`）：`POST /v1/admin/users/{id}/emails`・`…/{email_id}:remove`・`…:make-primary`
  - メールは復旧とログインの経路なので、なりすましと同じ outranks の判定（0052）をする
  - 本人と同じ不変条件を守る：primary は消せない、最後の確認済みメールは消せない、ログインの手段が無くなるなら消せない、
    Membership に結び付けたメールは消せない。primary にできるのは確認済みのメールだけ
  - 監査ログは本人の操作と同じ種類（`email.added` など）に、対象のユーザーの公開 ID を足す
- IdP 接続の変更と削除：
  - `PUT` で変えるのはクライアント ID・シークレット（省けば今の値）・戻り先だけ。slug と種類とエンドポイントは変えない
  - 削除は、有効な外部 ID の紐付けが残っていれば既定で断る（`409 connection_in_use`）。`revoke_identities: true` のときだけ
    紐付けを無効化してから消す。黙って消すと、その外部 ID しか持たないユーザーがログインの手段を失うため
  - Org 専用 SSO の connection は Org の owner が扱う（0077）ので、運営者は参照だけにする（`409 org_connection`）

### フィーチャーにしない

既存の管理 API の拡張で、新しいデータを持たず、既定の動作も変えない（新しいエンドポイントを足すだけ）。権限で絞れ、無効化で
消すデータも無いので、フィーチャー（0010・0011・0073）にしない。

### 複数 realm

すべての操作は要求の realm（0083）の中だけで行う。ほかの realm のユーザー・Org・connection は無いものとして扱う（404 か空の
一覧）。Storage の検索も realm の ID を引数に取り、realm の分離の契約テストに足す。

## 結果

- 運営者は管理 API だけでユーザーを探し、状態・セッション・付与と所属を調べられる。調べた後の操作（停止・失効・削除）にそのまま
  つなげられる
- メールの検索は完全一致だけで、ドメインや一部での検索はできない。調査で部分一致が要るときは、今までどおり復号できる CLI を使う
- support・security が既定でユーザーの一覧を見られるようになる。メールアドレスは `pii:read`（owner だけ）が無ければ見えない
- ユーザーの一覧は停止の有無を出すため、1 件ごとに停止の記録を読む（上限 200 件）

## 検討した代替案

- メールの部分一致の検索：暗号文のままではできず、平文か部分ごとのインデックスを持つことになり、0014 を崩す
- 読み取りもすべて監査ログに残す：既存の管理 API と揃わず、量が増える。個人情報の復号だけを残す
- 読み取りをすべて既存の管理の権限（`roles:manage` など）で許す：参照だけを渡したい support に、変更の権限まで渡すことになる
- 使っている外部 ID がある connection の削除で、常に紐付けを無効化する（Org 専用 SSO と同じ）：realm の connection は多くの
  ユーザーのログインの手段で、誤操作の影響が大きい。明示したときだけにした
