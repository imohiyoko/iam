package port

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
)

// 認証方式のプラグイン（ADR 0090、0092）。
//
// 方式は authn/method/<name>/ に置き、Authenticator を実装する。方式は Storage を直接触らず、コアが渡す
// CredentialStore（realm と方式に閉じた、復号済みの認証情報）だけを使う。フローの状態は Begin が返し、
// コアが封をして EphemeralStore に置き、Complete に渡す。

// FactorKind は要素の種類（SP 800-63B）。
type FactorKind string

const (
	FactorKnowledge  FactorKind = "knowledge"  // 知識（パスワードなど）
	FactorPossession FactorKind = "possession" // 所持（OTP の端末、セキュリティキーなど）
	FactorInherence  FactorKind = "inherence"  // 生体
)

// MethodUsage は方式を使える用途。
type MethodUsage string

const (
	UsageFirstFactor  MethodUsage = "first_factor"
	UsageSecondFactor MethodUsage = "second_factor"
	UsageRecovery     MethodUsage = "recovery"
	UsageStepUp       MethodUsage = "step_up"
)

// MethodInfo は方式の宣言。
type MethodInfo struct {
	// Name は方式の名前（API のパスの {method}、authn_credentials.method）。小文字の英数字と `_`。台帳に残るので変えない。
	Name string
	// Feature は方式を動かすフィーチャーの名前。フィーチャーが動いていなければ方式も使えない。
	// 空はコアの方式（TOTP。ADR 0101）で、コアが組み込みとして渡し、フィーチャーを問わずに動く。method.Register では空にできない。
	Feature string
	Kind    FactorKind
	// AMR は確かめたときにセッションに足す amr（RFC 8176）。
	AMR []string
	// AAL は方式で到達できる認証保証レベル（SP 800-63B。1〜3）。
	AAL int
	// Usages は使える用途。
	Usages []MethodUsage
	// DataVersion は方式固有のデータ（Credential.Data）の形のバージョン。前進のみ。
	DataVersion int
	// OutOfBand は応答が別の経路（本人の端末など）から届く方式（ADR 0104）。Complete は届くまで ErrMethodPending を返し、
	// クライアントの入力では照合しないので、コアはユーザーごとの照合の回数で数えない。
	OutOfBand bool
	// OneShot は、チャレンジを1回限りにする方式（passkey。ADR 0106）。照合に失敗しても、コアはフローを置き直さない
	// （同じチャレンジへの応答を2度受けない）。
	OneShot bool
	// ReserveRevokedLookups は、無効化した認証情報の検索キーを再登録させない方式（passkey の credential ID。4.6、ADR 0106）。
	// 作った認証情報に印を付け（Credential.ReserveLookup）、Storage が無効化で検索キーを退役済みに加える。退役済みの検索キーは、
	// 持ち主を消した後も残り、同じ方式で作れない。
	ReserveRevokedLookups bool
}

// Supports は用途 u に使えるかを返す。
func (i MethodInfo) Supports(u MethodUsage) bool {
	for _, x := range i.Usages {
		if x == u {
			return true
		}
	}
	return false
}

// MethodCredential は方式に渡す認証情報（復号済み）。ID は内部 ID で、方式の外（API）には PublicID だけを出す。
type MethodCredential struct {
	ID       string
	PublicID string
	UserID   string // 内部 ID
	// Data は方式固有のデータ（平文）。DataVersion はその形のバージョン。
	Data        []byte
	DataVersion int
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	// Sealed は保存されている暗号文。コアが書き込みの競合の検出（UpdateData）に使う。方式は触らない。
	Sealed []byte
}

// CredentialStore は、コアが方式に渡す認証情報のストア。realm と方式に閉じ、データの暗号化と復号はコアが行う。
// 呼び出し側のトランザクションに結び付くか（登録の完了）、操作ごとに短いトランザクションで動く（ログインと登録の始め。方式の重い計算
// （パスワードのハッシュ）を、直列にしたトランザクションの外で行うため。ADR 0101）。どちらでも、書き込みは比較と交換で競合を拒む。
type CredentialStore interface {
	// List はユーザー（内部 ID）の、この方式の有効な認証情報を作成時刻の順に返す。
	List(ctx context.Context, userID string) ([]MethodCredential, error)
	// FindByLookup は検索キー（方式が決める値。コアがブラインドインデックスにする）で有効な認証情報を返す。無ければ errs.NotFound。
	FindByLookup(ctx context.Context, lookup string) (MethodCredential, error)
	// Create はユーザーに認証情報を作る。lookup が空でなければ、realm と方式の中の有効なものと重複すれば errs.Conflict。
	Create(ctx context.Context, userID, lookup string, data []byte) (MethodCredential, error)
	// Update はデータを置き換える。c を読んだ後に別の書き込みがあったか、無効化されていれば errs.Conflict（原子的に判定する）。
	// 返す MethodCredential は新しいデータを持つ。
	Update(ctx context.Context, c MethodCredential, data []byte) (MethodCredential, error)
	// Revoke は認証情報を無効化する（置き換え。パスワードの変更など。ADR 0101）。c を読んだ後に別の書き込みか無効化があれば
	// errs.Conflict。
	Revoke(ctx context.Context, c MethodCredential, reason string) error
}

// MethodUsers は、ログイン ID で本人を決める方式（パスワード）に、コアが渡す本人の引き当て（ADR 0101）。
type MethodUsers interface {
	// LoginUser はログイン ID（メールアドレス）の本人の内部 ID を返す。確認済みのメールの、ログインできる状態のユーザーだけで、
	// それ以外は errs.NotFound（理由を区別しない）。ログイン ID ごとの回数の上限を超えれば *ratelimit.ExceededError。
	// 引き当てたメールに、発行するセッションを結び付ける（メールを外すと使えなくなる）。
	LoginUser(ctx context.Context, identifier string) (string, error)
}

// MethodEnv はコアが方式に渡す、呼び出しの環境。
type MethodEnv struct {
	RealmID string
	// UserID は本人の内部 ID。1要素目の Begin・Complete では空（方式が FindByLookup で決める）。
	UserID string
	// Usage は呼び出しの用途。登録では空で、復旧専用のセッションでの登録だけ UsageRecovery（今の秘密を求めない再設定。ADR 0101）。
	Usage MethodUsage
	// Credentials は認証情報のストア。
	Credentials CredentialStore
	// Now は今の時刻（Clock から）。
	Now time.Time
	// Issuer と Account は登録のときに認証器に表示する名前（発行者と、本人のメールアドレスか公開 ID）。
	Issuer, Account string
	// UserPublicID は本人の公開 ID（登録の始めだけ。passkey のユーザーハンドルにする。内部 ID は認証器に渡さない。ADR 0045、0106）。
	UserPublicID string
	// ClientIP は要求の接続元（接続元ごとの制限に使う。ADR 0104）。分からなければ空。
	ClientIP string
	// Users は1要素目で本人を引き当てる（ログイン ID で本人を決める方式だけが使う）。1要素目以外では nil。
	Users MethodUsers
	// RecentAuth は、登録で、本人の認証が直近（max_auth_age の内）か。汎用のパスは直近の認証を求めるので常に true。
	RecentAuth bool
	// ClientCertificates は要求で受け取ったクライアント証明書の連鎖（DER。先頭が本人の証明書。ADR 0103）。mTLS の専用の
	// 待ち受け（秘密鍵の所持は TLS のハンドシェイクで確かめてある）か、設定で信じたプロキシのヘッダーから、コアが取り出す。
	// 無ければ nil。連鎖・用途・失効は方式が確かめる。
	ClientCertificates [][]byte
	// Negotiate は要求の `Authorization: Negotiate` の SPNEGO のトークン（RFC 4559。Base64 を戻したもの。ADR 0107）。コアは
	// 汎用のログインの完了と登録のパスでだけ取り出す。無ければ nil。確かめるのは方式。
	Negotiate []byte
	// Principals は、方式が自分で確かめた本人の名前（Kerberos のプリンシパルなど）をユーザーに引き当てる（ADR 0107）。1要素目の
	// Complete でだけ渡し、それ以外では nil。
	Principals MethodPrincipals
}

// MethodPrincipals は、方式が確かめた外部の名前から本人を引き当てる、コアの手段（ADR 0107）。方式は Storage を触らないので、
// 結び付けの規則に要る検索だけをコアが行う。どれも、ログインできる状態のユーザーだけを返し、無ければ errs.NotFound（理由を区別しない）。
type MethodPrincipals interface {
	// EmailUser は確認済みのメールアドレスのユーザーの内部 ID を返す。
	EmailUser(ctx context.Context, email string) (string, error)
	// DirectoryUser は realm 共通の LDAP の connection（slug）で、属性 attribute が value の項目をちょうど 1 件探し、その外部 ID
	// を紐付けたユーザーの内部 ID を返す（ADR 0102）。ディレクトリに届かなければ errs.Unavailable に一致するエラー。
	DirectoryUser(ctx context.Context, connection, attribute, value string) (string, error)
}

// MethodRequest はクライアントからの入力。
type MethodRequest struct {
	// Payload は方式ごとの JSON（API では object）。空なら null。
	Payload json.RawMessage
	// State は Begin（EnrollBegin）が返した状態。Complete（EnrollComplete）でだけ渡す。
	State []byte
}

// MethodChallenge は Begin・EnrollBegin の結果。
type MethodChallenge struct {
	// Payload はクライアントに返す JSON（object）。nil なら {}。
	Payload json.RawMessage
	// State は Complete に渡す状態。コアが封をして EphemeralStore に置く（秘密を含めてよい）。
	State []byte
	// Deliver は、コアがトランザクションを確定した後に呼ぶ送信（SMS・プッシュなど。ADR 0104）。エラーならフローを置かず、
	// 送信の失敗（ErrDeliveryFailed）として返す。nil なら送らない。
	Deliver func(ctx context.Context) error
	// Events は、送信の後にコアが記録する監査ログ。
	Events []MethodEvent
	// Ref は、後で Callback の結果（MethodCallbackResult.Ref）と突き合わせるチャレンジの参照（BeginBackchannel だけ。ADR 0114）。
	// 秘密を入れない。
	Ref string
}

// MethodEvent は方式が残したい監査ログ（ADR 0104）。コアが種類を "method.<方式>.<Type>" にして、本人の公開 ID と一緒に記録する。
// Details に電話番号・宛先・コードなどの個人情報と秘密を入れない。
type MethodEvent struct {
	// Type は出来事の名前（小文字の英数字と `_`）。
	Type string
	// UserID は本人の内部 ID。空なら主体は anonymous。
	UserID  string
	Failure bool
	Details map[string]any
}

// ErrMethodPending は、別の経路からの応答がまだ届いていないこと（MethodInfo.OutOfBand の方式の Complete）。コアはフローを、
// 回数を数えずに置き直す。
var ErrMethodPending = errs.WithCode(errs.KindFailedPrecondition, "authorization_pending", "method: authorization pending")

// ErrNegotiate は、方式が HTTP の Negotiate の認証（RFC 4559）を求めること（要求に `Authorization: Negotiate` が無い。ADR 0107）。
// コアはフローを回数を数えずに置き直し、401 と `WWW-Authenticate: Negotiate` を返す（ブラウザがトークンを付けて送り直す）。
var ErrNegotiate = errs.WithCode(errs.KindUnauthenticated, "negotiate", "method: negotiate authentication required")

// ErrDeliveryFailed は送信（Deliver）の失敗。
var ErrDeliveryFailed = errs.WithCode(errs.KindUnavailable, "delivery_failed", "method: delivery failed")

// MethodResult はログイン（Complete）の結果。
type MethodResult struct {
	// Credential は使った認証情報（CredentialStore から得たもの）。
	Credential MethodCredential
	// AMR は足す amr。空なら MethodInfo.AMR。
	AMR []string
	// KnowledgeBreached は、知識の要素（パスワード）が漏洩済みか。確かめなかったか、確かめられなければ nil（警告の評価。ADR 0051）。
	KnowledgeBreached *bool
	// Details はコアがログインの成功の監査ログに足す詳細（ADR 0106）。個人情報と秘密を入れない。
	Details map[string]any
}

// MethodEnrollment は登録（EnrollComplete）の結果。
type MethodEnrollment struct {
	// Credential は作った認証情報（CredentialStore.Create の結果）。
	Credential MethodCredential
	// Payload はクライアントに返す JSON（object）。nil なら {}。
	Payload json.RawMessage
	// Details はコアが登録の監査ログに足す詳細（ADR 0106）。個人情報と秘密を入れない。
	Details map[string]any
}

// MethodAuditDetails は、方式が返すエラーのうち、失敗の監査ログに詳細を足したいもの（認証器のポリシーによる拒否など。ADR 0106）。
// コアは、本人確認の後の拒否（errs.Denial）でも、この詳細を付けて失敗を記録する。個人情報と秘密を入れない。
type MethodAuditDetails interface {
	error
	AuditDetails() map[string]any
}

// Authenticator は認証方式（ADR 0090）。照合の失敗（利用者の入力による）は errs.AuthenticationFailed に一致するエラーで返す。
// それ以外のエラーは基盤の障害として扱う。
type Authenticator interface {
	Info() MethodInfo
	// Begin はログイン（1要素目・2要素目など）のチャレンジを作る。
	Begin(ctx context.Context, env MethodEnv, in MethodRequest) (MethodChallenge, error)
	// Complete は応答を確かめ、使った認証情報を返す。再利用の拒否などの書き込みは env.Credentials で行う。
	Complete(ctx context.Context, env MethodEnv, in MethodRequest) (MethodResult, error)
	// EnrollBegin は登録を始める。
	EnrollBegin(ctx context.Context, env MethodEnv, in MethodRequest) (MethodChallenge, error)
	// EnrollComplete は登録を確かめ、env.Credentials.Create で認証情報を作る。
	EnrollComplete(ctx context.Context, env MethodEnv, in MethodRequest) (MethodEnrollment, error)
	// Revoke は無効化の前に呼ぶ（方式の外の片付け）。エラーなら無効化しない。
	Revoke(ctx context.Context, env MethodEnv, c MethodCredential) error
}

// MethodCallbackResult は Callback の結果。
type MethodCallbackResult struct {
	// Payload は呼び出し元に返す JSON（object）。nil なら {}。
	Payload json.RawMessage
	Events  []MethodEvent
	// Ref は、応答したチャレンジの参照（BeginBackchannel が返した MethodChallenge.Ref と同じ。ADR 0114）。コアはこれで
	// CIBA の要求に結果を記録する。応答でなければ空。
	Ref string
}

// CallbackAuthenticator は、別の経路（本人の端末など）からの応答を受ける方式（任意。ADR 0104）。
// POST /v1/login/methods/{method}:callback で、セッションを要さずに呼ぶ。本人の確認（端末の鍵の署名など）は方式が行う。
// env.UserID と env.Usage は空。照合の失敗は errs.AuthenticationFailed、入力の誤りは errs.Invalid で返す。
type CallbackAuthenticator interface {
	Authenticator
	Callback(ctx context.Context, env MethodEnv, in MethodRequest) (MethodCallbackResult, error)
}

// MethodHTTPRequest は方式のエンドポイント（EndpointAuthenticator）への要求（ADR 0108）。
type MethodHTTPRequest struct {
	// Endpoint はパスの {endpoint}（方式が決める名前。小文字の英数字と `_`）。
	Endpoint string
	// HTTPMethod は GET か POST。
	HTTPMethod string
	// Query はクエリ。Form は application/x-www-form-urlencoded の本文（POST だけ。それ以外の本文は渡さない）。
	Query, Form url.Values
}

// MethodHTTPResponse は方式のエンドポイントの応答。コアは Cache-Control: no-store を付けて、そのまま返す。
type MethodHTTPResponse struct {
	Status      int
	ContentType string
	Body        []byte
	// Events は、応答の後にコアが記録する方式の監査ログ。
	Events []MethodEvent
}

// EndpointAuthenticator は、HTTP の形を外部の仕様が決めるエンドポイントを持つ方式（任意。ADR 0108）。OpenID4VP のウォレットの
// request_uri・response_uri のように、JSON の汎用のパスを話せない相手から呼ばれる。
// GET・POST /v1/login/methods/{method}/endpoints/{endpoint} で、セッションを要さず、CrossOriginProtection の外で呼ぶ。
// 本人の確認は方式が行い、入力は全部疑う。env.UserID と env.Usage は空。照合の失敗・入力の誤り・見つからないは errs.AuthenticationFailed・
// errs.Invalid・errs.NotFound で返す（コアは 400 にする）。
type EndpointAuthenticator interface {
	Authenticator
	Endpoint(ctx context.Context, env MethodEnv, req MethodHTTPRequest) (MethodHTTPResponse, error)
}

// MethodSetup は、設定を持つ方式（ConfigurableAuthenticator）に起動時に渡すもの（ADR 0104）。
type MethodSetup struct {
	// RealmID は方式を使う realm（方式は realm ごとに設定する）。
	RealmID string
	// RealmSlug は realm の slug（設定ファイルで realm ごとの設定を書くときのキー）。
	RealmSlug string
	// Decode は設定ファイルの methods.<方式> を v に読む（知らない項目はエラー。設定が無ければ何もしない）。入れ子の設定を
	// 持つ方式が使う（ADR 0103）。nil なら Options を使う（テスト用）。
	Decode func(v any) error
	// Options は methods.<方式> を文字列の項目として読んだもの（Decode が nil のときだけ使う）。StringOptions で読む。
	// 知らない項目はエラーにする。
	Options map[string]string
	// Ephemeral は方式の名前と realm で前置きした EphemeralStore（コアのキーには届かない）。レートリミットや、
	// 別の経路からの応答の受け渡しに使う。秘密を置くなら方式がハッシュにする。
	Ephemeral EphemeralStore
	// Blind は値のブラインドインデックス（base64url）を返す。個人情報（電話番号など）をキーにするときに使う。
	Blind func(ctx context.Context, value string) (string, error)
	// SMS と Push は送信のポート。設定されていなければ nil。
	SMS  SMSSender
	Push PushSender
	// BaseURL は realm の公開の URL（server.public_url。realm のパスの接頭辞を含み、末尾の / は無い）。外部に渡す
	// 戻り先の URL（OpenID4VP の response_uri など。ADR 0108）を作るのに使う。設定されていなければ空。
	BaseURL string
	// Dev は開発モードか。
	Dev   bool
	Clock clock.Clock
	Log   *slog.Logger
}

// StringOptions は methods.<方式> を文字列の項目として返す（ADR 0104）。入れ子の値があればエラー。
func (s MethodSetup) StringOptions() (map[string]string, error) {
	if s.Decode == nil {
		return s.Options, nil
	}
	var m map[string]string
	if err := s.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// ConfigurableAuthenticator は、起動時に設定と送信のポートを受け取る方式（任意。ADR 0104）。Setup は設定済みの方式を返す。
// 設定や送信のポートが足りなければエラーにする（起動を止める。fail-closed）。nil を返すと、その realm では方式を動かさない
// （realm ごとの設定が無いなど。ADR 0103）。
type ConfigurableAuthenticator interface {
	Authenticator
	Setup(ctx context.Context, s MethodSetup) (Authenticator, error)
}

// Credential は authn_credentials の1行（ADR 0090、0092）。Data はユーザーのデータ鍵で暗号化した、方式固有のデータ。
// Lookup は方式が宣言した検索キーのブラインドインデックス（無ければ nil）。無効化は削除ではなく RevokedAt を記録する（4.6）。
// ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Credential struct {
	ID       string
	PublicID string
	RealmID  string
	UserID   string
	Method   string
	Lookup   []byte
	// LookupKeyID は Lookup を作ったインデックス鍵の ID（Lookup が無ければ空）。鍵を切り替えた後も前の鍵で引くのに使う（ADR 0103）。
	LookupKeyID string
	Data        []byte
	DataVersion int
	// PreferredOrgID はこの認証情報でログインしたときに入る Org（内部 ID。4.4。passkey が使う。ADR 0106）。空なら指定なし。
	PreferredOrgID string
	// ReserveLookup は、無効化で Lookup を退役済みに加える（方式の MethodInfo.ReserveRevokedLookups。ADR 0106）。
	ReserveLookup bool
	CreatedAt     time.Time
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
	RevokeReason  string
}

// RetiredLookup は退役した検索キー（authn_retired_credential_lookups の1行。ADR 0106）。無効化した認証情報の検索キーで、
// 同じ realm・方式では作れない。持ち主の消去でも消さない。
type RetiredLookup struct {
	RealmID     string
	Method      string
	Lookup      []byte
	LookupKeyID string
	RetiredAt   time.Time
}

// CredentialRepo は authn_credentials の Repository。Storage は方式を知らない。
type CredentialRepo interface {
	// Create は (realm, PublicID) が重複するか、Lookup が空でなく、同じ (realm, Method, Lookup) の無効化していないものがあるか、
	// 無効化していないものを作るときに (realm, Method, Lookup) が退役済みなら errs.Conflict を返す（原子的に判定する）。
	Create(ctx context.Context, c Credential) error
	// Get は内部 ID で返す（無効化したものも）。無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (Credential, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Credential, error)
	// GetByLookup は無効化していないものを返す。無ければ errs.NotFound。
	GetByLookup(ctx context.Context, realmID, method string, lookup []byte) (Credential, error)
	// LookupKeyIDs は方式の、無効化していない検索キーを持つ認証情報の LookupKeyID を、重複を除いて名前の順に返す。
	LookupKeyIDs(ctx context.Context, realmID, method string) ([]string, error)
	// ListByUser はユーザーの認証情報を作成時刻の順（同時刻は ID の順）に返す（無効化したものも含む）。method が空でなければ、その方式だけ。
	ListByUser(ctx context.Context, realmID, userID, method string) ([]Credential, error)
	// UpdateData は、今のデータが old と同じで無効化していなければ、データとその形のバージョンを置き換える。
	// 違えば（別の書き込みか無効化があった）errs.Conflict（原子的に判定する。再利用の拒否に使う）。無ければ errs.NotFound。
	UpdateData(ctx context.Context, realmID, id string, old, data []byte, dataVersion int) error
	// Used は最終使用の時刻を記録する。無ければ errs.NotFound。
	Used(ctx context.Context, realmID, id string, at time.Time) error
	// Revoke は at に無効化する。ReserveLookup で Lookup があれば、検索キーを退役済みに加える（既にあれば何もしない）。
	// 既に無効化されていれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
	// SetPreferredOrg はログインで入る Org（内部 ID。空なら指定なし）を変える。無ければ errs.NotFound（ADR 0106）。
	SetPreferredOrg(ctx context.Context, realmID, id, orgID string) error
	// LookupRetired は (realm, method, lookup) が退役済みかを返す。
	LookupRetired(ctx context.Context, realmID, method string, lookup []byte) (bool, error)
	// RetiredLookupKeyIDs は方式の退役済みの検索キーの LookupKeyID を、重複を除いて名前の順に返す（インデックス鍵の切り替えの後も、
	// 前の鍵で退役させたものを拒むため）。
	RetiredLookupKeyIDs(ctx context.Context, realmID, method string) ([]string, error)
	// MoveUser は fromUserID の認証情報（無効化したものも）を toUserID に移し、移した数を返す（統合。11.6）。
	// データの暗号化し直しは呼び出し側が先に行う。
	MoveUser(ctx context.Context, realmID, fromUserID, toUserID string) (int, error)
	// Count は方式の認証情報の件数（無効化したものを含む、全 realm）を返す（フィーチャーの無効化。11.12）。
	Count(ctx context.Context, method string) (int, error)
	// Purge は方式の認証情報を全 realm から最大 limit 件消し、消した件数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, method string, limit int) (int, error)
}

// BackchannelRequest は、CIBA の要求を本人の端末に送るときの中身（ADR 0114）。本人に見せるもので、秘密を含まない。
type BackchannelRequest struct {
	// ClientName は連携先の名前。BindingMessage は連携先が付けた binding_message（無ければ空）。
	ClientName     string
	BindingMessage string
	Scopes         []string
	// ExpiresAt は要求の期限。チャレンジもこれより長くしない。
	ExpiresAt time.Time
}

// BackchannelAuthenticator は、CIBA の本人の承認を受けられる方式（任意。ADR 0114）。BeginBackchannel は env.UserID の本人の端末に
// 要求を送るチャレンジを返す（送信は Deliver）。結果は Callback が返す MethodCallbackResult.Ref で知らせ、コアは Complete
// （State は BeginBackchannel が返したもの）で取り出す。本人が端末を持たなければ errs.NotFound。
type BackchannelAuthenticator interface {
	Authenticator
	BeginBackchannel(ctx context.Context, env MethodEnv, req BackchannelRequest) (MethodChallenge, error)
}
