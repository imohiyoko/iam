package port

import (
	"context"
	"encoding/json"
	"time"
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
// 呼び出し側のトランザクションの中でだけ使える。
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
}

// MethodEnv はコアが方式に渡す、呼び出しの環境。
type MethodEnv struct {
	RealmID string
	// UserID は本人の内部 ID。1要素目の Begin・Complete では空（方式が FindByLookup で決める）。
	UserID string
	// Usage は呼び出しの用途（登録では空）。
	Usage MethodUsage
	// Credentials は認証情報のストア。
	Credentials CredentialStore
	// Now は今の時刻（Clock から）。
	Now time.Time
	// Issuer と Account は登録のときに認証器に表示する名前（発行者と、本人のメールアドレスか公開 ID）。
	Issuer, Account string
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
}

// MethodResult はログイン（Complete）の結果。
type MethodResult struct {
	// Credential は使った認証情報（CredentialStore から得たもの）。
	Credential MethodCredential
	// AMR は足す amr。空なら MethodInfo.AMR。
	AMR []string
}

// MethodEnrollment は登録（EnrollComplete）の結果。
type MethodEnrollment struct {
	// Credential は作った認証情報（CredentialStore.Create の結果）。
	Credential MethodCredential
	// Payload はクライアントに返す JSON（object）。nil なら {}。
	Payload json.RawMessage
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

// Credential は authn_credentials の1行（ADR 0090、0092）。Data はユーザーのデータ鍵で暗号化した、方式固有のデータ。
// Lookup は方式が宣言した検索キーのブラインドインデックス（無ければ nil）。無効化は削除ではなく RevokedAt を記録する（4.6）。
// ID は内部 ID で、API に出すのは PublicID（ADR 0045）。
type Credential struct {
	ID           string
	PublicID     string
	RealmID      string
	UserID       string
	Method       string
	Lookup       []byte
	Data         []byte
	DataVersion  int
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// CredentialRepo は authn_credentials の Repository。Storage は方式を知らない。
type CredentialRepo interface {
	// Create は (realm, PublicID) が重複するか、Lookup が空でなく、同じ (realm, Method, Lookup) の無効化していないものがあれば
	// errs.Conflict を返す（原子的に判定する）。
	Create(ctx context.Context, c Credential) error
	// Get は内部 ID で返す（無効化したものも）。無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (Credential, error)
	GetByPublicID(ctx context.Context, realmID, publicID string) (Credential, error)
	// GetByLookup は無効化していないものを返す。無ければ errs.NotFound。
	GetByLookup(ctx context.Context, realmID, method string, lookup []byte) (Credential, error)
	// ListByUser はユーザーの認証情報を作成時刻の順（同時刻は ID の順）に返す（無効化したものも含む）。method が空でなければ、その方式だけ。
	ListByUser(ctx context.Context, realmID, userID, method string) ([]Credential, error)
	// UpdateData は、今のデータが old と同じで無効化していなければ、データとその形のバージョンを置き換える。
	// 違えば（別の書き込みか無効化があった）errs.Conflict（原子的に判定する。再利用の拒否に使う）。無ければ errs.NotFound。
	UpdateData(ctx context.Context, realmID, id string, old, data []byte, dataVersion int) error
	// Used は最終使用の時刻を記録する。無ければ errs.NotFound。
	Used(ctx context.Context, realmID, id string, at time.Time) error
	// Revoke は at に無効化する。既に無効化されていれば何もしない。無ければ errs.NotFound。
	Revoke(ctx context.Context, realmID, id string, at time.Time, reason string) error
	// MoveUser は fromUserID の認証情報（無効化したものも）を toUserID に移し、移した数を返す（統合。11.6）。
	// データの暗号化し直しは呼び出し側が先に行う。
	MoveUser(ctx context.Context, realmID, fromUserID, toUserID string) (int, error)
	// Count は方式の認証情報の件数（無効化したものを含む、全 realm）を返す（フィーチャーの無効化。11.12）。
	Count(ctx context.Context, method string) (int, error)
	// Purge は方式の認証情報を全 realm から最大 limit 件消し、消した件数を返す（フィーチャーの無効化）。
	Purge(ctx context.Context, method string, limit int) (int, error)
}
