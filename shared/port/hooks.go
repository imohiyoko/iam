package port

import "context"

// フロー フック（design.md 11.8、ADR 0081）。

// フローフックの名前。
const (
	HookPreRegistration    = "pre_registration"
	HookPostAuthentication = "post_authentication"
	HookPreMembershipEnd   = "pre_membership_end"
	HookPreToken           = "pre_token"
)

// Hooks はフローフックの名前の一覧。
var Hooks = []string{HookPreRegistration, HookPostAuthentication, HookPreMembershipEnd, HookPreToken}

// FlowHook はフローフックの実装（Go のインターフェースか Webhook）。ctx には呼び出し側がタイムアウトを付ける。
type FlowHook interface {
	Call(ctx context.Context, in HookInput) (HookResult, error)
}

// HookInput はフックに渡す事実。ID は公開 ID（ADR 0045）。フックごとに使う項目だけを埋める。
type HookInput struct {
	Hook  string `json:"hook"`
	Realm string `json:"realm"` // realm の slug
	// UserID は pre_registration のほか。
	UserID string `json:"user_id,omitempty"`
	// Email・VerifiedVia は pre_registration（作るユーザーのアドレスと、その確認の経路）。
	Email       string `json:"email,omitempty"`
	VerifiedVia string `json:"verified_via,omitempty"`
	// AuthMethods は post_authentication と pre_token（amr）。
	AuthMethods []string `json:"auth_methods,omitempty"`
	// OrgID は Org の公開 ID（pre_membership_end、pre_token の Org の文脈）。
	OrgID string `json:"org_id,omitempty"`
	// MembershipID・EndReason は pre_membership_end（left / removed）。
	MembershipID string `json:"membership_id,omitempty"`
	EndReason    string `json:"end_reason,omitempty"`
	// ClientID・Scopes は pre_token。
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

// HookResult はフックの判定。Allow でなければ操作を止める。Reason はログにだけ残す（本人には返さない）。
type HookResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
	// Risk は post_authentication でセッションに保存するリスクの点数（種類 → 0〜100。ADR 0084）。一覧に無い・止めた種類と
	// 範囲外の値は捨てる。
	Risk map[string]int `json:"risk,omitempty"`
	// Claims は pre_token で ID トークンに足すクレーム（予約されたクレームは上書きできない）。
	Claims map[string]any `json:"claims,omitempty"`
}
