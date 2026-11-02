package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
)

// Pushed Authorization Requests（RFC 9126、ADR 0112）。連携先は認可要求のパラメーターを、認証した上でバックチャネルの
// PAR エンドポイントに送り、短命の request_uri を受け取る。ブラウザには client_id と request_uri だけを渡す。
//
// 預かるのは送られたパラメーター（クライアントの認証の項目を除く）そのもので、authorize で request_uri を受けたときに
// それだけを認可要求として読み、ふつうの認可要求と同じ確かめを最初からやり直す（待つ間に連携先の登録が変わってもよい）。
// 状態は認可コードと同じく EphemeralStore に封をして置き、キーは request_uri の秘密の部分の SHA-256。1 回だけ取り出す。
//
//	oidc:par:v1:<秘密>  realm・client_id・パラメーター・期限

// PARFeature は Pushed Authorization Requests のフィーチャー（既定オフ）。
var PARFeature = feature.Feature{Name: feature.PAR, DataVersion: 1}

// RequestURIPrefix は request_uri の接頭辞（RFC 9126 2.2）。
const RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// 期限と大きさの上限。
const (
	// DefaultPushedTTL は request_uri の既定の期限（RFC 9126 2.2 の例と同じ 60 秒）。
	DefaultPushedTTL = time.Minute
	// MaxPushedTTL は設定できる期限の上限。
	MaxPushedTTL = 10 * time.Minute
	// maxPushedBytes は預かるパラメーターの大きさ（JSON）の上限。
	maxPushedBytes = 16 << 10
)

// ErrRequestURI は request_uri が使えない（形が違う・知らない・期限切れ・使用済み・別の連携先。理由は返さない）。
var ErrRequestURI = errs.WithCode(errs.KindInvalid, "invalid_request_uri", "invalid request_uri")

// ErrPushedTooLarge は預かるパラメーターが大きすぎる。
var ErrPushedTooLarge = errs.WithCode(errs.KindInvalid, "invalid_request", "pushed authorization request too large")

// pushedOmit は預からないパラメーター（クライアントの認証の項目）。
var pushedOmit = []string{"client_secret", "client_assertion", "client_assertion_type"}

type pushed struct {
	RealmID   string     `json:"realm_id"`
	ClientID  string     `json:"client_id"`
	Params    url.Values `json:"params"`
	ExpiresAt time.Time  `json:"expires_at"`
}

const (
	pushedPurpose = "flow.oidc_par"
	pushedPrefix  = "oidc:par:v1:"
)

// Push は認証した連携先 clientID の認可要求のパラメーターを預かり、request_uri とその期限を返す（RFC 9126 2.2）。
// パラメーターの確かめ（ふつうの認可要求と同じ）は呼び出し側が先に済ませる。
func (f *Flow) Push(ctx context.Context, realmID, clientID string, params url.Values) (string, time.Duration, error) {
	kept := url.Values{}
	for k, vs := range params {
		if !slices.Contains(pushedOmit, k) {
			kept[k] = append([]string(nil), vs...)
		}
	}
	ttl := min(ttlOr(f.PushedTTL, DefaultPushedTTL), MaxPushedTTL)
	p := pushed{RealmID: realmID, ClientID: clientID, Params: kept, ExpiresAt: f.Clock.Now().Add(ttl)}
	b, err := json.Marshal(p)
	if err != nil {
		return "", 0, err
	}
	if len(b) > maxPushedBytes {
		return "", 0, ErrPushedTooLarge
	}
	secret, err := randomString()
	if err != nil {
		return "", 0, err
	}
	if err := f.put(ctx, digestKey(pushedPrefix, secret), pushedPurpose, p, ttl); err != nil {
		return "", 0, err
	}
	return RequestURIPrefix + secret, ttl, nil
}

// TakePushed は request_uri の認可要求のパラメーターを 1 回だけ取り出す。realm・連携先（clientID）・期限が合わなければ
// ErrRequestURI（取り出したものは合わなくても二度と使えない）。
func (f *Flow) TakePushed(ctx context.Context, realmID, clientID, requestURI string) (url.Values, error) {
	secret, ok := strings.CutPrefix(requestURI, RequestURIPrefix)
	if !ok || secret == "" || len(secret) > 128 {
		return nil, ErrRequestURI
	}
	b, ok, err := f.Cache.Take(ctx, digestKey(pushedPrefix, secret))
	if err != nil {
		return nil, err
	}
	var p pushed
	if !ok || f.open(ctx, pushedPurpose, b, &p) != nil || p.RealmID != realmID || p.ClientID != clientID || !f.Clock.Now().Before(p.ExpiresAt) {
		return nil, ErrRequestURI
	}
	return p.Params, nil
}
