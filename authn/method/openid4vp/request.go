package openid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
)

// QueryID は DCQL の資格情報の問い合わせの ID（vp_token のキー）。
const QueryID = "credential"

// FormatSDJWTVC は DCQL の SD-JWT VC の形式。
const FormatSDJWTVC = "dc+sd-jwt"

// selfIssuedAudience は、ウォレットのメタデータを事前に知らないとき（静的な発見）の要求のオブジェクトの aud（OpenID4VP 5.8）。
const selfIssuedAudience = "https://self-issued.me/v2"

// dcqlQuery は求める資格情報（1 つ）。claims は結び付けの値と属性（必須）。link_by_email の発行者があれば、メールアドレスを
// 任意として足す（claim_sets の 1 つ目がメールアドレスを含む組、2 つ目が含まない組。ウォレットは満たせる最初の組で答える）。
// メールアドレスは link_by_email の発行者の、結び付けの無いときにだけ使う（verify も無ければ引き当てないだけにする）。
func (p *policy) dcqlQuery() map[string]any {
	var claims []map[string]any
	var ids []any
	var seen []string
	add := func(path []any) (string, bool) {
		b, _ := json.Marshal(path)
		for _, s := range seen {
			if s == string(b) {
				return "", false
			}
		}
		seen = append(seen, string(b))
		id := fmt.Sprintf("c%d", len(claims))
		claims = append(claims, map[string]any{"id": id, "path": path})
		return id, true
	}
	if id, ok := add(p.subject); ok {
		ids = append(ids, id)
	}
	for _, name := range sortedKeys(p.attributes) {
		if id, ok := add(p.attributes[name]); ok {
			ids = append(ids, id)
		}
	}
	q := map[string]any{"id": QueryID, "format": FormatSDJWTVC, "meta": map[string]any{"vct_values": p.vcts}, "claims": claims}
	if p.linkByEmail {
		// 必須の値と同じ path なら、既に必須なので組を分けない。
		if id, ok := add(p.email); ok {
			q["claims"] = claims
			q["claim_sets"] = []any{append(slices.Clone(ids), id), ids}
		}
	}
	return map[string]any{"credentials": []any{q}}
}

// clientMetadata は検証者のメタデータ（受ける形式と alg）。
func clientMetadata() map[string]any {
	algs := sdjwt.AlgorithmNames()
	return map[string]any{"vp_formats_supported": map[string]any{
		FormatSDJWTVC: map[string]any{"sd-jwt_alg_values": algs, "kb-jwt_alg_values": algs},
	}}
}

// authorizationRequest はウォレットを開く URL を作る。redirect_uri の接頭辞は署名できないので値で URL に載せ、x509_* は署名した要求の
// オブジェクトを request_uri で渡す（返す reqID・reqJWT を EphemeralStore に置く）。
func (r *runtime) authorizationRequest(state, nonce string, now time.Time) (string, string, string, error) {
	dcql, err := json.Marshal(r.p.dcqlQuery())
	if err != nil {
		return "", "", "", err
	}
	meta, err := json.Marshal(clientMetadata())
	if err != nil {
		return "", "", "", err
	}
	q := url.Values{}
	q.Set("client_id", r.clientID)
	if r.p.signer == nil {
		q.Set("response_type", "vp_token")
		q.Set("response_mode", "direct_post")
		q.Set("response_uri", r.responseURI)
		q.Set("nonce", nonce)
		q.Set("state", state)
		q.Set("dcql_query", string(dcql))
		q.Set("client_metadata", string(meta))
		return r.p.authzEndpoint + "?" + q.Encode(), "", "", nil
	}
	claims := map[string]any{
		"response_type": "vp_token", "response_mode": "direct_post", "response_uri": r.responseURI, "client_id": r.clientID,
		"nonce": nonce, "state": state, "dcql_query": json.RawMessage(dcql), "client_metadata": json.RawMessage(meta),
		"aud": selfIssuedAudience, "iat": now.Unix(), "exp": now.Add(r.p.requestTTL).Unix(),
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", "", "", err
	}
	obj, err := r.p.signer.Sign(body)
	if err != nil {
		return "", "", "", err
	}
	jwt, err := obj.CompactSerialize()
	if err != nil {
		return "", "", "", err
	}
	reqID, _, err := random(32)
	if err != nil {
		return "", "", "", err
	}
	q.Set("request_uri", r.requestURI+"?id="+reqID)
	return r.p.authzEndpoint + "?" + q.Encode(), reqID, jwt, nil
}
