package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// JWT のアクセストークン（RFC 9068。ADR 0123）。
//
// JWT にしても、トークンの行（OIDCTokens）はいままでどおり作る。行の Hash は JWT 全体の SHA-256 で、iam での検証
// （UserInfo・イントロスペクション・失効・送信者制約）は jti で行を引き、JWT 全体の一致で確かめる（署名の検証は要らない）。
// リソースサーバーは JWKS で署名を確かめられるが、失効・停止は期限（oidc.access_token_ttl）まで届かない。

// JWTAccessFeature は JWT のアクセストークンのフィーチャー（既定オフ）。
var JWTAccessFeature = feature.Feature{Name: feature.JWTAccessTokens, DataVersion: 1}

// JWTAccessType は JWS のヘッダーの typ（RFC 9068 2.1）。
const JWTAccessType = "at+jwt"

// jwtAccessToken は認可 g のアクセストークンを JWT で作る。tid は jti（トークンの行の ID）。
func (t *Tokens) jwtAccessToken(ctx context.Context, tx port.Tx, cl port.Client, g port.Grant, tid string, b Binding, now, exp time.Time) (string, error) {
	u, err := tx.Users().Get(ctx, g.RealmID, g.UserID)
	if err != nil {
		return "", err
	}
	orgPublicID, err := t.orgPublicID(ctx, tx, g.RealmID, g.OrgID)
	if err != nil {
		return "", err
	}
	// aud は自前の API に向けた認可ならリソースの URI（RFC 8707）、それ以外は連携先（RFC 9068 3 は aud を求める）。
	aud := []string{cl.PublicID}
	if ResourceBound(g) {
		aud = g.Audiences
	}
	claims := map[string]any{"iss": t.Issuer, "sub": u.PublicID, "aud": aud, "client_id": cl.PublicID, "jti": tid,
		"iat": now.Unix(), "exp": exp.Unix(), "auth_time": g.AuthTime.Unix(), "sid": g.SID}
	if len(g.Scopes) > 0 {
		claims["scope"] = strings.Join(g.Scopes, " ")
	}
	if len(g.AuthMethods) > 0 {
		claims["amr"] = g.AuthMethods
	}
	if t.ACR && g.ACR != "" {
		claims["acr"] = g.ACR
	}
	if orgPublicID != "" {
		claims["org_id"] = orgPublicID
	}
	if c := confirmation(port.OIDCToken{JKT: b.JKT, X5T: b.X5T}); c != nil {
		claims["cnf"] = c
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return t.Keys.Sign(ctx, tx, g.RealmID, cl.IDTokenAlg, JWTAccessType, payload)
}

// newJWTAccessID は JWT のアクセストークンの jti（トークンの行の ID）。
func newJWTAccessID() string { return id.NewExternal(id.AccessToken) }

// jwtHash は JWT のアクセストークンの行に置く SHA-256。
func jwtHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// splitJWTAccess は JWT のアクセストークンから jti と JWT 全体の SHA-256 を取り出す。署名はここでは確かめない
// （行の Hash と JWT 全体の一致で確かめる）。JWT の形でなければ false。
func splitJWTAccess(token string) (string, []byte, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, false
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if json.Unmarshal(b, &c) != nil || c.JTI == "" {
		return "", nil, false
	}
	return c.JTI, jwtHash(token), true
}
