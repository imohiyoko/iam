package provider

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"github.com/imohiyoko/iam/shared/port"
)

// 送信者制約トークン（ADR 0113）。token エンドポイントで、DPoP の証明の鍵（jkt。RFC 9449）とクライアント証明書（x5t#S256。
// RFC 8705）をアクセストークンに結び付ける。公開クライアントではリフレッシュトークンも結び付け、次のリフレッシュで同じ鍵・
// 証明書を求める（機密の連携先のリフレッシュトークンは連携先の認証が守る）。結び付けを決めるのは server（フィーチャーと
// 連携先の設定を見る）で、ここでは渡されたものを保存し、照合する。

// Binding はトークンに結び付ける鍵と証明書。空なら Bearer。
type Binding struct {
	// JKT は DPoP の証明の鍵の JWK SHA-256 Thumbprint。
	JKT string
	// X5T はクライアント証明書（本人の証明書の DER）の SHA-256（base64url）。
	X5T string
}

// Bound はどちらかで結び付けているか。
func (b Binding) Bound() bool { return b.JKT != "" || b.X5T != "" }

// CertThumbprint はクライアント証明書の x5t#S256（RFC 8705 3.1）。
func CertThumbprint(der []byte) string {
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// TokenBinding はトークンの結び付け。
func TokenBinding(t port.OIDCToken) Binding { return Binding{JKT: t.JKT, X5T: t.X5T} }

// Satisfies は要求で示した鍵・証明書（got）が、トークンの結び付け（b）を満たすか。結び付けの無い項目は問わない。
func (b Binding) Satisfies(got Binding) bool {
	return eq(b.JKT, got.JKT) && eq(b.X5T, got.X5T)
}

func eq(want, got string) bool {
	return want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// refreshBinding はリフレッシュトークンに結び付けるもの。公開クライアントだけ（RFC 9449 5、RFC 8705 4）。
func refreshBinding(cl port.Client, b Binding) Binding {
	if cl.AuthMethod == port.ClientAuthNone {
		return b
	}
	return Binding{}
}

// Confirmation はイントロスペクションの cnf（RFC 9449 6.2、RFC 8705 3.2）。
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
	X5T string `json:"x5t#S256,omitempty"`
}

func confirmation(t port.OIDCToken) *Confirmation {
	if t.JKT == "" && t.X5T == "" {
		return nil
	}
	return &Confirmation{JKT: t.JKT, X5T: t.X5T}
}
