package port

import (
	"context"
	"time"
)

// カスタム属性（design.md 11.7、ADR 0080）。

// AttributeType は属性の型。
type AttributeType string

const (
	AttributeString  AttributeType = "string"
	AttributeInteger AttributeType = "integer"
	AttributeBoolean AttributeType = "boolean"
	AttributeEnum    AttributeType = "enum"
)

// AttributeDef は attribute_defs の1行。Type と Encrypted は作成後に変えない。
type AttributeDef struct {
	RealmID      string
	Key          string // realm 内で一意。API とトークンでの名前
	Type         AttributeType
	Values       []string // enum の選択肢
	MaxLength    int      // string の最大の文字数
	UserEditable bool     // 本人が公開 API で書ける
	InToken      bool     // スコープ attributes で ID トークン・UserInfo に載せる
	Encrypted    bool     // 値をユーザーのデータ鍵で暗号化する
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserAttribute は user_attributes の1行。Value は JSON の値か、その暗号文（定義の Encrypted）。
type UserAttribute struct {
	RealmID   string
	UserID    string
	Key       string
	Value     []byte
	UpdatedAt time.Time
}

// AttributeRepo は attribute_defs と user_attributes の Repository。
type AttributeRepo interface {
	// CreateDef は (realm, key) が重複すれば errs.Conflict を返す。
	CreateDef(ctx context.Context, d AttributeDef) error
	GetDef(ctx context.Context, realmID, key string) (AttributeDef, error)
	// ListDefs は key の順に返す。
	ListDefs(ctx context.Context, realmID string) ([]AttributeDef, error)
	// UpdateDef は Values・MaxLength・UserEditable・InToken・UpdatedAt を置き換える。無ければ errs.NotFound。
	UpdateDef(ctx context.Context, d AttributeDef) error
	// DeleteDef は定義と、その属性のすべての値を消す。無ければ errs.NotFound。
	DeleteDef(ctx context.Context, realmID, key string) error

	// ListValues はユーザーの値を key の順に返す。
	ListValues(ctx context.Context, realmID, userID string) ([]UserAttribute, error)
	// SetValue は値を置く（あれば置き換える）。
	SetValue(ctx context.Context, a UserAttribute) error
	// DeleteValue は値を消す。無くてもよい。
	DeleteValue(ctx context.Context, realmID, userID, key string) error

	// Count は定義と値の数（すべての realm）。
	Count(ctx context.Context) (int, error)
	// Purge は値を、その後に定義を、合わせて最大 limit 件消し、消した件数を返す。
	Purge(ctx context.Context, limit int) (int, error)
}
