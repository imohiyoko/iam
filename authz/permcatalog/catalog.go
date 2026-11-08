// Package permcatalog は連携先の権限のカタログ（ADR 0121）。連携先の権限は `<接頭辞>.<リソース>:<操作>` の形で、登録した
// カタログにある権限（と、カタログにあるリソースの `*`）だけを、独自のロール・トークンのスコープ・要件に使える。
package permcatalog

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 上限。realm 全体のカタログの数には上限を置かず、1 つのカタログの中だけで数える。
const (
	MaxPermissions       = 500
	MaxDisplayNameLength = 64
	MaxDescriptionLength = 256
)

// ResourceType は authz:check をカタログの単位で付与するときの resource_type（resource_id は接頭辞）。
const ResourceType = "permission_catalog"

// エラーのコード。
const (
	CodeInvalidCatalog    = "invalid_catalog"
	CodeUnknownPermission = "unknown_permission"
	CodeCatalogInUse      = "catalog_in_use"
)

func invalid(msg string) error { return errs.WithCode(errs.KindInvalid, CodeInvalidCatalog, msg) }

func validText(s string, max int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
}

// Normalize はカタログの形を確かめ、権限を名前の順に並べる。権限はすべてそのカタログの接頭辞の下の連携先の権限で、
// 操作の `*` は使えない（`*` はロールの側でカタログのリソースに当てる）。
func Normalize(c port.PermissionCatalog) (port.PermissionCatalog, error) {
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	if !role.ValidCatalogPrefix(c.Prefix) {
		return c, invalid("invalid prefix")
	}
	if c.DisplayName == "" || !validText(c.DisplayName, MaxDisplayNameLength) {
		return c, invalid("invalid display_name")
	}
	if len(c.Permissions) > MaxPermissions {
		return c, invalid("too many permissions")
	}
	ps := make([]port.PermissionDef, 0, len(c.Permissions))
	for _, p := range c.Permissions {
		prefix, ok := role.CatalogPrefix(p.Name)
		if !ok || prefix != c.Prefix || strings.HasSuffix(p.Name, ":*") {
			return c, invalid("invalid permission " + p.Name)
		}
		if !validText(p.Description, MaxDescriptionLength) {
			return c, invalid("invalid description of " + p.Name)
		}
		ps = append(ps, p)
	}
	slices.SortFunc(ps, func(a, b port.PermissionDef) int { return cmp.Compare(a.Name, b.Name) })
	for i := 1; i < len(ps); i++ {
		if ps[i].Name == ps[i-1].Name {
			return c, invalid("duplicate permission " + ps[i].Name)
		}
	}
	c.Permissions = ps
	return c, nil
}

// Covers はカタログ c が権限 p を持つかを返す。p はカタログにある権限か、カタログにあるリソースの `*`。
func Covers(c port.PermissionCatalog, p string) bool {
	if res, ok := strings.CutSuffix(p, ":*"); ok {
		return slices.ContainsFunc(c.Permissions, func(d port.PermissionDef) bool { return strings.HasPrefix(d.Name, res+":") })
	}
	_, found := slices.BinarySearchFunc(c.Permissions, p, func(d port.PermissionDef, p string) int { return cmp.Compare(d.Name, p) })
	return found
}

// Require は perms の連携先の権限が、すべて realm のカタログにあることを確かめる。IAM 自身の権限は見ない（形は
// role.ValidPermission で先に確かめる）。無ければ errs.KindInvalid（コード unknown_permission）。
func Require(ctx context.Context, tx port.Tx, realmID string, perms []string) error {
	cats := map[string]*port.PermissionCatalog{}
	for _, p := range perms {
		prefix, ok := role.CatalogPrefix(p)
		if !ok {
			continue
		}
		c, seen := cats[prefix]
		if !seen {
			got, err := tx.PermissionCatalogs().Get(ctx, realmID, prefix)
			switch {
			case errors.Is(err, errs.NotFound):
			case err != nil:
				return err
			default:
				c = &got
			}
			cats[prefix] = c
		}
		if c == nil || !Covers(*c, p) {
			return errs.WithCode(errs.KindInvalid, CodeUnknownPermission, "unknown permission "+p)
		}
	}
	return nil
}

// Uses は perms のうち、カタログの接頭辞 prefix の下にあって、カタログ next（nil なら消したあと）に無くなるものを返す。
func Uses(perms []string, prefix string, next *port.PermissionCatalog) []string {
	var out []string
	for _, p := range perms {
		if got, ok := role.CatalogPrefix(p); ok && got == prefix && (next == nil || !Covers(*next, p)) {
			out = append(out, p)
		}
	}
	return out
}
