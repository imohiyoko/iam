package attribute

import (
	"context"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 標準クレーム（OIDC Core 5.1、5.4。ADR 0127）。
//
// フィーチャー standard_claims が動いていれば、カスタム属性の定義に標準クレームの名前（claim）を付けられる。profile・phone・address の
// スコープを許した ID トークンと UserInfo に、その属性の値を標準クレームとして載せる（in_token とは別に）。iam が値を持つ email・
// email_verified・sub は対応付けない。address は address.formatted などの下位の名前で付け、address のオブジェクトにまとめる。

// StandardClaimsFeature は standard_claims のフィーチャー（既定オフ。カスタム属性に依存する）。持つデータは定義の claim。
var StandardClaimsFeature = feature.Feature{Name: feature.StandardClaims, DataVersion: 1, Requires: []string{feature.CustomAttributes}}

// スコープ（OIDC Core 5.4）。
const (
	ScopeProfile = "profile"
	ScopePhone   = "phone"
	ScopeAddress = "address"
)

// ClaimScopes は standard_claims で足すスコープ。
var ClaimScopes = []string{ScopeProfile, ScopePhone, ScopeAddress}

// addressPrefix は address の下位のクレームの名前の接頭辞。
const addressPrefix = "address."

// standardClaims は対応付けられる標準クレームと、そのスコープ・型。
var standardClaims = map[string]struct {
	scope string
	types []port.AttributeType
}{}

func init() {
	text := []port.AttributeType{port.AttributeString, port.AttributeEnum}
	for _, c := range []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture",
		"website", "gender", "birthdate", "zoneinfo", "locale"} {
		standardClaims[c] = struct {
			scope string
			types []port.AttributeType
		}{ScopeProfile, text}
	}
	standardClaims["phone_number"] = struct {
		scope string
		types []port.AttributeType
	}{ScopePhone, text}
	standardClaims["phone_number_verified"] = struct {
		scope string
		types []port.AttributeType
	}{ScopePhone, []port.AttributeType{port.AttributeBoolean}}
	for _, c := range []string{"formatted", "street_address", "locality", "region", "postal_code", "country"} {
		standardClaims[addressPrefix+c] = struct {
			scope string
			types []port.AttributeType
		}{ScopeAddress, text}
	}
}

// ErrClaimTaken は、標準クレームがほかの属性に対応付け済み。
var ErrClaimTaken = errs.WithCode(errs.KindConflict, "claim_taken", "standard claim is mapped to another attribute")

// SupportedClaims は Discovery の claims_supported に足す名前（address は 1 つにまとめる。名前の順）。
func SupportedClaims() []string {
	var out []string
	for c := range standardClaims {
		if strings.HasPrefix(c, addressPrefix) {
			c = "address"
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// checkClaim は定義の claim を確かめる（フィーチャー、名前、型、realm での重複）。
func (s *Service) checkClaim(ctx context.Context, tx port.Tx, d port.AttributeDef) error {
	if d.Claim == "" {
		return nil
	}
	c, ok := standardClaims[d.Claim]
	if !s.StandardClaims || !ok || !slices.Contains(c.types, d.Type) {
		return ErrInvalidDef
	}
	ds, err := tx.Attributes().ListDefs(ctx, d.RealmID)
	if err != nil {
		return err
	}
	for _, o := range ds {
		if o.Key != d.Key && o.Claim == d.Claim {
			return ErrClaimTaken
		}
	}
	return nil
}

// Claims は、スコープで許した標準クレームを、対応付けた属性の値から作る。フィーチャーが動いていなければ空。
func (s *Service) Claims(ctx context.Context, tx port.Tx, u port.User, scopes []string) (map[string]any, error) {
	out := map[string]any{}
	if !s.StandardClaims {
		return out, nil
	}
	defs, err := defsByKey(ctx, tx, u.RealmID)
	if err != nil {
		return nil, err
	}
	want := map[string]string{} // 属性の key → クレーム
	for k, d := range defs {
		if c, ok := standardClaims[d.Claim]; ok && slices.Contains(scopes, c.scope) {
			want[k] = d.Claim
		}
	}
	if len(want) == 0 {
		return out, nil
	}
	vs, err := s.values(ctx, tx, u, defs, func(d port.AttributeDef) bool { _, ok := want[d.Key]; return ok })
	if err != nil {
		return nil, err
	}
	for k, v := range vs {
		c := want[k]
		if sub, ok := strings.CutPrefix(c, addressPrefix); ok {
			addr, _ := out["address"].(map[string]any)
			if addr == nil {
				addr = map[string]any{}
				out["address"] = addr
			}
			addr[sub] = v
			continue
		}
		out[c] = v
	}
	return out, nil
}
