package ldap

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// ディレクトリの値の読み方（ファジングの対象。fuzz_test.go）。

// ValidUsername はログインの名前として受け付けるか（空・長すぎる・制御文字を拒む）。
func ValidUsername(name string) bool {
	return name != "" && len(name) <= maxUsername && utf8.ValidString(name) && !strings.ContainsFunc(name, unicode.IsControl)
}

// loginFilter は本人を探す絞り込み。名前はエスケープして等しさの条件の値にだけ入れる（絞り込みの注入を防ぐ）。
func loginFilter(cfg Config, username string) string {
	return "(&" + cfg.UserFilter + "(" + cfg.LoginAttribute + "=" + ldap.EscapeFilter(username) + "))"
}

// subjectOf は変わらない識別子の値を外部 ID の subject にする。objectGUID（16 バイト）は GUID の文字列に、印字できる UTF-8 は
// そのまま、それ以外は "x:" と 16 進にする。空か長すぎれば誤り。
func subjectOf(attr string, raw []byte) (string, error) {
	switch {
	case len(raw) == 0:
		return "", errors.New("empty identifier")
	case strings.EqualFold(attr, "objectGUID") && len(raw) == 16:
		// Microsoft の GUID は前の 3 つの区切りがリトルエンディアン。
		return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(raw[0:4]), binary.LittleEndian.Uint16(raw[4:6]),
			binary.LittleEndian.Uint16(raw[6:8]), raw[8:10], raw[10:16]), nil
	case utf8.Valid(raw) && !strings.ContainsFunc(string(raw), func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError }) &&
		!strings.HasPrefix(string(raw), "x:") && len(raw) <= 255:
		return string(raw), nil
	case len(raw) <= 126:
		return "x:" + hex.EncodeToString(raw), nil
	}
	return "", errors.New("identifier too long")
}

// groupOf は所属の値（Group の DN）が base の下にあれば、正規化した DN（対応の鍵）と、名前（最初の RDN の値）を返す。
func groupOf(dn string, base *ldap.DN) (key, name string, ok bool) {
	if base == nil || dn == "" || len(dn) > maxDN {
		return "", "", false
	}
	d, err := ldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 || len(d.RDNs[0].Attributes) != 1 || !base.AncestorOfFold(d) {
		return "", "", false
	}
	name = strings.TrimSpace(d.RDNs[0].Attributes[0].Value)
	if name == "" || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return "", "", false
	}
	key = strings.ToLower(d.String())
	if len(key) > maxDN {
		return "", "", false
	}
	return key, name, true
}

// entry は本人の項目のうち使うもの。
type entry struct {
	DN       string
	Subject  string
	Email    string
	Groups   []string // 所属の値（DN）
	Disabled bool
}

// adDisabled は userAccountControl の ACCOUNTDISABLE のビット。
const adDisabled = 0x2

// attributes は検索で求める属性。
func attributes(cfg Config) []string {
	out := []string{cfg.IDAttribute, cfg.EmailAttribute}
	if cfg.GroupBaseDN != "" {
		out = append(out, cfg.GroupAttribute)
	}
	if cfg.ActiveDirectory {
		out = append(out, "userAccountControl")
	}
	return out
}

// entryOf は検索の結果の項目を読む。識別子はちょうど 1 つの値を求める。メールは値が 1 つのときだけ使う。
func entryOf(cfg Config, e *ldap.Entry) (entry, error) {
	ids := e.GetEqualFoldRawAttributeValues(cfg.IDAttribute)
	if len(ids) != 1 {
		return entry{}, fmt.Errorf("entry has %d values of %s", len(ids), cfg.IDAttribute)
	}
	sub, err := subjectOf(cfg.IDAttribute, ids[0])
	if err != nil {
		return entry{}, err
	}
	out := entry{DN: e.DN, Subject: sub}
	if ms := e.GetEqualFoldAttributeValues(cfg.EmailAttribute); len(ms) == 1 && len(ms[0]) <= 320 {
		out.Email = ms[0]
	}
	if cfg.GroupBaseDN != "" {
		gs := e.GetEqualFoldAttributeValues(cfg.GroupAttribute)
		if len(gs) > maxAttrValues {
			gs = gs[:maxAttrValues]
		}
		out.Groups = gs
	}
	if cfg.ActiveDirectory {
		uac := e.GetEqualFoldAttributeValues("userAccountControl")
		if len(uac) != 1 {
			// 読めなければ無効とみなす（fail-closed）。
			out.Disabled = true
		} else if v, err := strconv.ParseInt(uac[0], 10, 64); err != nil || v&adDisabled != 0 {
			out.Disabled = true
		}
	}
	return out, nil
}
