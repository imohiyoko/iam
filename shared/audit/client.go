package audit

import (
	"net/netip"
	"strings"
)

// 監査ログの IP と User-Agent（design.md 9.5、9.6、ADR 0063）。
//
// ペイロードには保持期間の後も残してよい形（IP は IPv4 /24・IPv6 /48、User-Agent はブラウザと OS の大分類）だけを平文で置き、
// 全文は Event.Client に暗号化して置く（shared/eventlog）。ハッシュチェーンは書き換えられないため、
// 期間の後の切り詰めは、全文を暗号化した鍵を消すことで行う。

// TruncateIP は IP を IPv4 は /24、IPv6 は /48 のプレフィックスにする。読めなければ空。
func TruncateIP(ip string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.WithZone("").Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// ClassifyUA は User-Agent をブラウザと OS の大分類（"Chrome on Windows" など）にする。空なら空。
func ClassifyUA(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return ""
	}
	return browserOf(ua) + " on " + osOf(ua)
}

func browserOf(ua string) string {
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"},
	} {
		if strings.Contains(ua, b.token) {
			return b.name
		}
	}
	return "Other"
}

func osOf(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		return "iOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		return "macOS"
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return "Other"
}
