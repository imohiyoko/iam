package audit_test

import (
	"testing"

	"github.com/imohiyoko/iam/shared/audit"
)

func TestTruncateIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77":          "203.0.113.0/24",
		"::ffff:203.0.113.77":   "203.0.113.0/24",
		"2001:db8:1234:5678::1": "2001:db8:1234::/48",
		"fe80::1%eth0":          "fe80::/48",
		"not an ip":             "",
		"":                      "",
	} {
		if got := audit.TruncateIP(in); got != want {
			t.Errorf("TruncateIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyUA(t *testing.T) {
	for in, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":           "Chrome on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15":     "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148": "Chrome on iOS",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0":                                                    "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 EdgA/130 Edg/130": "Edge on Android",
		"curl/8.5.0": "curl on Other",
		"":           "",
	} {
		if got := audit.ClassifyUA(in); got != want {
			t.Errorf("ClassifyUA(%q) = %q, want %q", in, got, want)
		}
	}
}
