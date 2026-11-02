package static_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/adapters/geoip/static"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

const table = `# cidr,country,asn,lat,lon
203.0.113.0/24,JP,AS64500,35.68,139.76
203.0.113.128/25,JP,64501,34.69,135.50
198.51.100.0/24,US,,,
2001:db8::/32,DE,64502,52.52,13.40
`

func TestLookup(t *testing.T) {
	tb, err := static.Parse(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for ip, want := range map[string]port.GeoLocation{
		"203.0.113.5":         {Country: "JP", ASN: 64500, HasCoordinates: true, Latitude: 35.68, Longitude: 139.76},
		"203.0.113.200":       {Country: "JP", ASN: 64501, HasCoordinates: true, Latitude: 34.69, Longitude: 135.50}, // 長い接頭辞
		"::ffff:198.51.100.7": {Country: "US"},
		"2001:db8:1::1":       {Country: "DE", ASN: 64502, HasCoordinates: true, Latitude: 52.52, Longitude: 13.40},
		"2001:db8::1%eth0":    {Country: "DE", ASN: 64502, HasCoordinates: true, Latitude: 52.52, Longitude: 13.40},
	} {
		got, ok, err := tb.Lookup(ctx, ip)
		if err != nil || !ok || got != want {
			t.Errorf("Lookup(%s) = %+v, %v, %v; want %+v", ip, got, ok, err, want)
		}
	}
	for _, ip := range []string{"192.0.2.1", "not an ip", ""} {
		if _, ok, err := tb.Lookup(ctx, ip); ok || err != nil {
			t.Errorf("Lookup(%q) found, %v", ip, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, line := range []string{
		"203.0.113.0/24,JP,1,35",          // 列の数
		"203.0.113.0,JP,1,,",              // CIDR でない
		"203.0.113.0/24,jp,1,,",           // 小文字
		"203.0.113.0/24,JPN,1,,",          // 3 文字
		"203.0.113.0/24,JP,ASx,,",         // ASN
		"203.0.113.0/24,JP,1,91,0",        // 緯度
		"203.0.113.0/24,JP,1,0,",          // 片方だけ
		"203.0.113.0/24,JP,1,NaN,0",       // NaN
		"::ffff:203.0.113.0/120,JP,1,,",   // IPv4 射影
		"203.0.113.0/24,JP,99999999999,,", // 32 bit を超える
	} {
		if _, err := static.Parse(strings.NewReader(line)); err == nil {
			t.Errorf("Parse(%q) accepted", line)
		}
	}
}

func TestPlugin(t *testing.T) {
	f, err := plugin.GeoIP("static")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f(ctx, plugin.Config{Options: map[string]string{}}); err == nil {
		t.Error("file is required")
	}
	if _, err := f(ctx, plugin.Config{Options: map[string]string{"file": "x", "url": "y"}}); err == nil {
		t.Error("unknown option accepted")
	}
	path := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := f(ctx, plugin.Config{Options: map[string]string{"file": path}})
	if err != nil {
		t.Fatal(err)
	}
	if loc, ok, _ := g.Lookup(ctx, "198.51.100.1"); !ok || loc.Country != "US" {
		t.Errorf("Lookup = %+v, %v", loc, ok)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(table)
	f.Add("::/0,,,,")
	f.Add("0.0.0.0/0,ZZ,AS0,-90,-180")
	f.Fuzz(func(t *testing.T, s string) {
		tb, err := static.Parse(strings.NewReader(s))
		if err != nil {
			return
		}
		loc, ok, err := tb.Lookup(context.Background(), "203.0.113.9")
		if err != nil || (!ok && loc != (port.GeoLocation{})) {
			t.Fatalf("Lookup = %+v, %v, %v", loc, ok, err)
		}
		if loc.HasCoordinates && (loc.Latitude < -90 || loc.Latitude > 90 || loc.Longitude < -180 || loc.Longitude > 180) {
			t.Fatalf("coordinates out of range: %+v", loc)
		}
	})
}
