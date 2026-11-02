// Package static は CIDR の表（CSV）から接続元の場所を引く GeoIP（フィーチャー login_risk。ADR 0105）。
//
// 1 行が `cidr,country,asn,latitude,longitude`（country・asn・座標は空でよい。`#` で始まる行と空行は飛ばす）。
// 重なる範囲はいちばん長い接頭辞のものを返す。起動時に読み、ログインの経路では外部に問い合わせない。
// 社内の拠点の表や、外部の GeoIP データベースを書き出したものを置く。
package static

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterGeoIP("static", func(_ context.Context, cfg plugin.Config) (port.GeoIP, error) {
		if err := cfg.CheckOptions("file"); err != nil {
			return nil, err
		}
		path := cfg.Option("file", "")
		if path == "" {
			return nil, errors.New("geoip static: file is required")
		}
		f, err := os.Open(path) // #nosec G304 -- 運用者が設定したパス
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return Parse(f)
	})
}

// maxRows は表の行の上限（読み込みの大きさを抑える）。
const maxRows = 1 << 20

var countryRE = regexp.MustCompile(`^[A-Z]{2}$`)

type row struct {
	prefix netip.Prefix
	loc    port.GeoLocation
}

// Table は CIDR の表。
type Table struct{ rows []row }

var _ port.GeoIP = (*Table)(nil)

// Parse は CSV を読む。誤った行があればエラー（行番号付き）。
func Parse(r io.Reader) (*Table, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 4096)
	t := &Table{}
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(t.rows) >= maxRows {
			return nil, fmt.Errorf("geoip static: more than %d rows", maxRows)
		}
		rw, err := parseRow(line)
		if err != nil {
			return nil, fmt.Errorf("geoip static: line %d: %w", n, err)
		}
		t.rows = append(t.rows, rw)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("geoip static: %w", err)
	}
	// 長い接頭辞を先に（いちばん細かい範囲を返す）。
	slices.SortStableFunc(t.rows, func(a, b row) int { return b.prefix.Bits() - a.prefix.Bits() })
	return t, nil
}

func parseRow(line string) (row, error) {
	f := strings.Split(line, ",")
	if len(f) != 5 {
		return row{}, errors.New("want 5 fields: cidr,country,asn,latitude,longitude")
	}
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	p, err := netip.ParsePrefix(f[0])
	if err != nil {
		return row{}, fmt.Errorf("cidr: %w", err)
	}
	if p.Addr().Is4In6() {
		return row{}, errors.New("cidr: use the IPv4 form instead of an IPv4-mapped prefix")
	}
	rw := row{prefix: p.Masked()}
	if f[1] != "" {
		if !countryRE.MatchString(f[1]) {
			return row{}, fmt.Errorf("country %q must be an ISO 3166-1 alpha-2 code in upper case", f[1])
		}
		rw.loc.Country = f[1]
	}
	if f[2] != "" {
		asn, err := strconv.ParseUint(strings.TrimPrefix(f[2], "AS"), 10, 32)
		if err != nil {
			return row{}, fmt.Errorf("asn %q: %w", f[2], err)
		}
		rw.loc.ASN = uint32(asn)
	}
	switch {
	case f[3] == "" && f[4] == "":
	case f[3] == "" || f[4] == "":
		return row{}, errors.New("latitude and longitude must both be set or both be empty")
	default:
		lat, err1 := strconv.ParseFloat(f[3], 64)
		lon, err2 := strconv.ParseFloat(f[4], 64)
		if err1 != nil || err2 != nil || !(lat >= -90 && lat <= 90) || !(lon >= -180 && lon <= 180) {
			return row{}, fmt.Errorf("coordinates %q,%q must be within [-90, 90] and [-180, 180]", f[3], f[4])
		}
		rw.loc.HasCoordinates, rw.loc.Latitude, rw.loc.Longitude = true, lat, lon
	}
	return rw, nil
}

// Lookup は ip を含むいちばん細かい範囲の場所を返す。
func (t *Table) Lookup(_ context.Context, ip string) (port.GeoLocation, bool, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return port.GeoLocation{}, false, nil
	}
	a = a.Unmap().WithZone("")
	for _, r := range t.rows {
		if r.prefix.Contains(a) {
			return r.loc, true, nil
		}
	}
	return port.GeoLocation{}, false, nil
}
